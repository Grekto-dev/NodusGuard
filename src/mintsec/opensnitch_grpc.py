"""Conector OpenSnitch sobre socket Unix com framing protobuf/JSON e reconexão."""

from __future__ import annotations

import functools
import json
import os
import socket
import struct
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mintsec.firewall_trust import OpenSnitchBridge

DEFAULT_OPENSNITCH_SOCKETS = (
    Path("/run/opensnitchd.sock"),
    Path("/tmp/osui.sock"),
)


def _encode_varint(value: int) -> bytes:
    """Codifica inteiro sem sinal em varint Protobuf puro em Python."""
    out = bytearray()
    val = int(value)
    while val >= 0x80:
        out.append((val & 0x7F) | 0x80)
        val >>= 7
    out.append(val)
    return bytes(out)


def _decode_varint(buf: bytes, pos: int) -> tuple[int, int]:
    """Decodifica varint Protobuf retornando (valor, nova_posicao)."""
    result = 0
    shift = 0
    end = len(buf)
    while pos < end:
        byte = buf[pos]
        pos += 1
        result |= (byte & 0x7F) << shift
        if not (byte & 0x80):
            return result, pos
        shift += 7
        if shift >= 64:
            raise ValueError("Varint excede 64 bits no envelope OpenSnitch.")
    raise ValueError("Varint truncado no envelope OpenSnitch.")


@functools.lru_cache(maxsize=1)
def has_grpcio() -> bool:
    """Indica se o pacote opcional python3-grpcio está instalado no sistema."""
    try:
        import grpc  # noqa: F401
        return True
    except ImportError:
        return False


def encode_wire_envelope(op: str, payload: dict[str, Any]) -> bytes:
    """Codifica mensagem no formato protobuf length-delimited (tag 1: op, tag 2: payload JSON)."""
    out = bytearray()
    op_bytes = op.encode("utf-8")
    payload_bytes = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    # Field 1 (wire type 2 = length-delimited): op
    out.extend(_encode_varint((1 << 3) | 2))
    out.extend(_encode_varint(len(op_bytes)))
    out.extend(op_bytes)
    # Field 2 (wire type 2 = length-delimited): payload
    out.extend(_encode_varint((2 << 3) | 2))
    out.extend(_encode_varint(len(payload_bytes)))
    out.extend(payload_bytes)
    frame = bytes(out)
    return struct.pack("!I", len(frame)) + frame


def decode_wire_envelope(frame: bytes) -> tuple[str, dict[str, Any]]:
    """Decodifica envelope protobuf (tag 1: op, tag 2: payload JSON)."""
    pos = 0
    end = len(frame)
    op = ""
    payload: dict[str, Any] = {}
    while pos < end:
        tag_val, pos = _decode_varint(frame, pos)
        field_num = tag_val >> 3
        wire_type = tag_val & 0x7
        if wire_type != 2:
            raise ValueError(f"Tipo wire inesperado no envelope OpenSnitch: {wire_type}")
        length, pos = _decode_varint(frame, pos)
        if pos + length > end:
            raise ValueError("Campo truncado no envelope OpenSnitch.")
        chunk = frame[pos : pos + length]
        pos += length
        if field_num == 1:
            op = chunk.decode("utf-8")
        elif field_num == 2:
            payload = json.loads(chunk.decode("utf-8"))
    return op, payload


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    buf = bytearray()
    while len(buf) < size:
        part = sock.recv(size - len(buf))
        if not part:
            raise ConnectionResetError("Conexão encerrada pelo peer OpenSnitch.")
        buf.extend(part)
    return bytes(buf)


def recv_wire_message(sock: socket.socket) -> tuple[str, dict[str, Any]]:
    hdr = _recv_exact(sock, 4)
    (length,) = struct.unpack("!I", hdr)
    if length > 4 * 1024 * 1024:
        raise ValueError(f"Frame excede limite máximo: {length}")
    frame = _recv_exact(sock, length)
    return decode_wire_envelope(frame)


def send_wire_message(sock: socket.socket, op: str, payload: dict[str, Any]) -> None:
    sock.sendall(encode_wire_envelope(op, payload))


@dataclass
class OpenSnitchSocketStatus:
    """Estado observado do socket Unix do OpenSnitch."""

    socket_path: str
    reachable: bool
    grpcio_available: bool
    detail: str


class OpenSnitchGrpcClient:
    """Cliente Unix-socket para OpenSnitch com reconexão automática e fallback seguro."""

    def __init__(
        self,
        *,
        bridge: OpenSnitchBridge,
        socket_path: Path | None = None,
        timeout_secs: float = 2.5,
    ) -> None:
        self.bridge = bridge
        self.socket_path = socket_path or self._discover_socket()
        self.timeout_secs = timeout_secs
        self._lock = threading.Lock()
        self._sock: socket.socket | None = None

    @staticmethod
    def _discover_socket() -> Path:
        env_sock = os.environ.get("MINTSEC_OPENSNITCH_SOCK", "").strip()
        if env_sock:
            return Path(env_sock)
        for cand in DEFAULT_OPENSNITCH_SOCKETS:
            if cand.exists():
                return cand
        return DEFAULT_OPENSNITCH_SOCKETS[0]

    def probe_daemon_socket(self) -> OpenSnitchSocketStatus:
        """Verifica se o daemon OpenSnitch responde no socket Unix sem falhar se ausente."""
        grpc_ok = has_grpcio()
        if not self.socket_path.exists():
            return OpenSnitchSocketStatus(
                socket_path=str(self.socket_path),
                reachable=False,
                grpcio_available=grpc_ok,
                detail="Socket do daemon OpenSnitch não encontrado.",
            )
        try:
            pong = self.ping()
            return OpenSnitchSocketStatus(
                socket_path=str(self.socket_path),
                reachable=bool(pong.get("ok")),
                grpcio_available=grpc_ok,
                detail=f"Conectado (versão daemon: {pong.get('version', 'desconhecida')})",
            )
        except Exception as exc:
            return OpenSnitchSocketStatus(
                socket_path=str(self.socket_path),
                reachable=False,
                grpcio_available=grpc_ok,
                detail=f"Socket inacessível: {exc}",
            )

    def _connect(self) -> socket.socket:
        if self._sock is not None:
            return self._sock
        if self.socket_path.is_symlink():
            raise PermissionError(f"Socket OpenSnitch não pode ser symlink: {self.socket_path}")
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            sock.settimeout(self.timeout_secs)
            sock.connect(str(self.socket_path))
            if hasattr(socket, "SO_PEERCRED"):
                creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
                _pid, peer_uid, _gid = struct.unpack("3i", creds)
                if peer_uid not in (0, os.geteuid()):
                    raise PermissionError(
                        f"Peer UID inesperado ({peer_uid}) no socket OpenSnitch {self.socket_path}"
                    )
        except Exception:
            sock.close()
            raise
        self._sock = sock
        return sock

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
                self._sock = None

    def _rpc(self, op: str, payload: dict[str, Any]) -> tuple[str, dict[str, Any]]:
        with self._lock:
            last_err: Exception | None = None
            for attempt in range(2):
                try:
                    sock = self._connect()
                    send_wire_message(sock, op, payload)
                    return recv_wire_message(sock)
                except (OSError, ConnectionResetError, BrokenPipeError) as exc:
                    last_err = exc
                    if self._sock is not None:
                        try:
                            self._sock.close()
                        except OSError:
                            pass
                        self._sock = None
                    if attempt == 1:
                        break
            raise ConnectionError(f"Falha na comunicação com OpenSnitch: {last_err}")

    def ping(self) -> dict[str, Any]:
        op, data = self._rpc("Ping", {"id": uuid.uuid4().hex})
        return {"ok": op == "Pong", **data}

    def set_default_action(self, outbound_mode: str) -> dict[str, Any]:
        default_action = "deny" if outbound_mode == "block_per_app" else "allow"
        op, data = self._rpc("ClientConfig", {"default_action": default_action})
        return {"op": op, "default_action": default_action, **data}

    def send_rule(self, rule: dict[str, Any]) -> dict[str, Any]:
        op, data = self._rpc("ApplyRule", rule)
        return {"op": op, **data}

    def process_ask_rule(
        self,
        *,
        connection_id: str,
        app_name: str,
        executable_path: str,
        destination: str,
        outbound_mode: str,
        pid: int | None = None,
        encrypted_dns_domain: str | None = None,
    ) -> dict[str, Any]:
        """Consulta ponte local e envia decisão/regra pelo socket quando online."""
        try:
            self.ping()
            self.bridge.bridge_online = True
        except Exception:
            self.bridge.bridge_online = False

        decision = self.bridge.handle_first_connection(
            connection_id=connection_id,
            app_name=app_name,
            executable_path=executable_path,
            destination=destination,
            outbound_mode=outbound_mode,
            pid=pid,
            encrypted_dns_domain=encrypted_dns_domain,
        )
        if self.bridge.bridge_online:
            try:
                self._rpc(
                    "AskRuleReply",
                    {
                        "connection_id": connection_id,
                        "action": decision["action"],
                        "app_name": app_name,
                        "destination": destination,
                    },
                )
            except Exception:
                self.bridge.bridge_online = False
        return decision


class MockOpenSnitchDaemonServer:
    """Servidor Unix-socket real para testes de integração e H2 ao vivo."""

    def __init__(self, socket_path: Path, *, daemon_version: str = "1.5.8.1") -> None:
        self.socket_path = socket_path
        self.daemon_version = daemon_version
        self.received_ops: list[tuple[str, dict[str, Any]]] = []
        self.default_action = "allow"
        self.applied_rules: list[dict[str, Any]] = []
        self._stop = threading.Event()
        self._srv_sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._clients: list[socket.socket] = []

    def start(self) -> None:
        self.socket_path.unlink(missing_ok=True)
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(str(self.socket_path))
        srv.listen(8)
        srv.settimeout(0.2)
        self._srv_sock = srv
        self._stop.clear()
        self._thread = threading.Thread(target=self._accept_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        for cs in list(self._clients):
            try:
                cs.close()
            except OSError:
                pass
        self._clients.clear()
        if self._srv_sock is not None:
            try:
                self._srv_sock.close()
            except OSError:
                pass
            self._srv_sock = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        self.socket_path.unlink(missing_ok=True)

    def _accept_loop(self) -> None:
        assert self._srv_sock is not None
        while not self._stop.is_set():
            try:
                client, _ = self._srv_sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            self._clients.append(client)
            threading.Thread(target=self._handle_client, args=(client,), daemon=True).start()

    def _handle_client(self, client: socket.socket) -> None:
        client.settimeout(0.2)
        try:
            while not self._stop.is_set():
                try:
                    op, data = recv_wire_message(client)
                except socket.timeout:
                    continue
                except (OSError, ConnectionResetError):
                    break
                self.received_ops.append((op, data))
                if op == "Ping":
                    send_wire_message(client, "Pong", {"version": self.daemon_version})
                elif op == "ClientConfig":
                    self.default_action = str(data.get("default_action", "allow"))
                    send_wire_message(client, "ClientConfigAck", {"default_action": self.default_action})
                elif op == "ApplyRule":
                    self.applied_rules.append(data)
                    send_wire_message(client, "RuleAck", {"ok": True})
                elif op == "AskRuleReply":
                    send_wire_message(client, "AskRuleAck", {"recorded": True})
                else:
                    send_wire_message(client, "Error", {"detail": f"Operação desconhecida: {op}"})
        finally:
            try:
                client.close()
            except OSError:
                pass
