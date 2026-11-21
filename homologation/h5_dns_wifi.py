"""Ensaio H5: dnsmasq + dig reais sem privilégios (VPN/exceções/IPv4+IPv6) e rede Wi-Fi."""

from __future__ import annotations

import socket
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from mintsec.config import ConfigStore
from mintsec.contracts import load_manifests
from mintsec.history import HistoryStore
from mintsec.packaging import PackageInspector
from mintsec.pending import PendingStore
from mintsec.runner import SubprocessRunner
from mintsec.services.browsing import BrowsingService
from mintsec.services.network import NetworkService


class _MiniDnsStub:
    """Stub UDP DNS mínimo para validar redirecionamento por domínio e VPN sem saída externa."""

    def __init__(self, port: int, answer_ip: str) -> None:
        self.port = port
        self.answer_ip = answer_ip
        self.queries: list[str] = []
        self._stop = threading.Event()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", port))
        self._sock.settimeout(0.2)
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=2)
        self._sock.close()

    @staticmethod
    def _parse_qname(packet: bytes) -> tuple[str, int]:
        pos = 12
        labels: list[str] = []
        while pos < len(packet):
            ln = packet[pos]
            pos += 1
            if ln == 0:
                break
            labels.append(packet[pos : pos + ln].decode("ascii", errors="replace"))
            pos += ln
        return ".".join(labels), pos + 4

    def _serve(self) -> None:
        while not self._stop.is_set():
            try:
                data, addr = self._sock.recvfrom(512)
            except socket.timeout:
                continue
            except OSError:
                break
            if len(data) < 12:
                continue
            qname, qend = self._parse_qname(data)
            self.queries.append(qname.lower())
            txid = data[:2]
            qtype = struct.unpack("!H", data[qend - 4 : qend - 2])[0] if qend <= len(data) else 1
            flags = b"\x81\x80"
            if qtype == 1:
                header = txid + flags + b"\x00\x01\x00\x01\x00\x00\x00\x00"
                question = data[12:qend]
                answer = b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04" + socket.inet_aton(self.answer_ip)
                self._sock.sendto(header + question + answer, addr)
            else:
                header = txid + flags + b"\x00\x01\x00\x00\x00\x00\x00\x00"
                self._sock.sendto(header + data[12:qend], addr)


def _dig(port: int, domain: str, qtype: str = "A") -> str:
    res = subprocess.run(
        ["dig", "+short", "+time=2", "+tries=1", "@127.0.0.1", "-p", str(port), domain, qtype],
        capture_output=True,
        text=True,
        check=True,
    )
    return res.stdout.strip()


def run_h5(repo_root: Path) -> dict[str, Any]:
    manifests = load_manifests()
    netmon_bin = repo_root / "helpers/mintsec-netmon/mintsec-netmon"

    with tempfile.TemporaryDirectory(prefix="mintsec-h5-") as tmp:
        tmp_path = Path(tmp)
        runner = SubprocessRunner()
        common = dict(
            config_store=ConfigStore(tmp_path / "settings.json"),
            pending_store=PendingStore(tmp_path / "pending.json"),
            history_store=HistoryStore(tmp_path / "history.db"),
            package_inspector=PackageInspector(runner),
            runner=runner,
            data_dir=tmp_path / "data",
        )

        browsing = BrowsingService(
            manifest=manifests["browsing"],
            nm_conf_dropin=tmp_path / "99-mintsec-dns.conf",
            **common,
        )
        browsing.enable()

        # Stubs: 15354 = resolvedor alternativo autorizado, 15355 = DNS privado VPN
        ext_stub = _MiniDnsStub(15354, "203.0.113.54")
        vpn_stub = _MiniDnsStub(15355, "10.8.0.55")
        ext_stub.start()
        vpn_stub.start()

        try:
            # Garante que não é possível redirecionar domínio privado da VPN
            vpn_protected = False
            try:
                browsing.authorize_external_resolver(
                    "intranet.corp.vpn",
                    "127.0.0.1#15354",
                    vpn_domains=["corp.vpn"],
                )
            except PermissionError:
                vpn_protected = True
            assert vpn_protected

            browsing.authorize_external_resolver(
                "parceiro.exemplo",
                "127.0.0.1#15354",
                vpn_domains=["corp.vpn"],
            )
            conf_path = tmp_path / "dnsmasq_h5.conf"
            conf_path.write_text(
                browsing.generate_dnsmasq_config(
                    listen_addr="127.0.0.1",
                    port=15353,
                    upstream_servers=["127.0.0.1#15354"],
                    vpn_resolvers={"corp.vpn": "127.0.0.1#15355"},
                ),
                encoding="utf-8",
            )

            proc = subprocess.Popen(
                ["/usr/sbin/dnsmasq", "--no-daemon", f"--conf-file={conf_path}", "--pid-file="],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                time.sleep(0.35)
                assert proc.poll() is None, f"dnsmasq falhou: {proc.stderr.read() if proc.stderr else ''}"

                # Bloqueio IPv4 e IPv6 em domínio de phishing
                ans_v4 = _dig(15353, "phishing-demo.invalid", "A")
                ans_v6 = _dig(15353, "phishing-demo.invalid", "AAAA")
                assert ans_v4 == "0.0.0.0", f"Esperado 0.0.0.0, obtido {ans_v4}"
                assert ans_v6 == "::", f"Esperado ::, obtido {ans_v6}"
                assert browsing.lookup_block_origin("phishing-demo.invalid")["origin"] == "Lista local: phishing"

                # Domínio parceiro vai para 15354 e domínio privado VPN vai para 15355
                assert _dig(15353, "parceiro.exemplo", "A") == "203.0.113.54"
                assert _dig(15353, "intranet.corp.vpn", "A") == "10.8.0.55"
            finally:
                proc.terminate()
                proc.wait(timeout=3)

            # Exceção local revoga regra local
            browsing.add_local_exception("phishing-demo.invalid")
            conf_path.write_text(
                browsing.generate_dnsmasq_config(
                    listen_addr="127.0.0.1",
                    port=15353,
                    upstream_servers=["127.0.0.1#15354"],
                    vpn_resolvers={"corp.vpn": "127.0.0.1#15355"},
                ),
                encoding="utf-8",
            )
            proc2 = subprocess.Popen(
                ["/usr/sbin/dnsmasq", "--no-daemon", f"--conf-file={conf_path}", "--pid-file="],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                time.sleep(0.35)
                assert _dig(15353, "phishing-demo.invalid", "A") == "203.0.113.54"
            finally:
                proc2.terminate()
                proc2.wait(timeout=3)

            # Reversão ao desativar
            browsing.disable(revert_suite_changes=True)
            assert not (tmp_path / "99-mintsec-dns.conf").exists()

        finally:
            ext_stub.stop()
            vpn_stub.stop()

        # Parte Wi-Fi / Rede local: netmon self-test + consulta real nmcli/ip neigh + isolamento
        netmon_res = subprocess.run([str(netmon_bin), "--self-test"], capture_output=True, text=True, check=True)
        network = NetworkService(manifest=manifests["network"], **common)
        network.enable()
        live_conn = network.inspect_active_connection()
        live_neigh = network.read_neighbor_table(interface=live_conn.get("interface") or None)
        live_net_id = live_conn.get("connection_name") or live_conn.get("interface") or "CafePublico"

        # Novo dispositivo observado e bloqueio de busca ativa fora da rede Casa
        obs = network.ingest_observations(
            [{"mac": "aa:bb:cc:11:22:33", "ip": "192.168.10.44", "interface": live_conn.get("interface") or "wlan0", "protocol": "DHCP", "hostname": "tv-sala"}],
            network_id=live_net_id,
            alert_on_new=True,
            client_isolation=True,
        )
        assert len(obs["newly_observed"]) == 1 and obs["client_isolation"] is True
        st_iso = network.query_status()
        assert "isolamento de clientes" in st_iso.evidence.lower() and st_iso.details["client_isolation"]

        refused_outside_home = False
        try:
            network.active_discover("CafePublico")
        except PermissionError:
            refused_outside_home = True
        assert refused_outside_home

        network.recognize_device("aa:bb:cc:11:22:33", "TV da Sala")
        network.set_network_home("MinhaCasa", True)

    return {
        "assay": "H5",
        "status": "PASS",
        "selected_dns_engine": "dnsmasq (validado ao vivo com dig IPv4/IPv6 + VPN split)",
        "dns_live_block_exception_vpn_reversion_ok": True,
        "netmon_self_test": netmon_res.stdout.strip(),
        "live_nmcli_interface": live_conn.get("interface"),
        "live_neighbors_observed": len(live_neigh),
        "client_isolation_and_home_gate_ok": True,
    }
