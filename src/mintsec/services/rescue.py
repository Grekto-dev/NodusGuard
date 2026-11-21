"""Módulo 7: Resgate offline (UDisks2, segurança contra disco de sistema, GPG e gravação)."""

from __future__ import annotations

import hashlib
import json
import os
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mintsec.contracts import (
    ModuleManifest,
    ModuleState,
    ModuleStatus,
    atomic_write_json,
    read_json_safe,
    xdg_dir,
)
from mintsec.formatting import format_bytes, now_iso
from mintsec.services.base import ModuleService

SYSTEM_MOUNTPOINTS = frozenset({"/", "/boot", "/boot/efi", "/home", "/var", "/usr", "/opt", "[SWAP]"})
SYSTEM_MOUNT_PREFIXES = ("/boot/", "/efi/", "/home/", "/var/", "/usr/", "/opt/")
_BLOCK_DEV_NAME_RE = re.compile(r"^[A-Za-z0-9_]+$")


@dataclass(frozen=True)
class BlockDeviceCandidate:
    """Dispositivo removível avaliado contra o grafo de ancestrais de sistema/swap."""

    path: str
    name: str
    model: str
    size_bytes: int
    serial: str
    wwn: str
    transport: str
    removable: bool
    safe_for_rescue_write: bool
    refusal_reason: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_block_devices(lsblk_json: dict[str, Any]) -> tuple[list[BlockDeviceCandidate], set[str]]:
    """Analisa árvore lsblk -J incluindo LUKS/LVM/RAID para identificar discos protegidos."""
    raw_nodes = lsblk_json.get("blockdevices", [])
    by_name: dict[str, dict[str, Any]] = {}
    parents: dict[str, set[str]] = {}

    def _walk(node: dict[str, Any], parent_name: str | None = None) -> None:
        name = str(node.get("kname") or node.get("name") or "")
        if not name:
            return
        by_name[name] = node
        parents.setdefault(name, set())
        if parent_name:
            parents[name].add(parent_name)
        pk = node.get("pkname")
        if pk:
            parents[name].add(str(pk))
        for child in node.get("children", []) or []:
            _walk(child, parent_name=name)

    for top in raw_nodes:
        _walk(top, parent_name=None)

    # Propaga proteção para todos os ancestrais físicos de /, /boot, /home, swap (LUKS/LVM/RAID)
    protected_nodes: set[str] = set()

    def _protect_ancestors(node_name: str) -> None:
        stack = [node_name]
        while stack:
            cur = stack.pop()
            if cur in protected_nodes:
                continue
            protected_nodes.add(cur)
            for p in parents.get(cur, set()):
                stack.append(p)

    for name, node in by_name.items():
        mps = []
        if node.get("mountpoint"):
            mps.append(str(node["mountpoint"]))
        for mp in node.get("mountpoints", []) or []:
            if mp:
                mps.append(str(mp))
        fstype = str(node.get("fstype") or "").lower()
        if any(mp in SYSTEM_MOUNTPOINTS or mp.startswith(SYSTEM_MOUNT_PREFIXES) for mp in mps) or fstype == "swap":
            _protect_ancestors(name)

    candidates: list[BlockDeviceCandidate] = []
    for name, node in by_name.items():
        dtype = str(node.get("type") or "")
        if dtype != "disk":
            continue
        path = str(node.get("path") or f"/dev/{name}")
        model = str(node.get("model") or "Mídia USB").strip()
        serial = str(node.get("serial") or "").strip()
        wwn = str(node.get("wwn") or "").strip()
        tran = str(node.get("tran") or "").lower()
        removable = bool(node.get("rm", False))
        size_raw = node.get("size", 0)
        size_bytes = int(size_raw) if isinstance(size_raw, (int, float)) else 0

        refusal: str | None = None
        if name in protected_nodes:
            refusal = "Disco sustenta sistema operacional, dados montados ou swap (inclusive via LUKS/LVM/RAID)."
        elif not removable and tran != "usb":
            refusal = "Dispositivo não identificado como mídia removível USB."
        elif size_bytes <= 0:
            refusal = "Capacidade inválida ou mídia sem tamanho reportado."
        elif not serial and not wwn:
            refusal = "Alvo ambíguo: mídia sem WWN nem serial reportados."

        candidates.append(
            BlockDeviceCandidate(
                path=path,
                name=name,
                model=model,
                size_bytes=size_bytes,
                serial=serial,
                wwn=wwn,
                transport=tran,
                removable=removable,
                safe_for_rescue_write=(refusal is None),
                refusal_reason=refusal,
            )
        )
    return candidates, protected_nodes


class RescueService(ModuleService):
    """Gerencia verificação GPG da imagem de resgate e gravação validada via UDisks2."""

    def __init__(
        self,
        *,
        manifest: ModuleManifest,
        config_store: Any,
        pending_store: Any,
        history_store: Any,
        package_inspector: Any = None,
        runner: Any = None,
        authorizer: Any = None,
        data_dir: Path | None = None,
    ) -> None:
        super().__init__(
            manifest=manifest,
            config_store=config_store,
            pending_store=pending_store,
            history_store=history_store,
            package_inspector=package_inspector,
            runner=runner,
            authorizer=authorizer,
        )
        self.data_dir = data_dir or xdg_dir("XDG_DATA_HOME", ".local/share")
        self.state_path = self.data_dir / "rescue_state.json"

    def _load_state(self) -> dict[str, Any]:
        return read_json_safe(
            self.state_path,
            default={
                "rescue_h7_approved": False,
                "last_image_verified_at": None,
                "last_usb_write_at": None,
                "last_usb_write_bytes": 0,
            },
        )

    def _save_state(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.state_path, data, mode=0o600)

    def list_block_candidates(self) -> tuple[list[BlockDeviceCandidate], set[str]]:
        """Inspeciona árvore real de blocos via lsblk -J -b (somente leitura)."""
        lsblk_bin = self.runner.which("lsblk")
        if not lsblk_bin:
            return [], set()
        res = self.runner.run(
            [
                lsblk_bin,
                "-J",
                "-b",
                "-o",
                "NAME,KNAME,PATH,TYPE,SIZE,MODEL,SERIAL,WWN,TRAN,RM,MOUNTPOINT,PKNAME,FSTYPE",
            ],
            timeout=5.0,
        )
        if res.returncode != 0 or not res.stdout.strip():
            return [], set()
        data = json.loads(res.stdout)
        return evaluate_block_devices(data)

    def verify_image_signature(
        self,
        *,
        image_path: Path,
        signature_path: Path,
        keyring_path: Path,
    ) -> dict[str, Any]:
        """Verifica assinatura GPG da imagem live offline usando gpgv."""
        gpgv_bin = self.runner.which("gpgv")
        if not gpgv_bin:
            raise FileNotFoundError("Utilitário gpgv não encontrado.")
        res = self.runner.run(
            [gpgv_bin, "--keyring", str(keyring_path), "--", str(signature_path), str(image_path)],
            timeout=15.0,
        )
        ok = res.returncode == 0
        if ok:
            state = self._load_state()
            state["last_image_verified_at"] = now_iso()
            self._save_state(state)
        return {
            "ok": ok,
            "returncode": res.returncode,
            "stderr": res.stderr.strip(),
        }

    def write_to_fd_verified(self, *, image_path: Path, fd: int) -> tuple[int, str]:
        """Grava imagem em descritor aberto e confere integralmente os bytes escritos via SHA-256."""
        written_hash = hashlib.sha256()
        total_written = 0
        with image_path.open("rb") as src:
            while chunk := src.read(65536):
                written_hash.update(chunk)
                view = memoryview(chunk)
                while view:
                    n = os.write(fd, view)
                    total_written += n
                    view = view[n:]
        os.fsync(fd)

        os.lseek(fd, 0, os.SEEK_SET)
        readback_hash = hashlib.sha256()
        remaining = total_written
        while remaining > 0:
            chunk = os.read(fd, min(65536, remaining))
            if not chunk:
                raise IOError("Leitura pós-escrita terminou prematuramente.")
            readback_hash.update(chunk)
            remaining -= len(chunk)

        if readback_hash.hexdigest() != written_hash.hexdigest():
            raise RuntimeError("Falha na conferência pós-escrita: SHA-256 divergente.")
        return total_written, readback_hash.hexdigest()

    def open_device_exclusive_udisks2(
        self,
        *,
        device_path: str,
        expected_identity: BlockDeviceCandidate,
    ) -> tuple[int, dict[str, Any]]:
        """Abre dispositivo exclusivamente via D-Bus UDisks2 (O_EXCL) revalidando propriedades."""
        import gi

        gi.require_version("Gio", "2.0")
        from gi.repository import Gio, GLib

        bus = Gio.bus_get_sync(Gio.BusType.SYSTEM, None)
        dev_name = Path(device_path).name
        if not _BLOCK_DEV_NAME_RE.match(dev_name):
            raise ValueError(f"Nome de dispositivo de bloco inválido: {dev_name}")
        obj_path = f"/org/freedesktop/UDisks2/block_devices/{dev_name}"
        props_proxy = Gio.DBusProxy.new_sync(
            bus,
            Gio.DBusProxyFlags.NONE,
            None,
            "org.freedesktop.UDisks2",
            obj_path,
            "org.freedesktop.UDisks2.Block",
            None,
        )
        size_v = props_proxy.get_cached_property("Size")
        actual_size = int(size_v.unpack()) if size_v is not None else 0
        if actual_size != expected_identity.size_bytes:
            raise RuntimeError(
                f"Capacidade divergente no alvo UDisks2 ({actual_size} != {expected_identity.size_bytes})."
            )

        res, out_fd_list = props_proxy.call_with_unix_fd_list_sync(
            "OpenDevice",
            GLib.Variant("(sa{sv})", ("rw", {"flags": GLib.Variant("i", os.O_EXCL)})),
            Gio.DBusCallFlags.NONE,
            -1,
            None,
            None,
        )
        fd_idx = int(res.unpack()[0])
        fd = out_fd_list.get(fd_idx)
        return fd, {"object_path": obj_path, "size": actual_size}

    def validate_and_write_image(
        self,
        *,
        image_path: Path,
        target_path: Path,
        expected_identity: BlockDeviceCandidate,
        reopened_identity: BlockDeviceCandidate,
        confirmed: bool = False,
        caller_uid: int | None = None,
        use_udisks2: bool = False,
    ) -> dict[str, Any]:
        """Revalida alvo aberto (sistema, capacidade, WWN/serial), grava e confere todos os bytes."""
        if not confirmed:
            raise PermissionError("Gravação da mídia de resgate exige confirmação explícita.")
        if not expected_identity.safe_for_rescue_write:
            raise PermissionError(
                expected_identity.refusal_reason or "Dispositivo não seguro para gravação."
            )
        if not reopened_identity.safe_for_rescue_write:
            raise PermissionError(
                reopened_identity.refusal_reason or "Alvo reaberto recusado por segurança."
            )

        # Recusa se a mídia foi trocada entre seleção e abertura (capacidade, WWN ou serial divergem)
        if (
            reopened_identity.size_bytes != expected_identity.size_bytes
            or reopened_identity.wwn != expected_identity.wwn
            or reopened_identity.serial != expected_identity.serial
            or reopened_identity.path != expected_identity.path
        ):
            raise RuntimeError(
                "Mídia trocada ou identidade divergente detectada ao reabrir o dispositivo; gravação abortada."
            )

        self.authorizer.require("org.mintsecurity.rescue.write-usb", caller_uid=caller_uid)

        if image_path.is_symlink() or not image_path.is_file():
            raise PermissionError(f"Imagem de resgate inválida ou symlink: {image_path}")
        image_bytes = image_path.stat().st_size
        if image_bytes > reopened_identity.size_bytes:
            raise ValueError(
                f"Imagem ({format_bytes(image_bytes)}) excede capacidade da mídia ({format_bytes(reopened_identity.size_bytes)})."
            )

        if use_udisks2:
            fd, _meta = self.open_device_exclusive_udisks2(
                device_path=str(target_path),
                expected_identity=expected_identity,
            )
        else:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            fd = os.open(target_path, flags, 0o600)
        try:
            total_written, digest = self.write_to_fd_verified(image_path=image_path, fd=fd)
        finally:
            os.close(fd)

        state = self._load_state()
        state["last_usb_write_at"] = now_iso()
        state["last_usb_write_bytes"] = total_written
        self._save_state(state)
        self.record_event(
            action="Mídia de resgate gravada e verificada",
            reason=f"{total_written} bytes conferidos via SHA-256 em {target_path}.",
            confirmation_state="confirmed",
            actor="user",
            evidence=f"Modelo: {reopened_identity.model} · Serial: {reopened_identity.serial or reopened_identity.wwn}",
        )
        return {
            "ok": True,
            "bytes_written": total_written,
            "sha256": digest,
        }

    def query_status(self) -> ModuleStatus:
        udisks_info = self.package_inspector.inspect_package("udisks2", binaries=["udisksctl"])
        gpg_info = self.package_inspector.inspect_package("gpgv", binaries=["gpgv"])
        candidates, protected = self.list_block_candidates()
        state = self._load_state()

        if not udisks_info.installed:
            return self.build_status(
                state=ModuleState.AUSENTE,
                installed_version=None,
                package_origin="Não instalado",
                mode_summary="UDisks2 não instalado",
                evidence="Pacote udisks2 necessário para abertura exclusiva de mídia USB.",
            )

        safe_usb = [c for c in candidates if c.safe_for_rescue_write]
        h7_ok = bool(state.get("rescue_h7_approved", False))
        return self.build_status(
            state=ModuleState.DESATIVADO if not h7_ok else ModuleState.ATIVO,
            installed_version=udisks_info.version,
            package_origin=udisks_info.origin,
            mode_summary=(
                f"{len(safe_usb)} mídia(s) USB segura(s) · {len(protected)} disco(s)/partição(ões) protegidos · "
                + ("Homologado H7" if h7_ok else "Aguardando homologação H7")
            ),
            evidence=(
                f"gpgv: {gpg_info.version or 'ausente'} · "
                "Proteção contra gravação em disco de sistema, swap, LUKS, LVM e RAID ativa."
            ),
            last_confirmed_at=state.get("last_usb_write_at") or state.get("last_image_verified_at"),
            details={
                "candidates": [c.to_dict() for c in candidates],
                "protected_count": len(protected),
                "h7_approved": h7_ok,
            },
        )

    def configure(self, **options: Any) -> ModuleStatus:
        return self.query_status()

    def enable(self, **options: Any) -> ModuleStatus:
        return self.query_status()

    def disable(self, *, revert_suite_changes: bool = False) -> ModuleStatus:
        return self.query_status()
