"""Gerenciamento da pasta do incidente fora de $HOME e sobrescrita segura."""

from __future__ import annotations

import errno
import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mintsec.contracts import atomic_write_json, ensure_private_dir, read_json_safe
from mintsec.formatting import format_bytes, now_iso


class IncidentError(RuntimeError):
    """Erro base em operações de preservação da pasta do incidente."""


class InsufficientSpaceError(IncidentError):
    """Levantada quando a pasta do incidente não tem espaço livre suficiente."""

    def __init__(self, required_bytes: int, available_bytes: int) -> None:
        self.required_bytes = required_bytes
        self.available_bytes = available_bytes
        super().__init__(
            f"Espaço insuficiente na pasta do incidente: necessário {format_bytes(required_bytes)}, "
            f"disponível {format_bytes(available_bytes)}."
        )


def sha256_file(path: Path) -> str:
    """Calcula SHA-256 em streaming sem carregar o arquivo inteiro na memória."""
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(65536):
            digest.update(chunk)
    return digest.hexdigest()


@dataclass
class PreservedItem:
    """Registro de um arquivo preservado durante tratamento de incidente."""

    original_path: str
    preserved_path: str
    restored_from_path: str
    original_sha256: str
    restored_sha256: str
    size_bytes: int
    method: str  # 'rename' ou 'copy'
    status: str  # 'completed' | 'interrupted' | 'preserved_only'
    timestamp: str

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class IncidentReport:
    """Resumo persistido e inspecionável de uma pasta de incidente."""

    incident_id: str
    incident_dir: str
    total_bytes: int
    items: list[PreservedItem] = field(default_factory=list)


class IncidentManager:
    """Gerencia preservação segura antes de sobrescrever originais em incidentes."""

    def __init__(self, root_dir: Path | None = None) -> None:
        env_root = os.environ.get("MINTSEC_INCIDENT_ROOT", "").strip()
        if root_dir is not None:
            candidate = root_dir
        elif env_root:
            candidate = Path(env_root)
        else:
            candidate = Path(f"/var/tmp/mint-security-incidents-{os.getuid()}")

        self.root_dir = self._validate_outside_home(candidate)

    @staticmethod
    def _validate_outside_home(candidate: Path) -> Path:
        if candidate.is_symlink():
            raise PermissionError(f"A pasta do incidente não pode ser symlink: {candidate}")
        resolved = Path(os.path.realpath(candidate))
        home_resolved = Path(os.path.realpath(os.path.expanduser("~")))
        if resolved == home_resolved or home_resolved in resolved.parents:
            raise ValueError(
                f"A pasta do incidente deve ficar fora de $HOME ({home_resolved}): {resolved}"
            )
        return resolved

    def incident_dir(self, incident_id: str) -> Path:
        """Retorna o caminho seguro (0700) da pasta do incidente."""
        safe_id = "".join(ch for ch in incident_id if ch.isalnum() or ch in ("-", "_"))
        if not safe_id:
            raise ValueError("Identificador de incidente inválido")
        ensure_private_dir(self.root_dir, 0o700)
        target = self.root_dir / safe_id
        ensure_private_dir(target, 0o700)
        return target

    def _manifest_path(self, incident_id: str) -> Path:
        return self.incident_dir(incident_id) / "incident.json"

    def _load_manifest(self, incident_id: str) -> dict[str, Any]:
        return read_json_safe(
            self._manifest_path(incident_id),
            default={"incident_id": incident_id, "items": []},
        )

    def _save_manifest(self, incident_id: str, manifest: dict[str, Any]) -> None:
        atomic_write_json(self._manifest_path(incident_id), manifest, mode=0o600)

    def _unique_preserved_path(self, inc_dir: Path, original: Path) -> Path:
        files_dir = ensure_private_dir(inc_dir / "preserved", 0o700)
        base = files_dir / original.name
        if not base.exists():
            return base
        counter = 1
        while True:
            candidate = files_dir / f"{original.stem}.{counter}{original.suffix}"
            if not candidate.exists():
                return candidate
            counter += 1

    def prepare_and_overwrite(
        self,
        *,
        target_path: Path,
        restored_source_path: Path,
        incident_id: str,
        simulate_interrupt_after_preserve: bool = False,
    ) -> PreservedItem:
        """Preserva o original fora de $HOME (rename ou cópia verificada) antes de sobrescrever."""
        target = Path(target_path)
        restored_src = Path(restored_source_path)
        if restored_src.is_symlink():
            raise PermissionError(f"Arquivo de origem de restauração não pode ser symlink: {restored_src}")
        if not restored_src.is_file():
            raise FileNotFoundError(f"Versão a restaurar não encontrada: {restored_src}")
        if target.is_symlink():
            raise PermissionError(f"Arquivo alvo de sobrescrita não pode ser symlink: {target}")
        if not target.exists():
            raise FileNotFoundError(f"Arquivo original esperado não encontrado: {target}")

        inc_dir = self.incident_dir(incident_id)
        restored_sha = sha256_file(restored_src)
        original_sha = sha256_file(target)
        orig_stat = target.stat()
        size_bytes = orig_stat.st_size
        preserved_path = self._unique_preserved_path(inc_dir, target)

        inc_stat = inc_dir.stat()
        method = "copy"

        if orig_stat.st_dev == inc_stat.st_dev:
            try:
                os.rename(target, preserved_path)
                method = "rename"
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise

        if method == "copy":
            statvfs = os.statvfs(inc_dir)
            available = statvfs.f_bavail * statvfs.f_frsize
            required = size_bytes + 4096
            if available < required:
                raise InsufficientSpaceError(required_bytes=required, available_bytes=available)
            shutil.copy2(target, preserved_path)
            copied_sha = sha256_file(preserved_path)
            if copied_sha != original_sha:
                preserved_path.unlink(missing_ok=True)
                raise IncidentError(
                    "Falha na conferência da cópia preservada antes da substituição; original mantido."
                )

        # Protege a cópia preservada contra escrita
        os.chmod(preserved_path, stat.S_IRUSR)

        manifest = self._load_manifest(incident_id)
        item = PreservedItem(
            original_path=str(target),
            preserved_path=str(preserved_path),
            restored_from_path=str(restored_src),
            original_sha256=original_sha,
            restored_sha256=restored_sha,
            size_bytes=size_bytes,
            method=method,
            status="preserved_only" if simulate_interrupt_after_preserve else "completed",
            timestamp=now_iso(),
        )
        manifest["items"].append(item.to_dict())
        self._save_manifest(incident_id, manifest)

        if simulate_interrupt_after_preserve:
            raise InterruptedError(
                f"Operação interrompida após preservar versão anterior em {preserved_path}"
            )

        # Copia versão restaurada para arquivo temporário aleatório no diretório destino e substitui atomicamente
        fd, tmp_name = tempfile.mkstemp(prefix=".mintsec-restore-", suffix=".tmp", dir=str(target.parent))
        tmp_dest = Path(tmp_name)
        try:
            with restored_src.open("rb") as src_h, os.fdopen(fd, "wb") as dst_h:
                shutil.copyfileobj(src_h, dst_h, length=65536)
                dst_h.flush()
                os.fsync(dst_h.fileno())
            os.chmod(tmp_dest, orig_stat.st_mode & 0o777)
            if sha256_file(tmp_dest) != restored_sha:
                raise IncidentError("Divergência ao gravar arquivo restaurado; versão preservada permanece intacta.")
            os.replace(tmp_dest, target)
        except Exception:
            tmp_dest.unlink(missing_ok=True)
            raise
        return item

    def get_report(self, incident_id: str) -> IncidentReport:
        """Retorna os itens preservados e espaço ocupado na pasta do incidente."""
        inc_dir = self.incident_dir(incident_id)
        manifest = self._load_manifest(incident_id)
        total = 0
        for root, _, files in os.walk(inc_dir, followlinks=False):
            for fname in files:
                fpath = Path(root) / fname
                if fpath.is_symlink():
                    continue
                try:
                    total += fpath.stat().st_size
                except OSError:
                    pass
        items = [PreservedItem(**entry) for entry in manifest.get("items", [])]
        return IncidentReport(
            incident_id=incident_id,
            incident_dir=str(inc_dir),
            total_bytes=total,
            items=items,
        )

    def list_incidents(self) -> list[IncidentReport]:
        """Lista todas as pastas de incidentes existentes."""
        if not self.root_dir.exists():
            return []
        reports: list[IncidentReport] = []
        for child in sorted(self.root_dir.iterdir()):
            if child.is_dir():
                reports.append(self.get_report(child.name))
        return reports

    def cleanup_incident(self, incident_id: str, *, confirmed: bool = False) -> int:
        """Remove a pasta do incidente mediante confirmação explícita, retornando bytes liberados."""
        if not confirmed:
            raise PermissionError("Limpeza da pasta do incidente exige confirmação explícita.")
        inc_dir = self.incident_dir(incident_id)
        freed = self.get_report(incident_id).total_bytes
        for root, dirs, files in os.walk(inc_dir, topdown=False, followlinks=False):
            for fname in files:
                fpath = Path(root) / fname
                if not fpath.is_symlink():
                    os.chmod(fpath, 0o600)
                fpath.unlink()
            for dname in dirs:
                dpath = Path(root) / dname
                if dpath.is_symlink():
                    dpath.unlink()
                else:
                    os.chmod(dpath, 0o700)
                    dpath.rmdir()
        os.chmod(inc_dir, 0o700)
        inc_dir.rmdir()
        return freed
