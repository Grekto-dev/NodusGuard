"""Contratos versionados de módulos, estados, eventos e decisões pendentes."""

from __future__ import annotations

import json
import os
import stat
import tempfile
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


SCHEMA_VERSION = "1.0"


class ModuleState(str, Enum):
    """Estados canônicos expostos no painel e na API D-Bus."""

    AUSENTE = "ausente"
    DESATIVADO = "desativado"
    ATIVO = "ativo"
    DEGRADADO = "degradado"
    VERIFICACAO_INCOMPLETA = "verificacao_incompleta"
    INDISPONIVEL = "indisponivel"

    @property
    def ui_label(self) -> str:
        """Rótulo voltado ao usuário para exibição no painel."""
        labels = {
            ModuleState.AUSENTE: "Não instalado",
            ModuleState.DESATIVADO: "Desativado por você",
            ModuleState.ATIVO: "Ativo",
            ModuleState.DEGRADADO: "Degradado",
            ModuleState.VERIFICACAO_INCOMPLETA: "Verificação incompleta",
            ModuleState.INDISPONIVEL: "Estado indisponível",
        }
        return labels[self]


def xdg_dir(env_name: str, default_subpath: str) -> Path:
    """Resolve diretório XDG garantindo caminho absoluto sob $HOME quando omitido."""
    raw = os.environ.get(env_name, "").strip()
    if raw:
        return Path(raw) / "mint-security-suite"
    return Path.home() / default_subpath / "mint-security-suite"


def ensure_private_dir(path: Path, mode: int = 0o700) -> Path:
    """Garante diretório privado pertencente ao usuário atual e sem symlink."""
    if path.is_symlink():
        raise PermissionError(f"Diretório privado não pode ser symlink: {path}")
    path.mkdir(parents=True, exist_ok=True)
    st = os.lstat(path)
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PermissionError(f"Caminho esperado como diretório inválido: {path}")
    if st.st_uid != os.geteuid():
        raise PermissionError(
            f"Diretório '{path}' pertence ao UID {st.st_uid} (esperado {os.geteuid()})."
        )
    os.chmod(path, mode)
    return path


def atomic_write_text(path: Path, content: str, mode: int = 0o600) -> None:
    """Escreve texto de forma atômica via arquivo temporário, fsync e os.replace."""
    if path.parent.is_symlink():
        raise PermissionError(f"Diretório pai não pode ser symlink: {path.parent}")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent_st = os.lstat(path.parent)
    if stat.S_ISLNK(parent_st.st_mode) or not stat.S_ISDIR(parent_st.st_mode):
        raise PermissionError(f"Diretório pai inválido: {path.parent}")
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=str(path.parent))
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_path, mode)
        os.replace(tmp_path, path)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def atomic_write_json(path: Path, payload: Any, mode: int = 0o600) -> None:
    """Escreve JSON de forma atômica via arquivo temporário, fsync e os.replace."""
    serialized = json.dumps(payload, ensure_ascii=False, indent=2) + "\n"
    atomic_write_text(path, serialized, mode=mode)


def read_json_safe(path: Path, default: Any) -> Any:
    """Lê JSON retornando default quando o arquivo não existir."""
    if not path.exists():
        return default
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


@dataclass(frozen=True)
class ModuleManifest:
    """Manifesto versionado que descreve um módulo da suíte."""

    schema_version: str
    module_id: str
    display_name: str
    short_description: str
    phase: str
    experimental: bool
    engine: dict[str, Any]
    packages: list[str]
    optional_packages: list[str]
    deb_package: str
    dbus_bus_name: str
    dbus_object_path: str
    systemd_units: list[str]
    capabilities: list[str]
    operations: list[str]
    reversible_changes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ModuleManifest:
        """Valida e constrói um manifesto a partir de dicionário JSON."""
        required_keys = {
            "schema_version",
            "module_id",
            "display_name",
            "short_description",
            "phase",
            "experimental",
            "engine",
            "packages",
            "deb_package",
            "dbus_bus_name",
            "dbus_object_path",
            "systemd_units",
            "capabilities",
            "operations",
        }
        missing = sorted(required_keys - set(data.keys()))
        if missing:
            raise ValueError(f"Manifesto inválido, campos ausentes: {', '.join(missing)}")
        if data["schema_version"] != SCHEMA_VERSION:
            raise ValueError(f"Versão de esquema incompatível: {data['schema_version']}")
        if data["phase"] not in {"mvp", "continuous", "conditional"}:
            raise ValueError(f"Fase inválida no manifesto: {data['phase']}")
        for core_op in ("query", "configure", "enable", "disable"):
            if core_op not in data["operations"]:
                raise ValueError(f"Operação obrigatória ausente no manifesto {data['module_id']}: {core_op}")
        return cls(
            schema_version=str(data["schema_version"]),
            module_id=str(data["module_id"]),
            display_name=str(data["display_name"]),
            short_description=str(data["short_description"]),
            phase=str(data["phase"]),
            experimental=bool(data["experimental"]),
            engine=dict(data["engine"]),
            packages=list(data["packages"]),
            optional_packages=list(data.get("optional_packages", [])),
            deb_package=str(data["deb_package"]),
            dbus_bus_name=str(data["dbus_bus_name"]),
            dbus_object_path=str(data["dbus_object_path"]),
            systemd_units=list(data["systemd_units"]),
            capabilities=list(data["capabilities"]),
            operations=list(data["operations"]),
            reversible_changes=list(data.get("reversible_changes", [])),
        )


@dataclass
class ModuleStatus:
    """Estado operacional atual de um módulo com evidência e origem real do pacote."""

    module_id: str
    display_name: str
    state: ModuleState
    installed_version: str | None
    package_origin: str
    mode_summary: str
    last_confirmed_at: str | None
    evidence: str
    degraded_reason: str | None = None
    needs_setup: bool = False
    phase: str = "mvp"
    experimental: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["state"] = self.state.value
        payload["state_label"] = self.state.ui_label
        return payload


@dataclass
class EventRecord:
    """Evento registrado com quem agiu, evidência, horário e reversibilidade."""

    event_id: str
    module_id: str
    action: str
    reason: str
    timestamp: str
    confirmation_state: str
    actor: str = "suite"
    evidence: str = ""
    app_name: str = ""
    reversible: bool = False
    revert_action: str | None = None
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class PendingDecision:
    """Pendência aberta que exige decisão do usuário ou acompanha incidente ativo."""

    pending_id: str
    kind: str
    module_id: str
    app_name: str
    title: str
    summary: str
    evidence: str
    created_at: str
    status: str = "open"
    fan_q_overflow: bool = False
    affected_paths: list[str] = field(default_factory=list)
    actions: list[str] = field(default_factory=list)
    incident_id: str | None = None
    occurrences: int = 1
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PendingDecision:
        return cls(
            pending_id=str(data["pending_id"]),
            kind=str(data["kind"]),
            module_id=str(data["module_id"]),
            app_name=str(data.get("app_name", "")),
            title=str(data["title"]),
            summary=str(data["summary"]),
            evidence=str(data.get("evidence", "")),
            created_at=str(data["created_at"]),
            status=str(data.get("status", "open")),
            fan_q_overflow=bool(data.get("fan_q_overflow", False)),
            affected_paths=list(data.get("affected_paths", [])),
            actions=list(data.get("actions", [])),
            incident_id=data.get("incident_id"),
            occurrences=int(data.get("occurrences", 1)),
            metadata=dict(data.get("metadata", {})),
        )


def default_manifests_dir() -> Path:
    """Localiza o diretório de manifestos no repositório ou instalação padrão."""
    env_dir = os.environ.get("MINTSEC_MANIFESTS_DIR", "").strip()
    if env_dir:
        return Path(env_dir)
    repo_dir = Path(__file__).resolve().parents[2] / "manifests"
    if repo_dir.is_dir():
        return repo_dir
    return Path("/usr/share/mint-security-suite/manifests")


def load_manifests(manifests_dir: Path | None = None) -> dict[str, ModuleManifest]:
    """Carrega e valida todos os manifestos JSON do diretório informado."""
    target = manifests_dir or default_manifests_dir()
    if not target.is_dir():
        raise FileNotFoundError(f"Diretório de manifestos não encontrado: {target}")
    manifests: dict[str, ModuleManifest] = {}
    for file_path in sorted(target.glob("*.json")):
        with file_path.open("r", encoding="utf-8") as handle:
            raw = json.load(handle)
        manifest = ModuleManifest.from_dict(raw)
        manifests[manifest.module_id] = manifest
    return manifests
