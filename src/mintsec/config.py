"""Configurações persistentes da suíte com separação entre visual e política."""

from __future__ import annotations

import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mintsec.contracts import atomic_write_json, read_json_safe, xdg_dir

VALID_THEME_MODES = {"follow_system", "light", "dark"}
VALID_THEME_PRESETS = {"lavender", "neutral_light", "system_dark", "graphite_dark"}
VALID_DENSITIES = {"essential", "detailed"}
VALID_PAUSE_POLICIES = {"unset", "alert_only", "auto_pause"}
VALID_FIREWALL_OUTBOUND = {"monitor_only", "block_per_app"}
VALID_LANGUAGES = {"en", "pt_BR"}


@dataclass
class SuiteConfig:
    """Preferências da suíte, separando aparência da política de decisão."""

    # Aparência e idioma (nunca altera política de decisão)
    theme_mode: str = "follow_system"
    theme_preset: str = "lavender"
    density: str = "essential"
    language: str = "en"

    # Política de decisão
    pause_policy: str = "unset"
    firewall_outbound_mode: str = "monitor_only"

    # Fluxo de primeiro uso e recursos opcionais
    first_run_completed: bool = False
    history_enabled: bool = True
    notifications_grouped: bool = True
    removable_media_prompt: bool = True
    enabled_modules: dict[str, bool] = field(default_factory=dict)

    def validate(self) -> None:
        """Garante que os valores configurados pertencem aos conjuntos aprovados."""
        if self.theme_mode not in VALID_THEME_MODES:
            raise ValueError(f"theme_mode inválido: {self.theme_mode}")
        if self.theme_preset not in VALID_THEME_PRESETS:
            raise ValueError(f"theme_preset inválido: {self.theme_preset}")
        if self.density not in VALID_DENSITIES:
            raise ValueError(f"density inválida: {self.density}")
        if self.language not in VALID_LANGUAGES:
            raise ValueError(f"language inválido: {self.language}")
        if self.pause_policy not in VALID_PAUSE_POLICIES:
            raise ValueError(f"pause_policy inválida: {self.pause_policy}")
        if self.firewall_outbound_mode not in VALID_FIREWALL_OUTBOUND:
            raise ValueError(f"firewall_outbound_mode inválido: {self.firewall_outbound_mode}")

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuiteConfig:
        cfg = cls(
            theme_mode=str(data.get("theme_mode", "follow_system")),
            theme_preset=str(data.get("theme_preset", "lavender")),
            density=str(data.get("density", "essential")),
            language=str(data.get("language", "en")),
            pause_policy=str(data.get("pause_policy", "unset")),
            firewall_outbound_mode=str(data.get("firewall_outbound_mode", "monitor_only")),
            first_run_completed=bool(data.get("first_run_completed", False)),
            history_enabled=bool(data.get("history_enabled", True)),
            notifications_grouped=bool(data.get("notifications_grouped", True)),
            removable_media_prompt=bool(data.get("removable_media_prompt", True)),
            enabled_modules=dict(data.get("enabled_modules", {})),
        )
        cfg.validate()
        return cfg


class ConfigStore:
    """Gerencia leitura e persistência atômica de SuiteConfig."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (xdg_dir("XDG_CONFIG_HOME", ".config") / "settings.json")
        self._lock = threading.Lock()
        self._cached_sig: tuple[int, int] | None = None
        self._cached_raw: dict[str, Any] | None = None

    def _file_sig(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def load(self) -> SuiteConfig:
        with self._lock:
            sig = self._file_sig()
            if sig is None:
                self._cached_sig = None
                self._cached_raw = None
                return SuiteConfig()
            if self._cached_sig == sig and self._cached_raw is not None:
                return SuiteConfig.from_dict(self._cached_raw)
        raw = read_json_safe(self.path, default={})
        cfg = SuiteConfig.from_dict(raw)
        with self._lock:
            self._cached_sig = self._file_sig()
            self._cached_raw = dict(raw) if self._cached_sig is not None else None
        return cfg

    def save(self, config: SuiteConfig) -> None:
        config.validate()
        payload = config.to_dict()
        atomic_write_json(self.path, payload, mode=0o600)
        with self._lock:
            self._cached_sig = self._file_sig()
            self._cached_raw = payload if self._cached_sig is not None else None

    def update(self, **changes: Any) -> SuiteConfig:
        cfg = self.load()
        for key, value in changes.items():
            if not hasattr(cfg, key):
                raise KeyError(f"Campo de configuração desconhecido: {key}")
            setattr(cfg, key, value)
        self.save(cfg)
        return cfg
