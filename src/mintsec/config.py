"""Configurações persistentes da suíte com separação entre visual e política."""

from __future__ import annotations

import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

from mintsec.contracts import atomic_write_json, read_json_safe, xdg_dir

VALID_THEME_MODES = {"follow_system", "light", "dark"}
VALID_THEME_PRESETS = {"lavender", "neutral_light", "system_dark", "graphite_dark"}
VALID_DENSITIES = {"essential", "detailed"}
VALID_PAUSE_POLICIES = {"unset", "alert_only", "auto_pause"}
VALID_FIREWALL_OUTBOUND = {"monitor_only", "block_per_app"}
VALID_LANGUAGES = {"en", "pt_BR"}
VALID_PAUSE_MODES = {"none", "timed", "until_restart", "indefinite"}
VALID_AUTO_SCAN_INTERVALS = {"6h", "12h", "daily", "weekly"}
VALID_SCAN_POST_ACTIONS = {"none", "suspend", "shutdown"}
_REC_ID_RE = re.compile(r"^[a-z0-9_:-]{1,64}$")


@dataclass
class SuiteConfig:
    """Preferências da suíte, separando aparência da política de decisão."""

    # Aparência e idioma (nunca altera política de decisão)
    theme_mode: str = "follow_system"
    theme_preset: str = "lavender"
    density: str = "essential"
    language: str = "en"
    use_system_titlebar: bool = True

    # Política de decisão
    pause_policy: str = "unset"
    firewall_outbound_mode: str = "monitor_only"

    # Fluxo de primeiro uso e recursos opcionais
    first_run_completed: bool = False
    history_enabled: bool = True
    notifications_grouped: bool = True
    removable_media_prompt: bool = True
    enabled_modules: dict[str, bool] = field(default_factory=dict)

    # Inicialização, agendamento automático, modos e pausa de proteção
    autostart_enabled: bool = True
    auto_quick_scan_enabled: bool = True
    auto_quick_scan_interval: str = "daily"
    auto_db_update_enabled: bool = True
    do_not_disturb: bool = False
    game_mode: bool = False
    protection_paused: bool = False
    protection_pause_mode: str = "none"
    protection_paused_until: str | None = None
    ignored_recommendations: list[str] = field(default_factory=list)
    default_scan_post_action: str = "none"

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
        if self.auto_quick_scan_interval not in VALID_AUTO_SCAN_INTERVALS:
            raise ValueError(f"auto_quick_scan_interval inválido: {self.auto_quick_scan_interval}")
        if self.protection_pause_mode not in VALID_PAUSE_MODES:
            raise ValueError(f"protection_pause_mode inválido: {self.protection_pause_mode}")
        if self.default_scan_post_action not in VALID_SCAN_POST_ACTIONS:
            raise ValueError(f"default_scan_post_action inválido: {self.default_scan_post_action}")

    def is_protection_paused_now(self, now: datetime | None = None) -> bool:
        """Informa se a proteção está atualmente pausada levando em conta expiração temporizada."""
        if not self.protection_paused:
            return False
        if self.protection_pause_mode == "timed":
            if not self.protection_paused_until:
                return False
            try:
                until_dt = datetime.fromisoformat(self.protection_paused_until)
            except ValueError:
                return False
            ref = now or datetime.now(tz=until_dt.tzinfo)
            if ref.tzinfo is None and until_dt.tzinfo is not None:
                ref = ref.replace(tzinfo=until_dt.tzinfo)
            return ref < until_dt
        return self.protection_pause_mode in {"until_restart", "indefinite"}

    def to_dict(self) -> dict[str, Any]:
        self.validate()
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SuiteConfig:
        if not isinstance(data, dict):
            data = {}
        raw_until = data.get("protection_paused_until")
        clean_until: str | None = None
        if isinstance(raw_until, str) and raw_until.strip():
            try:
                datetime.fromisoformat(raw_until.strip())
                clean_until = raw_until.strip()
            except ValueError:
                clean_until = None

        raw_modules = data.get("enabled_modules", {})
        clean_modules = (
            {str(k): bool(v) for k, v in raw_modules.items()}
            if isinstance(raw_modules, dict)
            else {}
        )

        raw_ignored = data.get("ignored_recommendations", [])
        clean_ignored: list[str] = []
        seen_ignored: set[str] = set()
        if isinstance(raw_ignored, list):
            for entry in raw_ignored:
                s = str(entry).strip()
                if _REC_ID_RE.fullmatch(s) and s not in seen_ignored:
                    seen_ignored.add(s)
                    clean_ignored.append(s)
                    if len(clean_ignored) >= 32:
                        break

        cfg = cls(
            theme_mode=str(data.get("theme_mode", "follow_system")),
            theme_preset=str(data.get("theme_preset", "lavender")),
            density=str(data.get("density", "essential")),
            language=str(data.get("language", "en")),
            use_system_titlebar=bool(data.get("use_system_titlebar", True)),
            pause_policy=str(data.get("pause_policy", "unset")),
            firewall_outbound_mode=str(data.get("firewall_outbound_mode", "monitor_only")),
            first_run_completed=bool(data.get("first_run_completed", False)),
            history_enabled=bool(data.get("history_enabled", True)),
            notifications_grouped=bool(data.get("notifications_grouped", True)),
            removable_media_prompt=bool(data.get("removable_media_prompt", True)),
            enabled_modules=clean_modules,
            autostart_enabled=bool(data.get("autostart_enabled", True)),
            auto_quick_scan_enabled=bool(data.get("auto_quick_scan_enabled", True)),
            auto_quick_scan_interval=str(data.get("auto_quick_scan_interval", "daily")),
            auto_db_update_enabled=bool(data.get("auto_db_update_enabled", True)),
            do_not_disturb=bool(data.get("do_not_disturb", False)),
            game_mode=bool(data.get("game_mode", False)),
            protection_paused=bool(data.get("protection_paused", False)),
            protection_pause_mode=str(data.get("protection_pause_mode", "none")),
            protection_paused_until=clean_until,
            ignored_recommendations=clean_ignored,
            default_scan_post_action=str(data.get("default_scan_post_action", "none")),
        )
        cfg.validate()
        return cfg


class ConfigStore:
    """Gerencia leitura e persistência atômica de SuiteConfig."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (xdg_dir("XDG_CONFIG_HOME", ".config") / "settings.json")
        self._lock = threading.RLock()
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
        with self._lock:
            cfg = self.load()
            for key, value in changes.items():
                if not hasattr(cfg, key):
                    raise KeyError(f"Campo de configuração desconhecido: {key}")
                setattr(cfg, key, value)
            self.save(cfg)
            return cfg
