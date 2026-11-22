"""Cliente D-Bus de sistema com ativação sob demanda e fallback local seguro."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from mintsec.auth import AuthorizationError
from mintsec.contracts import ModuleManifest
from mintsec.runner import SubprocessRunner

_DBUS_SERVICE_UNAVAILABLE_MSG = (
    "O serviço administrativo do sistema (D-Bus) está indisponível. "
    "Verifique a instalação do NodusGuard."
)


def is_system_bus_mode() -> bool:
    """Detecta se a suíte roda instalada no sistema ou com MINTSEC_USE_SYSTEM_BUS=1."""
    if os.environ.get("MINTSEC_USE_SYSTEM_BUS", "").strip() == "1":
        return True
    if os.environ.get("MINTSEC_USE_SYSTEM_BUS", "").strip() == "0":
        return False
    return Path(__file__).resolve().as_posix().startswith("/usr/lib/python3/dist-packages/")


def _is_bus_unavailable_error(exc: Exception) -> bool:
    """Permite fallback local somente quando o barramento/serviço D-Bus está ausente."""
    if isinstance(exc, AuthorizationError):
        return False
    err_name = ""
    getter = getattr(exc, "get_dbus_name", None)
    if callable(getter):
        err_name = str(getter() or "")
    msg = str(exc)
    combined = f"{err_name} {msg}"
    for denied in ("AccessDenied", "AuthorizationError", "Autorização negada", "PermissionError", "PolicyKit"):
        if denied in combined:
            return False
    if isinstance(exc, (ImportError, FileNotFoundError)):
        return True
    return any(
        tok in combined
        for tok in (
            "ServiceUnknown",
            "NameHasNoOwner",
            "Disconnected",
            "Failed to connect",
            "Spawn.ExecFailed",
            "org.freedesktop.DBus.Error.FileNotFound",
        )
    )


def _disallow_unprivileged_fallback(local_service: Any) -> bool:
    """Impede fallback silencioso em processo não privilegiado quando usa runner real do host."""
    return isinstance(getattr(local_service, "runner", None), SubprocessRunner) and os.geteuid() != 0


class SystemModuleClient:
    """Despacha operações de módulo via SystemBus (Polkit) ou localmente em desenvolvimento."""

    def __init__(self, manifests: dict[str, ModuleManifest], bus: Any = None) -> None:
        self.manifests = manifests
        self._bus = bus

    def _get_bus(self) -> Any:
        if self._bus is None:
            import dbus

            self._bus = dbus.SystemBus()
        return self._bus

    def call_dbus(
        self,
        module_id: str,
        method_name: str,
        *args: Any,
        timeout: float = 180.0,
    ) -> dict[str, Any]:
        """Invoca método no serviço D-Bus de sistema correspondente ao módulo."""
        import dbus

        manifest = self.manifests[module_id]
        bus = self._get_bus()
        obj = bus.get_object(manifest.dbus_bus_name, manifest.dbus_object_path)
        iface = dbus.Interface(obj, manifest.dbus_bus_name)
        fn = getattr(iface, method_name)
        raw = fn(*args, timeout=timeout)
        return json.loads(str(raw))

    def query_status(self, module_id: str, local_service: Any) -> dict[str, Any]:
        if is_system_bus_mode():
            try:
                return self.call_dbus(module_id, "QueryStatus", timeout=25.0)
            except Exception as exc:
                if not _is_bus_unavailable_error(exc):
                    raise
        return local_service.query_status().to_dict()

    def enable(self, module_id: str, local_service: Any, options: dict[str, Any] | None = None) -> dict[str, Any]:
        if is_system_bus_mode():
            try:
                return self.call_dbus(module_id, "Enable", json.dumps(options or {}), timeout=180.0)
            except Exception as exc:
                if not _is_bus_unavailable_error(exc):
                    raise
                if _disallow_unprivileged_fallback(local_service):
                    raise RuntimeError(_DBUS_SERVICE_UNAVAILABLE_MSG) from exc
        return local_service.enable(**(options or {})).to_dict()

    def disable(self, module_id: str, local_service: Any, *, revert_suite_changes: bool = False) -> dict[str, Any]:
        if is_system_bus_mode():
            try:
                return self.call_dbus(module_id, "Disable", bool(revert_suite_changes), timeout=180.0)
            except Exception as exc:
                if not _is_bus_unavailable_error(exc):
                    raise
                if _disallow_unprivileged_fallback(local_service):
                    raise RuntimeError(_DBUS_SERVICE_UNAVAILABLE_MSG) from exc
        return local_service.disable(revert_suite_changes=revert_suite_changes).to_dict()

    def revoke_firewall_rule(self, rule_id: str, local_service: Any) -> dict[str, Any]:
        if is_system_bus_mode():
            try:
                return self.call_dbus("firewall", "RevokeRule", str(rule_id), timeout=180.0)
            except Exception as exc:
                if not _is_bus_unavailable_error(exc):
                    raise
                if _disallow_unprivileged_fallback(local_service):
                    raise RuntimeError(_DBUS_SERVICE_UNAVAILABLE_MSG) from exc
        ok = bool(local_service.revoke_rule(rule_id))
        return {"ok": ok, "status": local_service.query_status().to_dict()}

    def update_antimalware_signatures(self, local_service: Any) -> dict[str, Any]:
        if is_system_bus_mode():
            try:
                return self.call_dbus("antimalware", "UpdateSignatures", timeout=180.0)
            except Exception as exc:
                if not _is_bus_unavailable_error(exc):
                    raise
                if _disallow_unprivileged_fallback(local_service):
                    raise RuntimeError(_DBUS_SERVICE_UNAVAILABLE_MSG) from exc
        return local_service.update_signatures()
