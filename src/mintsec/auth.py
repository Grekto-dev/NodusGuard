"""Autorização de chamadores D-Bus, integração Polkit e validação de política."""

from __future__ import annotations

import os
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

DESTRUCTIVE_ACTIONS = frozenset(
    {
        "org.mintsecurity.recovery.overwrite",
        "org.mintsecurity.quarantine.delete",
        "org.mintsecurity.rescue.write-usb",
        "org.mintsecurity.firewall.reset",
    }
)


class AuthorizationError(PermissionError):
    """Erro levantado quando o chamador D-Bus ou Polkit nega a operação."""


@dataclass(frozen=True)
class AuthorizationResult:
    """Resultado explícito de verificação de autorização."""

    authorized: bool
    action_id: str
    caller_uid: int | None
    is_challenge: bool = False
    details: str = ""


def validate_polkit_policy(policy_path: Path) -> list[str]:
    """Valida a política Polkit garantindo ausência de retenção em ações destrutivas."""
    errors: list[str] = []
    tree = ET.parse(policy_path)
    root = tree.getroot()
    found_actions: dict[str, dict[str, str]] = {}

    for action_el in root.findall("action"):
        action_id = action_el.attrib.get("id", "")
        defaults_el = action_el.find("defaults")
        if defaults_el is None:
            errors.append(f"Ação sem <defaults>: {action_id}")
            continue
        found_actions[action_id] = {
            "allow_any": (defaults_el.findtext("allow_any") or "").strip(),
            "allow_inactive": (defaults_el.findtext("allow_inactive") or "").strip(),
            "allow_active": (defaults_el.findtext("allow_active") or "").strip(),
        }

    for action_id in DESTRUCTIVE_ACTIONS:
        if action_id not in found_actions:
            errors.append(f"Ação destrutiva ausente da política: {action_id}")
            continue
        cfg = found_actions[action_id]
        if cfg["allow_active"] != "auth_admin":
            errors.append(
                f"Ação destrutiva {action_id} deve usar allow_active=auth_admin (encontrado: {cfg['allow_active']})"
            )
        if "keep" in cfg["allow_active"] or "keep" in cfg["allow_any"]:
            errors.append(f"Ação destrutiva {action_id} não pode reter autorização")
        if cfg["allow_any"] != "no" or cfg["allow_inactive"] != "no":
            errors.append(f"Ação destrutiva {action_id} deve bloquear allow_any/allow_inactive")

    return errors


def _proc_start_time(pid: int) -> int:
    """Lê starttime (campo 22 de /proc/<pid>/stat) para identificar unix-process no Polkit."""
    try:
        raw = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        rparen = raw.rfind(")")
        if rparen < 0:
            return 0
        fields = raw[rparen + 2 :].split()
        # Índice 0 após ')' corresponde ao campo 3 (state); campo 22 (starttime) fica no índice 19
        return int(fields[19]) if len(fields) > 19 else 0
    except Exception:
        return 0


class CallerAuthorizer:
    """Autoriza remetentes D-Bus via UID e Polkit (com stub injetável para testes)."""

    def __init__(
        self,
        *,
        test_decision: bool | None = None,
        allowed_uids: set[int] | None = None,
    ) -> None:
        self._test_decision = test_decision
        self._allowed_uids = allowed_uids

    def get_dbus_caller_uid(self, sender_bus_name: str, bus: object | None = None) -> int:
        """Obtém o UID Unix real do remetente D-Bus via daemon."""
        import dbus

        if bus is None:
            bus = dbus.SystemBus()
        dbus_obj = bus.get_object("org.freedesktop.DBus", "/org/freedesktop/DBus")  # type: ignore[attr-defined]
        iface_cls = getattr(bus, "Interface", None) or dbus.Interface
        iface = iface_cls(dbus_obj, "org.freedesktop.DBus")
        return int(iface.GetConnectionUnixUser(sender_bus_name))

    def check_polkit(
        self,
        action_id: str,
        *,
        sender_bus_name: str | None = None,
        caller_uid: int | None = None,
        allow_interaction: bool = True,
    ) -> AuthorizationResult:
        """Verifica autorização Polkit para o sujeito informando se é destrutiva."""
        if caller_uid is None:
            caller_uid = os.getuid() if sender_bus_name is None else self.get_dbus_caller_uid(sender_bus_name)

        if self._allowed_uids is not None and caller_uid not in self._allowed_uids:
            return AuthorizationResult(
                authorized=False,
                action_id=action_id,
                caller_uid=caller_uid,
                details="UID do remetente não permitido",
            )

        if self._test_decision is not None:
            return AuthorizationResult(
                authorized=self._test_decision,
                action_id=action_id,
                caller_uid=caller_uid,
                details="Decisão simulada para teste",
            )

        try:
            import dbus

            bus = dbus.SystemBus()
            authority = bus.get_object(
                "org.freedesktop.PolicyKit1",
                "/org/freedesktop/PolicyKit1/Authority",
            )
            iface = dbus.Interface(authority, "org.freedesktop.PolicyKit1.Authority")
            if sender_bus_name:
                subject = ("system-bus-name", {"name": dbus.String(sender_bus_name)})
            else:
                subject = (
                    "unix-process",
                    {
                        "pid": dbus.UInt32(os.getpid()),
                        "start-time": dbus.UInt64(_proc_start_time(os.getpid())),
                        "uid": dbus.UInt32(caller_uid),
                    },
                )
            flags = dbus.UInt32(1 if allow_interaction else 0)
            is_auth, is_challenge, details = iface.CheckAuthorization(
                subject,
                action_id,
                {},
                flags,
                "",
            )
            return AuthorizationResult(
                authorized=bool(is_auth),
                action_id=action_id,
                caller_uid=caller_uid,
                is_challenge=bool(is_challenge),
                details=str(dict(details)),
            )
        except Exception as exc:
            return AuthorizationResult(
                authorized=False,
                action_id=action_id,
                caller_uid=caller_uid,
                details=f"Polkit indisponível: {exc}",
            )

    def require(
        self,
        action_id: str,
        *,
        sender_bus_name: str | None = None,
        caller_uid: int | None = None,
        allow_interaction: bool = True,
    ) -> AuthorizationResult:
        """Exige autorização válida ou levanta AuthorizationError."""
        res = self.check_polkit(
            action_id,
            sender_bus_name=sender_bus_name,
            caller_uid=caller_uid,
            allow_interaction=allow_interaction,
        )
        if not res.authorized:
            raise AuthorizationError(f"Autorização negada para {action_id}: {res.details}")
        return res
