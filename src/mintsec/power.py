"""Ações de energia pós-verificação via systemd-logind (D-Bus) com fallback systemctl."""

from __future__ import annotations

from typing import Any

from mintsec.runner import CommandRunner, SubprocessRunner

VALID_POST_SCAN_ACTIONS = ("none", "suspend", "shutdown")


def execute_post_scan_action(
    action: str,
    *,
    runner: CommandRunner | None = None,
    bus: Any = None,
) -> dict[str, Any]:
    """Executa ação de energia configurada após o término limpo do scan."""
    clean = str(action).strip()
    if clean not in VALID_POST_SCAN_ACTIONS:
        raise ValueError(f"Ação pós-scan inválida: {action}")
    if clean == "none":
        return {"ok": True, "action": "none", "method": "noop"}

    dbus_err: str = ""
    try:
        import dbus

        sys_bus = bus if bus is not None else dbus.SystemBus()
        obj = sys_bus.get_object("org.freedesktop.login1", "/org/freedesktop/login1")
        iface = dbus.Interface(obj, "org.freedesktop.login1.Manager")
        if clean == "suspend":
            iface.Suspend(False)
        else:
            iface.PowerOff(False)
        return {"ok": True, "action": clean, "method": "login1"}
    except Exception as exc:  # noqa: BLE001
        dbus_err = str(exc)

    cmd_runner = runner or SubprocessRunner()
    subcmd = "suspend" if clean == "suspend" else "poweroff"
    systemctl_bin = cmd_runner.which("systemctl") or "systemctl"
    res = cmd_runner.run([systemctl_bin, subcmd], timeout=15.0)
    ok = res.returncode == 0
    err_txt = (res.stderr or res.stdout or dbus_err).strip()
    return {
        "ok": ok,
        "action": clean,
        "method": "systemctl",
        "returncode": res.returncode,
        "error": "" if ok else err_txt,
    }
