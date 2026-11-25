"""Daemon D-Bus sob demanda para os serviços isolados e histórico WAL."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, NoReturn

from mintsec.auth import AuthorizationError, CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import ensure_private_dir
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.services.catalog import SuiteController


ENABLE_OPTION_ALLOWLIST: dict[str, frozenset[str]] = {
    "antimalware": frozenset({"monitored_folders", "exclusions", "realtime_opt_in", "limits"}),
    "firewall": frozenset({"apply_essential_rules"}),
    "recovery": frozenset(
        {"repo_path", "repo_type", "separate_maintenance_credential", "include_paths", "schedule_days"}
    ),
    "network": frozenset({"network_id", "is_home"}),
    "browsing": frozenset({"engine", "upstream_resolvers", "vpn_private_domains"}),
    "isolation": frozenset(),
    "rescue": frozenset(),
}


def _build_daemon_controller(*, use_system_state: bool = False) -> SuiteController:
    """Constrói SuiteController isolando estado sob STATE_DIRECTORY quando executa como root."""
    if not use_system_state and os.geteuid() != 0 and not os.environ.get("STATE_DIRECTORY", "").strip():
        return SuiteController(authorizer=CallerAuthorizer())

    raw_state = os.environ.get("STATE_DIRECTORY", "").strip() or "/var/lib/mint-security-suite"
    state_dir = ensure_private_dir(Path(raw_state), 0o700)
    cfg_store = ConfigStore(state_dir / "settings.json")
    cfg = cfg_store.load()
    return SuiteController(
        config_store=cfg_store,
        pending_store=PendingStore(state_dir / "pending.json"),
        history_store=HistoryStore(state_dir / "history.db", enabled=cfg.history_enabled),
        incident_manager=IncidentManager(state_dir / "incidents"),
        authorizer=CallerAuthorizer(),
        data_dir=state_dir,
    )


def _raise_dbus_error(exc: Exception) -> NoReturn:
    import dbus

    if isinstance(exc, AuthorizationError):
        raise dbus.DBusException(str(exc), name="org.freedesktop.DBus.Error.AccessDenied")
    raise dbus.DBusException(str(exc))


def _authorize_dbus_call(
    authorizer: CallerAuthorizer,
    bus_obj: Any,
    action_id: str,
    sender: str | None,
) -> int | None:
    """Autentica o chamador D-Bus real via sender_bus_name no Polkit."""
    if not sender:
        if getattr(authorizer, "_test_decision", None) is None:
            raise AuthorizationError("Remetente D-Bus ausente; autorização recusada.")
        uid: int | None = None
    else:
        uid = authorizer.get_dbus_caller_uid(sender, bus=bus_obj)
    authorizer.require(action_id, sender_bus_name=sender, caller_uid=uid)
    return uid


class ModuleDBusService:
    """Expõe operações do módulo via D-Bus com verificação de remetente e ociosidade."""

    def __init__(
        self,
        *,
        controller: SuiteController,
        module_id: str,
        idle_exit_secs: int = 30,
        bus: Any = None,
        loop: Any = None,
    ) -> None:
        import dbus
        import dbus.service
        from gi.repository import GLib

        self.controller = controller
        self.module_id = module_id
        self.idle_exit_secs = idle_exit_secs
        self.loop = loop or GLib.MainLoop()
        self._timeout_id: int | None = None

        manifest = controller.manifests[module_id]
        bus_obj = bus or dbus.SystemBus()
        self._bus_name = dbus.service.BusName(manifest.dbus_bus_name, bus_obj)

        service = controller.services[module_id]
        authorizer = controller.authorizer
        allowed_keys = ENABLE_OPTION_ALLOWLIST.get(module_id, frozenset())

        class _Exported(dbus.service.Object):
            def __init__(inner_self) -> None:
                super().__init__(bus_obj, manifest.dbus_object_path)

            def _touch(inner_self) -> None:
                self._reset_idle_timer()

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="",
                out_signature="s",
                sender_keyword="sender",
            )
            def QueryStatus(inner_self, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    _authorize_dbus_call(authorizer, bus_obj, "org.mintsecurity.suite.query", sender)
                    return json.dumps(service.query_status().to_dict(), ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="s",
                out_signature="s",
                sender_keyword="sender",
            )
            def Enable(inner_self, options_json: str, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    action_id = (
                        "org.mintsecurity.firewall.configure"
                        if module_id == "firewall"
                        else "org.mintsecurity.module.toggle"
                    )
                    uid = _authorize_dbus_call(authorizer, bus_obj, action_id, sender)
                    raw_opts = json.loads(options_json or "{}")
                    if not isinstance(raw_opts, dict):
                        raise ValueError("Parâmetro options_json deve ser um objeto JSON.")
                    unknown = set(raw_opts.keys()) - allowed_keys
                    if unknown:
                        raise ValueError(f"Opções não permitidas para {module_id}: {', '.join(sorted(unknown))}")
                    filtered: dict[str, Any] = {k: v for k, v in raw_opts.items() if k in allowed_keys}
                    if module_id == "firewall":
                        filtered["caller_uid"] = uid
                        filtered["_preauthorized"] = True
                    return json.dumps(service.enable(**filtered).to_dict(), ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="b",
                out_signature="s",
                sender_keyword="sender",
            )
            def Disable(inner_self, revert_suite_changes: bool, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    revert = bool(revert_suite_changes)
                    if module_id == "firewall":
                        action_id = (
                            "org.mintsecurity.firewall.reset"
                            if revert
                            else "org.mintsecurity.firewall.configure"
                        )
                    else:
                        action_id = "org.mintsecurity.module.toggle"
                    uid = _authorize_dbus_call(authorizer, bus_obj, action_id, sender)
                    if module_id == "firewall":
                        status = service.disable(
                            revert_suite_changes=revert,
                            caller_uid=uid,
                            preauthorized=True,
                        )
                    else:
                        status = service.disable(revert_suite_changes=revert)
                    return json.dumps(status.to_dict(), ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="s",
                out_signature="s",
                sender_keyword="sender",
            )
            def RevokeRule(inner_self, rule_id: str, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    if module_id != "firewall":
                        raise ValueError("RevokeRule só é suportado pelo módulo firewall.")
                    uid = _authorize_dbus_call(
                        authorizer,
                        bus_obj,
                        "org.mintsecurity.firewall.configure",
                        sender,
                    )
                    clean_id = str(rule_id).strip()
                    if not clean_id:
                        raise ValueError("Identificador de regra inválido.")
                    ok = service.revoke_rule(clean_id, caller_uid=uid, preauthorized=True)
                    return json.dumps(
                        {"ok": bool(ok), "status": service.query_status().to_dict()},
                        ensure_ascii=False,
                    )
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="",
                out_signature="s",
                sender_keyword="sender",
            )
            def UpdateSignatures(inner_self, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    if module_id != "antimalware":
                        raise ValueError("UpdateSignatures só é suportado pelo módulo antimalware.")
                    uid = _authorize_dbus_call(
                        authorizer,
                        bus_obj,
                        "org.mintsecurity.antimalware.update-db",
                        sender,
                    )
                    res = service.update_signatures(caller_uid=uid, preauthorized=True)
                    return json.dumps(res, ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="s",
                out_signature="s",
                sender_keyword="sender",
            )
            def AllowAppPreset(inner_self, payload_json: str, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    if module_id != "firewall":
                        raise ValueError("AllowAppPreset só é suportado pelo módulo firewall.")
                    uid = _authorize_dbus_call(
                        authorizer,
                        bus_obj,
                        "org.mintsecurity.firewall.configure",
                        sender,
                    )
                    payload = json.loads(payload_json or "{}")
                    if not isinstance(payload, dict):
                        raise ValueError("Parâmetro payload_json deve ser um objeto JSON.")
                    allowed = {"preset_id", "lan_only", "source_cidr"}
                    unknown = set(payload.keys()) - allowed
                    if unknown:
                        raise ValueError(f"Opções não permitidas em AllowAppPreset: {', '.join(sorted(unknown))}")
                    res = service.allow_app_preset(
                        str(payload.get("preset_id", "")),
                        lan_only=payload.get("lan_only"),
                        source_cidr=payload.get("source_cidr"),
                        caller_uid=uid,
                        preauthorized=True,
                    )
                    return json.dumps(res, ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="s",
                out_signature="s",
                sender_keyword="sender",
            )
            def RevokeAppPreset(inner_self, preset_id: str, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    if module_id != "firewall":
                        raise ValueError("RevokeAppPreset só é suportado pelo módulo firewall.")
                    uid = _authorize_dbus_call(
                        authorizer,
                        bus_obj,
                        "org.mintsecurity.firewall.configure",
                        sender,
                    )
                    res = service.revoke_app_preset(
                        str(preset_id or "").strip(),
                        caller_uid=uid,
                        preauthorized=True,
                    )
                    return json.dumps(res, ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="s",
                out_signature="s",
                sender_keyword="sender",
            )
            def AllowCustomPorts(inner_self, payload_json: str, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    if module_id != "firewall":
                        raise ValueError("AllowCustomPorts só é suportado pelo módulo firewall.")
                    uid = _authorize_dbus_call(
                        authorizer,
                        bus_obj,
                        "org.mintsecurity.firewall.configure",
                        sender,
                    )
                    payload = json.loads(payload_json or "{}")
                    if not isinstance(payload, dict):
                        raise ValueError("Parâmetro payload_json deve ser um objeto JSON.")
                    allowed = {"app_name", "ports", "direction", "protocol", "lan_only", "source_cidr"}
                    unknown = set(payload.keys()) - allowed
                    if unknown:
                        raise ValueError(f"Opções não permitidas em AllowCustomPorts: {', '.join(sorted(unknown))}")
                    raw_ports = payload.get("ports")
                    if not isinstance(raw_ports, list):
                        raise ValueError("Parâmetro ports deve ser uma lista.")
                    res = service.allow_custom_app_ports(
                        app_name=str(payload.get("app_name", "")),
                        ports=[str(p) for p in raw_ports],
                        direction=str(payload.get("direction", "in")),
                        protocol=str(payload.get("protocol", "both")),
                        lan_only=bool(payload.get("lan_only", True)),
                        source_cidr=payload.get("source_cidr"),
                        caller_uid=uid,
                        preauthorized=True,
                    )
                    return json.dumps(res, ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="s",
                out_signature="s",
                sender_keyword="sender",
            )
            def AllowUfwProfile(inner_self, profile_name: str, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    if module_id != "firewall":
                        raise ValueError("AllowUfwProfile só é suportado pelo módulo firewall.")
                    uid = _authorize_dbus_call(
                        authorizer,
                        bus_obj,
                        "org.mintsecurity.firewall.configure",
                        sender,
                    )
                    res = service.allow_ufw_profile(
                        str(profile_name or "").strip(),
                        caller_uid=uid,
                        preauthorized=True,
                    )
                    return json.dumps(res, ensure_ascii=False)
                except Exception as exc:
                    _raise_dbus_error(exc)

        self._exported = _Exported()
        self._reset_idle_timer()

    def _reset_idle_timer(self) -> None:
        if self.idle_exit_secs <= 0:
            return
        from gi.repository import GLib

        if self._timeout_id is not None:
            GLib.source_remove(self._timeout_id)
        self._timeout_id = GLib.timeout_add_seconds(self.idle_exit_secs, self._on_idle_exit)

    def _on_idle_exit(self) -> bool:
        self.loop.quit()
        return False

    def run(self) -> None:
        self.loop.run()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Serviço isolado sob demanda do NodusGuard")
    parser.add_argument(
        "--module",
        choices=["antimalware", "firewall", "recovery", "network", "browsing", "isolation", "rescue"],
        help="Módulo a servir via D-Bus",
    )
    parser.add_argument("--idle-exit-secs", type=int, default=30, help="Encerrar após ociosidade (s)")
    parser.add_argument("--run-schedule", help="Executar agendamento específico do antivírus")
    parser.add_argument("--history-only", action="store_true", help="Inicializar/validar histórico WAL sem privilégios")
    args = parser.parse_args(argv)

    controller = _build_daemon_controller(use_system_state=bool(args.module))
    if args.history_only:
        mode = controller.history_store.journal_mode()
        print(f"SQLite history journal_mode={mode}")
        return 0
    if args.run_schedule:
        cfg = controller.config_store.load()
        if cfg.is_protection_paused_now():
            print(json.dumps({"skipped": True, "reason": "protection_paused"}, ensure_ascii=False))
            return 0
        if cfg.game_mode:
            print(json.dumps({"skipped": True, "reason": "game_mode"}, ensure_ascii=False))
            return 0
        schedules = controller.antimalware.list_schedules()
        sched = next((s for s in schedules if s.get("schedule_id") == args.run_schedule), None)
        if sched is None or not sched.get("active", True):
            print(json.dumps({"skipped": True, "reason": "schedule_missing_or_inactive"}, ensure_ascii=False))
            return 0
        result = controller.antimalware.run_scan(
            scope=str(sched["scope"]),
            paths=sched.get("paths") or None,
        )
        print(json.dumps(result.to_dict(), ensure_ascii=False))
        return 0
    if not args.module:
        parser.error("Informe --module, --run-schedule ou --history-only")

    from dbus.mainloop.glib import DBusGMainLoop

    DBusGMainLoop(set_as_default=True)
    srv = ModuleDBusService(
        controller=controller,
        module_id=args.module,
        idle_exit_secs=args.idle_exit_secs,
    )
    srv.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
