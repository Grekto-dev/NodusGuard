"""Daemon D-Bus sob demanda para os serviços isolados e histórico WAL."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from mintsec.auth import AuthorizationError, CallerAuthorizer
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
                    raise dbus.DBusException(str(exc))

            @dbus.service.method(
                manifest.dbus_bus_name,
                in_signature="s",
                out_signature="s",
                sender_keyword="sender",
            )
            def Enable(inner_self, options_json: str, sender: str | None = None) -> str:
                inner_self._touch()
                try:
                    uid = _authorize_dbus_call(authorizer, bus_obj, "org.mintsecurity.module.toggle", sender)
                    raw_opts = json.loads(options_json or "{}")
                    if not isinstance(raw_opts, dict):
                        raise ValueError("Parâmetro options_json deve ser um objeto JSON.")
                    unknown = set(raw_opts.keys()) - allowed_keys
                    if unknown:
                        raise ValueError(f"Opções não permitidas para {module_id}: {', '.join(sorted(unknown))}")
                    filtered: dict[str, Any] = {k: v for k, v in raw_opts.items() if k in allowed_keys}
                    if module_id == "firewall":
                        filtered["caller_uid"] = uid
                    return json.dumps(service.enable(**filtered).to_dict(), ensure_ascii=False)
                except Exception as exc:
                    raise dbus.DBusException(str(exc))

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
                    action_id = (
                        "org.mintsecurity.firewall.reset"
                        if (module_id == "firewall" and revert)
                        else "org.mintsecurity.module.toggle"
                    )
                    uid = _authorize_dbus_call(authorizer, bus_obj, action_id, sender)
                    if module_id == "firewall":
                        status = service.disable(revert_suite_changes=revert, caller_uid=uid)
                    else:
                        status = service.disable(revert_suite_changes=revert)
                    return json.dumps(status.to_dict(), ensure_ascii=False)
                except Exception as exc:
                    raise dbus.DBusException(str(exc))

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

    controller = SuiteController(authorizer=CallerAuthorizer())
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
