"""Testes de pausa/retomada de scan, ação pós-scan imediata/padrão e elevação D-Bus/Polkit."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from mintsec.auth import AuthorizationError, CallerAuthorizer
from mintsec.config import ConfigStore, SuiteConfig
from mintsec.contracts import ModuleState, load_manifests
from mintsec.dbus_client import SystemModuleClient, _is_bus_unavailable_error
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.power import execute_post_scan_action
from mintsec.runner import CommandResult, SubprocessRunner
from mintsec.services import daemon
from mintsec.services.catalog import SuiteController
from mintsec.services.daemon import ModuleDBusService, _build_daemon_controller


class _RecordingAuthorizer(CallerAuthorizer):
    def __init__(self, *, decision: bool = True) -> None:
        super().__init__(test_decision=decision)
        self.calls: list[tuple[str, str | None, int | None]] = []

    def get_dbus_caller_uid(self, sender_bus_name: str, bus: object | None = None) -> int:
        return 1000

    def require(
        self,
        action_id: str,
        *,
        sender_bus_name: str | None = None,
        caller_uid: int | None = None,
        allow_interaction: bool = True,
    ):
        self.calls.append((action_id, sender_bus_name, caller_uid))
        return super().require(
            action_id,
            sender_bus_name=sender_bus_name,
            caller_uid=caller_uid,
            allow_interaction=allow_interaction,
        )


class _FakeToolRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def which(self, binary: str) -> str | None:
        if binary in ("clamscan", "freshclam", "ufw", "systemctl"):
            return f"/usr/bin/{binary}"
        return None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None, pause_event=None) -> CommandResult:
        cmd = [str(a) for a in argv]
        self.calls.append(cmd)
        name = Path(cmd[0]).name
        if name == "dpkg-query":
            return CommandResult(tuple(cmd), 0, "install ok installed\t1.0.0\n", "")
        if name == "apt-cache":
            return CommandResult(
                tuple(cmd),
                0,
                " *** 1.0.0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n",
                "",
            )
        if name == "ufw" and cmd[1:3] == ["status", "numbered"]:
            return CommandResult(tuple(cmd), 0, "Status: inactive\n", "")
        if name == "freshclam":
            return CommandResult(tuple(cmd), 0, "Database updated.\n", "")
        return CommandResult(tuple(cmd), 0, "", "")


class ScanControlsAndElevationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="mintsec-ctrl-elev-")
        self.root = Path(self.tmp.name)
        self.manifests = load_manifests()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_subprocess_runner_pause_resume_and_cancel_while_paused(self) -> None:
        runner = SubprocessRunner()
        script = (
            "import time, sys\n"
            "for i in range(1, 30):\n"
            "    print(f'tick {i}', flush=True)\n"
            "    time.sleep(0.05)\n"
        )
        pause_ev = threading.Event()
        cancel_ev = threading.Event()
        seen: list[str] = []

        def _on_line(ln: str) -> None:
            seen.append(ln)

        result_holder: list[CommandResult] = []

        def _bg() -> None:
            result_holder.append(
                runner.run(
                    [sys.executable, "-c", script],
                    timeout=5.0,
                    on_line=_on_line,
                    cancel_event=cancel_ev,
                    pause_event=pause_ev,
                )
            )

        t = threading.Thread(target=_bg, daemon=True)
        t.start()
        deadline = time.monotonic() + 3.0
        while len(seen) < 2 and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertGreaterEqual(len(seen), 2)

        pause_ev.set()
        time.sleep(0.12)
        count_paused = len(seen)
        time.sleep(0.25)
        self.assertEqual(len(seen), count_paused, f"Output grew while SIGSTOP paused: {seen}")

        pause_ev.clear()
        deadline_res = time.monotonic() + 3.0
        while len(seen) <= count_paused and time.monotonic() < deadline_res:
            time.sleep(0.02)
        self.assertGreater(len(seen), count_paused)

        cancel_ev.set()
        t.join(timeout=3.0)
        self.assertFalse(t.is_alive())
        self.assertEqual(len(result_holder), 1)
        self.assertTrue(result_holder[0].cancelled)

        # Cancelar estando pausado (SIGSTOP ativo) deve enviar SIGCONT antes de SIGTERM e terminar rápido
        pause_ev2 = threading.Event()
        cancel_ev2 = threading.Event()
        seen2: list[str] = []
        t2_res: list[CommandResult] = []
        t2 = threading.Thread(
            target=lambda: t2_res.append(
                runner.run(
                    [sys.executable, "-c", "import time\nfor i in range(50):\n print(i, flush=True); time.sleep(0.05)"],
                    timeout=5.0,
                    on_line=seen2.append,
                    cancel_event=cancel_ev2,
                    pause_event=pause_ev2,
                )
            ),
            daemon=True,
        )
        t2.start()
        deadline2 = time.monotonic() + 3.0
        while not seen2 and time.monotonic() < deadline2:
            time.sleep(0.02)
        pause_ev2.set()
        time.sleep(0.12)
        cancel_ev2.set()
        t2.join(timeout=2.0)
        self.assertFalse(t2.is_alive())
        self.assertTrue(t2_res and t2_res[0].cancelled)

    def test_antimalware_pause_stats_and_eta_exclusion(self) -> None:
        target = self.root / "scan_files"
        target.mkdir()
        files = [target / f"f{i}.txt" for i in range(4)]
        for fp in files:
            fp.write_text("clean", encoding="utf-8")

        class _PausableClamRunner(_FakeToolRunner):
            def __init__(self, fpaths: list[Path], gate_pause: threading.Event) -> None:
                super().__init__()
                self.fpaths = fpaths
                self.gate_pause = gate_pause

            def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None, pause_event=None) -> CommandResult:
                cmd = [str(a) for a in argv]
                self.calls.append(cmd)
                if Path(cmd[0]).name == "clamscan":
                    out_lines: list[str] = []
                    for idx, fp in enumerate(self.fpaths):
                        if idx == 1:
                            self.gate_pause.set()
                            while pause_event is not None and pause_event.is_set():
                                if cancel_event is not None and cancel_event.is_set():
                                    return CommandResult(tuple(cmd), -1, "\n".join(out_lines), "", cancelled=True)
                                time.sleep(0.02)
                        line = f"{fp}: OK"
                        out_lines.append(line)
                        if on_line:
                            on_line(line)
                        time.sleep(0.02)
                    return CommandResult(tuple(cmd), 0, "\n".join(out_lines) + "\n", "")
                return super().run(argv, timeout=timeout, env=env, on_line=on_line, cancel_event=cancel_event, pause_event=pause_event)

        hit_pause_point = threading.Event()
        runner = _PausableClamRunner(files, hit_pause_point)
        ctrl = SuiteController(
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            incident_manager=IncidentManager(self.root / "incidents"),
            runner=runner,
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
            clamav_db_dir=self.root / "clamdb",
        )
        pause_ev = threading.Event()
        stats_events: list[dict] = []
        holder: list = []
        th = threading.Thread(
            target=lambda: holder.append(
                ctrl.antimalware.run_scan(
                    scope="custom",
                    paths=[str(target)],
                    on_stats=stats_events.append,
                    pause_event=pause_ev,
                )
            ),
            daemon=True,
        )
        th.start()
        self.assertTrue(hit_pause_point.wait(timeout=3.0))
        pause_ev.set()
        time.sleep(0.2)
        self.assertTrue(any(ev.get("phase") == "paused" for ev in stats_events), stats_events)
        pause_ev.clear()
        th.join(timeout=3.0)
        self.assertEqual(len(holder), 1)
        self.assertFalse(holder[0].cancelled)
        self.assertEqual(holder[0].items_scanned, 4)
        self.assertEqual(stats_events[-1]["phase"], "done")

    def test_config_default_post_scan_and_power_helper(self) -> None:
        store = ConfigStore(self.root / "settings.json")
        self.assertEqual(store.load().default_scan_post_action, "none")
        store.update(default_scan_post_action="suspend")
        self.assertEqual(ConfigStore(store.path).load().default_scan_post_action, "suspend")
        store.update(default_scan_post_action="shutdown")
        self.assertEqual(ConfigStore(store.path).load().default_scan_post_action, "shutdown")
        with self.assertRaises(ValueError):
            SuiteConfig(default_scan_post_action="hibernate").validate()

        self.assertEqual(execute_post_scan_action("none")["method"], "noop")
        with self.assertRaises(ValueError):
            execute_post_scan_action("reboot_invalid")

        fake_iface = mock.MagicMock()
        fake_bus = mock.MagicMock()
        with mock.patch("dbus.Interface", return_value=fake_iface):
            res_s = execute_post_scan_action("suspend", bus=fake_bus)
            res_p = execute_post_scan_action("shutdown", bus=fake_bus)
        self.assertEqual(res_s, {"ok": True, "action": "suspend", "method": "login1"})
        self.assertEqual(res_p, {"ok": True, "action": "shutdown", "method": "login1"})
        fake_iface.Suspend.assert_called_once_with(False)
        fake_iface.PowerOff.assert_called_once_with(False)

        broken_bus = mock.MagicMock()
        broken_bus.get_object.side_effect = RuntimeError("no logind bus")
        runner = _FakeToolRunner()
        res_fb = execute_post_scan_action("shutdown", runner=runner, bus=broken_bus)
        self.assertTrue(res_fb["ok"])
        self.assertEqual(res_fb["method"], "systemctl")
        self.assertEqual(runner.calls[-1], ["/usr/bin/systemctl", "poweroff"])

    def test_daemon_state_isolation_polkit_methods_and_client_no_fallback(self) -> None:
        import dbus

        state_dir = self.root / "sys_state"
        with mock.patch.dict(os.environ, {"STATE_DIRECTORY": str(state_dir)}):
            d_ctrl = _build_daemon_controller(use_system_state=True)
        self.assertEqual(d_ctrl.data_dir if hasattr(d_ctrl, "data_dir") else d_ctrl.firewall.data_dir, state_dir)
        self.assertEqual(d_ctrl.config_store.path, state_dir / "settings.json")

        rec_auth = _RecordingAuthorizer(decision=True)
        runner = _FakeToolRunner()
        ctrl = SuiteController(
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            incident_manager=IncidentManager(self.root / "incidents"),
            runner=runner,
            authorizer=rec_auth,
            data_dir=self.root / "data",
            clamav_db_dir=self.root / "clamdb",
        )
        ctrl.firewall.ufw_conf_path = self.root / "ufw.conf"
        ctrl.firewall.ufw_conf_path.write_text("ENABLED=no\n", encoding="utf-8")

        with mock.patch("dbus.service.BusName"), mock.patch("dbus.service.Object.__init__", return_value=None):
            fw_srv = ModuleDBusService(
                controller=ctrl,
                module_id="firewall",
                idle_exit_secs=0,
                bus=mock.MagicMock(),
            )
            am_srv = ModuleDBusService(
                controller=ctrl,
                module_id="antimalware",
                idle_exit_secs=0,
                bus=mock.MagicMock(),
            )

        with self.assertRaises(dbus.DBusException):
            fw_srv._exported.Enable('{"_preauthorized": true}', sender=":1.50")

        rec_auth.calls.clear()
        en_json = fw_srv._exported.Enable('{"apply_essential_rules": true}', sender=":1.50")
        en_data = json.loads(en_json)
        self.assertIn("module_id", en_data)
        self.assertEqual(len(rec_auth.calls), 1)
        self.assertEqual(rec_auth.calls[0][0], "org.mintsecurity.firewall.configure")

        # Adiciona regra via service e revoga pelo método D-Bus RevokeRule
        rule = ctrl.firewall.add_rule(direction="in", target="22/tcp", scope="SSH teste", preauthorized=True)
        rec_auth.calls.clear()
        rev_res = json.loads(fw_srv._exported.RevokeRule(rule.rule_id, sender=":1.50"))
        self.assertTrue(rev_res["ok"])
        self.assertEqual(rec_auth.calls, [("org.mintsecurity.firewall.configure", ":1.50", 1000)])

        # Antimalware UpdateSignatures autoriza uma única vez e roda freshclam
        rec_auth.calls.clear()
        upd_res = json.loads(am_srv._exported.UpdateSignatures(sender=":1.50"))
        self.assertTrue(upd_res["ok"])
        self.assertEqual(rec_auth.calls, [("org.mintsecurity.antimalware.update-db", ":1.50", 1000)])
        self.assertTrue(any(Path(c[0]).name == "freshclam" for c in runner.calls))

        # AccessDenied preserva DBus name
        denied_auth = _RecordingAuthorizer(decision=False)
        ctrl_denied = SuiteController(
            config_store=ConfigStore(self.root / "d_settings.json"),
            pending_store=PendingStore(self.root / "d_pending.json"),
            history_store=HistoryStore(self.root / "d_history.db"),
            incident_manager=IncidentManager(self.root / "d_incidents"),
            runner=runner,
            authorizer=denied_auth,
            data_dir=self.root / "d_data",
            clamav_db_dir=self.root / "clamdb",
        )
        with mock.patch("dbus.service.BusName"), mock.patch("dbus.service.Object.__init__", return_value=None):
            fw_denied = ModuleDBusService(
                controller=ctrl_denied,
                module_id="firewall",
                idle_exit_secs=0,
                bus=mock.MagicMock(),
            )
        with self.assertRaises(dbus.DBusException) as ctx:
            fw_denied._exported.Enable('{"apply_essential_rules": true}', sender=":1.50")
        self.assertEqual(ctx.exception.get_dbus_name(), "org.freedesktop.DBus.Error.AccessDenied")

        # Client não faz fallback em NoReply nem em processo não-root com SubprocessRunner
        noreply_exc = dbus.DBusException("timed out", name="org.freedesktop.DBus.Error.NoReply")
        self.assertFalse(_is_bus_unavailable_error(noreply_exc))

        live_runner_svc = mock.MagicMock()
        live_runner_svc.runner = SubprocessRunner()
        client = SystemModuleClient(self.manifests, bus=mock.MagicMock())
        svc_unknown = dbus.DBusException("no owner", name="org.freedesktop.DBus.Error.ServiceUnknown")
        with mock.patch.dict(os.environ, {"MINTSEC_USE_SYSTEM_BUS": "1"}), mock.patch(
            "os.geteuid", return_value=1000
        ):
            with mock.patch.object(client, "call_dbus", side_effect=noreply_exc):
                with self.assertRaises(dbus.DBusException):
                    client.enable("firewall", live_runner_svc)
            with mock.patch.object(client, "call_dbus", side_effect=svc_unknown):
                with self.assertRaises(RuntimeError):
                    client.enable("firewall", live_runner_svc)
                with self.assertRaises(RuntimeError):
                    client.revoke_firewall_rule("suite-1", live_runner_svc)
                with self.assertRaises(RuntimeError):
                    client.update_antimalware_signatures(live_runner_svc)

    def test_controller_dbus_routing_and_firewall_overlay(self) -> None:
        ctrl = SuiteController(
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            incident_manager=IncidentManager(self.root / "incidents"),
            runner=SubprocessRunner(),
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
            clamav_db_dir=self.root / "clamdb",
        )
        ctrl.config_store.update(firewall_outbound_mode="block_per_app")

        dbus_fw_active = {
            "module_id": "firewall",
            "display_name": "Firewall",
            "state": "ativo",
            "installed_version": "0.36.2",
            "package_origin": "Ubuntu",
            "mode_summary": "Firewall de entrada ativo · Saída em monitoramento",
            "last_confirmed_at": "2026-11-22T10:00:00-03:00",
            "evidence": "Consultado diretamente via ufw status.",
            "phase": "mvp",
            "experimental": False,
            "details": {"ufw_active": True, "opensnitch_installed": True, "rules": []},
        }
        with mock.patch.dict(os.environ, {"MINTSEC_USE_SYSTEM_BUS": "1"}):
            with mock.patch.object(ctrl.dbus_client, "query_status", return_value=dbus_fw_active):
                st = ctrl.get_module_status("firewall")
                self.assertEqual(st.state, ModuleState.ATIVO)
                self.assertEqual(st.details["outbound_mode"], "block_per_app")
                self.assertIn("bloqueio por aplicativo", st.mode_summary)

            with mock.patch.object(ctrl.dbus_client, "enable", return_value=dbus_fw_active) as en_mock:
                st_en = ctrl.enable_module("firewall", apply_essential_rules=True)
                self.assertEqual(st_en.state, ModuleState.ATIVO)
                en_mock.assert_called_once()
                self.assertTrue(ctrl.config_store.load().enabled_modules.get("firewall"))

            with mock.patch.object(
                ctrl.dbus_client,
                "revoke_firewall_rule",
                return_value={"ok": True, "status": dbus_fw_active},
            ) as rev_mock:
                self.assertTrue(ctrl.revoke_firewall_rule("suite-abc"))
                rev_mock.assert_called_once()

            with mock.patch.object(
                ctrl.dbus_client,
                "update_antimalware_signatures",
                return_value={"ok": True, "stdout": "Updated", "stderr": "", "returncode": 0},
            ) as upd_mock:
                upd = ctrl.update_antimalware_signatures()
                self.assertTrue(upd["ok"])
                upd_mock.assert_called_once()

    def test_gtk_xephyr_pause_resume_live_post_action_and_settings_default(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        disp_num = next(
            (
                d
                for d in range(112, 145)
                if not Path(f"/tmp/.X{d}-lock").exists() and not Path(f"/tmp/.X11-unix/X{d}").exists()
            ),
            144,
        )
        disp = f":{disp_num}"
        xephyr = subprocess.Popen(
            ["Xephyr", disp, "-screen", "1280x800", "-ac", "-noreset"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            sock = Path(f"/tmp/.X11-unix/X{disp_num}")
            for _ in range(50):
                if sock.exists():
                    break
                time.sleep(0.1)
            self.assertTrue(sock.exists(), f"Xephyr failed on {disp}")

            script = """
import tempfile, threading, time
from pathlib import Path
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk
Gtk.init([])

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController
from mintsec_ui.window import SuiteWindow

class _GateRunner:
    def __init__(self, target):
        self.target = target
        self.scan_entered = threading.Event()
        self.scan_release = threading.Event()

    def which(self, b):
        return f"/usr/bin/{b}" if b in ("clamscan", "ufw") else None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None, pause_event=None):
        cmd = [str(a) for a in argv]
        if cmd[0] == "dpkg-query":
            pkg = cmd[-1]
            if pkg in ("clamav", "clamav-freshclam", "ufw"):
                return CommandResult(tuple(cmd), 0, "install ok installed\\t1.0.0\\n", "")
            return CommandResult(tuple(cmd), 1, "", "not installed")
        if Path(cmd[0]).name == "clamscan":
            self.scan_entered.set()
            while not self.scan_release.is_set():
                if cancel_event is not None and cancel_event.is_set():
                    return CommandResult(tuple(cmd), -1, "", "", cancelled=True)
                time.sleep(0.02)
            while pause_event is not None and pause_event.is_set():
                if cancel_event is not None and cancel_event.is_set():
                    return CommandResult(tuple(cmd), -1, "", "", cancelled=True)
                time.sleep(0.02)
            line = f"{self.target}: OK"
            if on_line:
                on_line(line)
            return CommandResult(tuple(cmd), 0, line + "\\n", "")
        if Path(cmd[0]).name == "ufw":
            return CommandResult(tuple(cmd), 0, "Status: inactive\\n", "")
        return CommandResult(tuple(cmd), 0, "", "")

def flush(ms=60):
    end = time.monotonic() + (ms / 1000.0)
    ctx = GLib.MainContext.default()
    while time.monotonic() < end:
        while ctx.pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.01)

with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    scan_dir = base / "scan"
    scan_dir.mkdir()
    sample = scan_dir / "doc.txt"
    sample.write_text("clean", encoding="utf-8")

    power_calls = []
    runner = _GateRunner(sample)
    ctrl = SuiteController(
        config_store=ConfigStore(base / "settings.json"),
        pending_store=PendingStore(base / "pending.json"),
        history_store=HistoryStore(base / "history.db"),
        incident_manager=IncidentManager(base / "incidents"),
        runner=runner,
        authorizer=CallerAuthorizer(test_decision=True),
        data_dir=base / "data",
        clamav_db_dir=base / "clamdb",
        post_scan_executor=lambda act: power_calls.append(act) or {"ok": True, "action": act, "method": "mock"},
    )
    ctrl.config_store.update(first_run_completed=True, language="en")
    win = SuiteWindow(None, controller=ctrl, initial_width=1280, initial_height=760)
    flush(100)

    # 1. Settings default post-scan action syncs ScansPage immediately
    win.navigate_to("settings", tab="alerts")
    flush(50)
    assert win.settings_page.post_scan_action_combo.get_active_id() == "none"
    win.settings_page.post_scan_action_combo.set_active_id("suspend")
    flush(50)
    assert ctrl.config_store.load().default_scan_post_action == "suspend"
    assert win.scans_page.get_selected_post_action() == "suspend"
    win.settings_page.post_scan_action_combo.set_active_id("none")
    flush(40)
    assert win.scans_page.get_selected_post_action() == "none"

    # 2. Scan em andamento: pausar, retomar, alterar combo pós-scan ao vivo para shutdown e executar imediato
    win.navigate_to("scans", tab="scan")
    flush(40)
    win.scans_page.post_action_countdown_secs = 0
    win.scans_page.start_scan("custom", custom_paths=[str(scan_dir)])
    assert runner.scan_entered.wait(timeout=3.0)
    flush(60)
    assert win.scans_page.btn_pause.get_visible()
    win.scans_page.btn_pause.clicked()
    flush(80)
    assert win.scans_page._paused is True
    assert "paused" in win.scans_page.progress_phase_lbl.get_text().lower()

    # Altera ação pós-scan durante o scan em andamento -> aplica imediatamente
    win.scans_page.post_action_combo.set_active_id("shutdown")
    flush(40)
    assert win.scans_page.post_action_hint_lbl.get_visible()

    win.scans_page.btn_pause.clicked()
    flush(60)
    assert win.scans_page._paused is False
    runner.scan_release.set()
    for _ in range(30):
        flush(30)
        if not win.scans_page._scanning:
            break
    assert not win.scans_page._scanning
    assert power_calls == ["shutdown"], f"Expected shutdown after finish, got {power_calls}"

    # 3. Scan cancelado não dispara ação pós-scan
    power_calls.clear()
    runner.scan_entered.clear()
    runner.scan_release.clear()
    win.scans_page.post_action_combo.set_active_id("suspend")
    win.scans_page.start_scan("custom", custom_paths=[str(scan_dir)])
    assert runner.scan_entered.wait(timeout=3.0)
    flush(40)
    win.scans_page.btn_cancel.clicked()
    for _ in range(30):
        flush(30)
        if not win.scans_page._scanning:
            break
    assert power_calls == [], f"Cancelled scan must not trigger power action: {power_calls}"

    # 4. Contagem regressiva cancelável
    runner.scan_entered.clear()
    runner.scan_release.clear()
    win.scans_page.post_action_countdown_secs = 5
    win.scans_page.post_action_combo.set_active_id("suspend")
    win.scans_page.start_scan("custom", custom_paths=[str(scan_dir)])
    assert runner.scan_entered.wait(timeout=3.0)
    runner.scan_release.set()
    for _ in range(30):
        flush(30)
        if not win.scans_page._scanning:
            break
    flush(50)
    assert win.scans_page.post_action_revealer.get_reveal_child()
    win.scans_page.btn_post_cancel.clicked()
    flush(40)
    assert not win.scans_page.post_action_revealer.get_reveal_child()
    assert power_calls == []

    win.destroy()
    flush(40)
print("XEPHYR_SCAN_CONTROLS_OK")
"""
            env = dict(os.environ)
            env["DISPLAY"] = disp
            env["MINTSEC_DISABLE_TRAY"] = "1"
            env["PYTHONPATH"] = str(repo_root / "src")
            res = subprocess.run(
                [sys.executable, "-c", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=30.0,
                check=False,
            )
            self.assertEqual(res.returncode, 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
            self.assertIn("XEPHYR_SCAN_CONTROLS_OK", res.stdout)
        finally:
            xephyr.terminate()
            try:
                xephyr.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xephyr.kill()


if __name__ == "__main__":
    unittest.main()
