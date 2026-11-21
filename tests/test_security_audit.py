"""Testes de auditoria de segurança, validação de entradas e regressão de UI."""

from __future__ import annotations

import importlib.machinery
import importlib.util
import json
import os
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from mintsec.auth import AuthorizationError, CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import ModuleState, load_manifests
from mintsec.dbus_client import SystemModuleClient
from mintsec.firewall_trust import verify_root_owned_path_chain
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.opensnitch_grpc import _decode_varint, decode_wire_envelope
from mintsec.packaging import PackageInspector
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.antimalware import AntimalwareService
from mintsec.services.browsing import BrowsingService
from mintsec.services.catalog import SuiteController
from mintsec.services.daemon import ModuleDBusService, _authorize_dbus_call
from mintsec.services.firewall import FirewallService
from mintsec.services.recovery import RecoveryService


class _FakeAuditRunner:
    def __init__(self) -> None:
        self.calls: list[list[str]] = []

    def which(self, binary: str) -> str | None:
        if binary in ("clamscan", "ufw", "restic", "timeshift", "gpgv"):
            return f"/usr/bin/{binary}"
        return None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        self.calls.append(list(argv))
        if argv[0] == "dpkg-query":
            return CommandResult(tuple(argv), 0, "install ok installed\t1.0.0\n", "")
        if argv[0] == "apt-cache":
            return CommandResult(
                tuple(argv),
                0,
                " *** 1.0.0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n",
                "",
            )
        if argv[0].endswith("ufw") and argv[1:3] == ["status", "numbered"]:
            return CommandResult(tuple(argv), 0, "Status: inactive\n", "")
        if argv[0].endswith("restic") and "snapshots" in argv:
            return CommandResult(tuple(argv), 0, "[]", "")
        return CommandResult(tuple(argv), 0, "", "")


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


class SecurityAuditTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="mintsec-audit-")
        self.root = Path(self.tmp.name)
        self.manifests = load_manifests()
        self.runner = _FakeAuditRunner()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_controller(self, authorizer: CallerAuthorizer | None = None) -> SuiteController:
        return SuiteController(
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            incident_manager=IncidentManager(self.root / "incidents"),
            runner=self.runner,
            authorizer=authorizer or _RecordingAuthorizer(),
            data_dir=self.root / "data",
            clamav_db_dir=self.root / "clamdb",
        )

    def test_daemon_polkit_sender_forwarding_allowlist_and_reset_action(self) -> None:
        import dbus

        prod_auth = CallerAuthorizer(test_decision=None)
        with self.assertRaises(AuthorizationError):
            _authorize_dbus_call(prod_auth, mock.MagicMock(), "org.mintsecurity.suite.query", None)

        rec_auth = _RecordingAuthorizer(decision=True)
        uid = _authorize_dbus_call(rec_auth, mock.MagicMock(), "org.mintsecurity.suite.query", ":1.42")
        self.assertEqual(uid, 1000)
        self.assertEqual(rec_auth.calls[-1], ("org.mintsecurity.suite.query", ":1.42", 1000))

        ctrl = self._make_controller(rec_auth)
        with mock.patch("dbus.service.BusName"), mock.patch("dbus.service.Object.__init__", return_value=None):
            srv = ModuleDBusService(
                controller=ctrl,
                module_id="firewall",
                idle_exit_secs=0,
                bus=mock.MagicMock(),
            )

        with self.assertRaises(dbus.DBusException):
            srv._exported.Enable('{"unknown_key": 1}', sender=":1.42")

        res_json = srv._exported.Disable(True, sender=":1.42")
        res_data = json.loads(res_json)
        self.assertEqual(res_data["state"], ModuleState.DESATIVADO.value)
        self.assertTrue(any(act == "org.mintsecurity.firewall.reset" for act, _, _ in rec_auth.calls))

    def test_dbus_client_does_not_fallback_on_permission_denial(self) -> None:
        class FakeAccessDenied(Exception):
            def get_dbus_name(self) -> str:
                return "org.freedesktop.DBus.Error.AccessDenied"

        class FakeServiceUnknown(Exception):
            def get_dbus_name(self) -> str:
                return "org.freedesktop.DBus.Error.ServiceUnknown"

        local_svc = mock.MagicMock()
        local_svc.enable.return_value.to_dict.return_value = {"state": "ativo"}
        local_svc.query_status.return_value.to_dict.return_value = {"state": "desativado"}

        client = SystemModuleClient(self.manifests, bus=mock.MagicMock())
        with mock.patch.dict(os.environ, {"MINTSEC_USE_SYSTEM_BUS": "1"}):
            with mock.patch.object(client, "call_dbus", side_effect=FakeAccessDenied("Polkit denied")):
                with self.assertRaises(FakeAccessDenied):
                    client.enable("firewall", local_svc)
            local_svc.enable.assert_not_called()

            with mock.patch.object(client, "call_dbus", side_effect=AuthorizationError("Negado")):
                with self.assertRaises(AuthorizationError):
                    client.disable("firewall", local_svc, revert_suite_changes=True)
            local_svc.disable.assert_not_called()

            with mock.patch.object(client, "call_dbus", side_effect=FakeServiceUnknown("Sem serviço")):
                out = client.query_status("firewall", local_svc)
            self.assertEqual(out["state"], "desativado")
            local_svc.query_status.assert_called_once()

    def test_antimalware_hardening_validation_symlinks_and_quarantine(self) -> None:
        am = AntimalwareService(
            manifest=self.manifests["antimalware"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            package_inspector=PackageInspector(self.runner),
            runner=self.runner,
            authorizer=_RecordingAuthorizer(),
            data_dir=self.root / "data",
            clamav_db_dir=self.root / "clamdb",
            systemd_user_dir=self.root / "systemd_user",
        )

        with self.assertRaises(ValueError):
            am.save_schedule(schedule_id="../../etc/evil", scope="quick", frequency="weekly")
        with self.assertRaises(ValueError):
            am.save_schedule(schedule_id="ok1", scope="quick\nExecStart=/bin/sh", frequency="weekly")
        with self.assertRaises(ValueError):
            am.configure(exclusions=["/tmp/ok\nVirusEvent=/bin/sh"])
        with self.assertRaises(ValueError):
            am.configure(limits={"max_filesize": "100M --exec"})

        sample = self.root / "doc.txt"
        sample.write_bytes(b"limpo")
        am.run_scan(scope="custom", paths=["--infected", str(sample)])
        clam_calls = [c for c in self.runner.calls if c and c[0].endswith("clamscan")]
        self.assertTrue(clam_calls)
        argv = clam_calls[-1]
        self.assertIn("--", argv)
        self.assertLess(argv.index("--"), argv.index("--infected"))

        link_target = self.root / "symlink_sample.txt"
        link_target.symlink_to(sample)
        with self.assertRaises(PermissionError):
            am.quarantine_file(link_target, detection_name="Test", confirmed=True)

        q_item = am.quarantine_file(sample, detection_name="Test", confirmed=True)
        outside = self.root / "outside_secret.txt"
        outside.write_bytes(b"nao-tocar")
        tampered = json.loads(am.quarantine_index_path.read_text(encoding="utf-8"))
        tampered["items"][0]["quarantine_file"] = str(outside)
        am.quarantine_index_path.write_text(json.dumps(tampered), encoding="utf-8")

        with self.assertRaises(PermissionError):
            am.restore_quarantined(q_item.item_id)
        with self.assertRaises(PermissionError):
            am.delete_quarantined(q_item.item_id, confirmed=True)
        self.assertTrue(outside.exists())

        # Restaura payload válido e confere permissão restritiva 0600
        sample2 = self.root / "doc2.txt"
        sample2.write_bytes(b"limpo2")
        am.quarantine_index_path.write_text('{"items":[]}', encoding="utf-8")
        q2 = am.quarantine_file(sample2, detection_name="Test2", confirmed=True)
        restored = am.restore_quarantined(q2.item_id, destination_path=self.root / "restaurado.txt")
        self.assertEqual(stat.S_IMODE(restored.stat().st_mode), 0o600)

    def test_browsing_firewall_and_recovery_input_validation(self) -> None:
        browsing = BrowsingService(
            manifest=self.manifests["browsing"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            package_inspector=PackageInspector(self.runner),
            runner=self.runner,
            data_dir=self.root / "data",
        )
        with self.assertRaises(ValueError):
            browsing.add_local_exception("evil.com\naddress=/google.com/127.0.0.1")
        with self.assertRaises(ValueError):
            browsing.authorize_external_resolver("example.com", "1.1.1.1\nserver=8.8.8.8")

        rec_auth = _RecordingAuthorizer()
        fw = FirewallService(
            manifest=self.manifests["firewall"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            package_inspector=PackageInspector(self.runner),
            runner=self.runner,
            authorizer=rec_auth,
            data_dir=self.root / "data",
            ufw_conf_path=self.root / "ufw.conf",
        )
        with self.assertRaises(ValueError):
            fw.add_rule(direction="inout", target="80/tcp")
        with self.assertRaises(ValueError):
            fw.add_rule(direction="in", target="80/tcp", action="DROP_EVIL")
        with self.assertRaises(ValueError):
            fw.add_rule(direction="in", target="--reset")
        fw.disable(revert_suite_changes=True)
        self.assertEqual(rec_auth.calls[-1][0], "org.mintsecurity.firewall.reset")

        rec = RecoveryService(
            manifest=self.manifests["recovery"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            incident_manager=IncidentManager(self.root / "incidents"),
            package_inspector=PackageInspector(self.runner),
            runner=self.runner,
            authorizer=rec_auth,
            data_dir=self.root / "data",
        )
        with self.assertRaises(ValueError):
            rec.configure(repo_path="-oProxyCommand=evil")
        rec.configure(repo_path=str(self.root / "repo"))
        rec.backup_now(password="segredo")
        restic_bk = [c for c in self.runner.calls if c and c[0].endswith("restic") and "backup" in c]
        self.assertIn("--", restic_bk[-1])
        with self.assertRaises(ValueError):
            rec.restore_files(snapshot_id="../../evil", paths=["/tmp/a"], destination_dir=self.root / "out", password="s")
        with self.assertRaises(ValueError):
            rec.restore_files(snapshot_id="abcdef12", paths=["/home/user/../../etc/passwd"], password="s")

    def test_incident_symlinks_opensnitch_bounds_trust_chain_and_bank_mode(self) -> None:
        sym_root = self.root / "sym_inc_root"
        real_root = self.root / "real_inc_root"
        real_root.mkdir()
        sym_root.symlink_to(real_root)
        with self.assertRaises(PermissionError):
            IncidentManager(sym_root)

        swap_root = self.root / "swap_inc_root"
        mgr_swap = IncidentManager(swap_root)
        swap_root.symlink_to(real_root)
        with self.assertRaises(PermissionError):
            mgr_swap.incident_dir("inc-1")

        mgr = IncidentManager(real_root)
        orig = self.root / "orig.txt"
        orig.write_bytes(b"a")
        src_sym = self.root / "src_sym.txt"
        src_sym.symlink_to(orig)
        tgt_sym = self.root / "tgt_sym.txt"
        tgt_sym.symlink_to(orig)
        with self.assertRaises(PermissionError):
            mgr.prepare_and_overwrite(target_path=tgt_sym, restored_source_path=orig, incident_id="inc-s")
        with self.assertRaises(PermissionError):
            mgr.prepare_and_overwrite(target_path=orig, restored_source_path=src_sym, incident_id="inc-s")

        # cleanup_incident não deve seguir symlink nem alterar permissão de arquivo externo
        outside_file = self.root / "external.txt"
        outside_file.write_bytes(b"keep-mode")
        os.chmod(outside_file, 0o644)
        inc_d = mgr.incident_dir("inc-clean")
        (inc_d / "evil_link").symlink_to(outside_file)
        mgr.cleanup_incident("inc-clean", confirmed=True)
        self.assertEqual(stat.S_IMODE(outside_file.stat().st_mode), 0o644)

        with self.assertRaises(ValueError):
            _decode_varint(b"\x80" * 11 + b"\x01", 0)
        with self.assertRaises(ValueError):
            decode_wire_envelope(b"\x0a\x64abc")

        # Symlink para executável dentro de diretório pai gravável por terceiros deve falhar
        chain_root = self.root / "chain"
        safe_dir = chain_root / "safe_dir"
        bad_parent = chain_root / "bad_parent"
        safe_dir.mkdir(parents=True)
        bad_parent.mkdir(parents=True)
        real_bin = bad_parent / "app"
        real_bin.write_bytes(b"\x7fELF" + b"\x00" * 60)
        os.chmod(real_bin, 0o755)
        os.chmod(chain_root, 0o755)
        os.chmod(safe_dir, 0o755)
        os.chmod(bad_parent, 0o777)
        link_bin = safe_dir / "app"
        link_bin.symlink_to(real_bin)
        res = verify_root_owned_path_chain(
            link_bin,
            allowed_uids={os.geteuid()},
            stop_at_prefix=chain_root,
        )
        self.assertFalse(res.safe)

        bank_path = Path(__file__).resolve().parents[1] / "bin" / "mint-security-bank-mode"
        loader = importlib.machinery.SourceFileLoader("mint_security_bank_mode", str(bank_path))
        spec = importlib.util.spec_from_loader("mint_security_bank_mode", loader)
        assert spec is not None
        bank_mod = importlib.util.module_from_spec(spec)
        loader.exec_module(bank_mod)
        with self.assertRaises(ValueError):
            bank_mod.validate_bank_launch("mintsec-bank", 99, ["/usr/bin/firefox"], check_exists=False)
        with self.assertRaises(PermissionError):
            bank_mod.validate_bank_launch("mintsec-bank", 8, ["/tmp/evil-browser"], check_exists=False)

    def test_protections_filter_click_has_no_recursion_and_refreshes_once(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        disp = next(
            (
                f":{d}"
                for d in range(88, 120)
                if not Path(f"/tmp/.X{d}-lock").exists() and not Path(f"/tmp/.X11-unix/X{d}").exists()
            ),
            ":94",
        )
        xephyr = subprocess.Popen(
            ["Xephyr", disp, "-screen", "1024x768", "-ac", "-nolisten", "tcp", "-noreset"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            time.sleep(0.6)
            env = dict(os.environ)
            env["DISPLAY"] = disp
            env["PYTHONPATH"] = str(repo_root / "src")
            env["XDG_CONFIG_HOME"] = str(self.root / "xdg_cfg")
            env["XDG_DATA_HOME"] = str(self.root / "xdg_data")
            script = """
import tempfile
from pathlib import Path
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import Gtk
from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController
from mintsec_ui.app import SecuritySuiteApp

class _Runner:
    def which(self, b): return None
    def run(self, argv, **_kw): return CommandResult(tuple(argv), 1, "", "")

with tempfile.TemporaryDirectory() as td:
    root = Path(td)
    ctrl = SuiteController(
        config_store=ConfigStore(root / "settings.json"),
        pending_store=PendingStore(root / "pending.json"),
        history_store=HistoryStore(root / "history.db"),
        incident_manager=IncidentManager(root / "incidents"),
        runner=_Runner(),
        authorizer=CallerAuthorizer(test_decision=True),
        data_dir=root / "data",
    )
    ctrl.config_store.update(first_run_completed=True)
    app = SecuritySuiteApp(controller=ctrl)
    app.register()
    app.activate()
    win = app.window
    win.navigate_to("protections")
    calls = [0]
    orig = win.protections_page.refresh
    def _w(*a, **kw):
        calls[0] += 1
        return orig(*a, **kw)
    win.protections_page.refresh = _w
    win.protections_page._filter_buttons["installed"].clicked()
    while Gtk.events_pending():
        Gtk.main_iteration_do(False)
    assert calls[0] == 1, f"expected 1 refresh call, got {calls[0]}"
    win.destroy()
    while Gtk.events_pending():
        Gtk.main_iteration_do(False)
print("FILTER_CLICK_OK")
"""
            res = subprocess.run(
                [sys.executable, "-c", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=15.0,
                check=False,
            )
            self.assertEqual(res.returncode, 0, msg=res.stderr or res.stdout)
            self.assertIn("FILTER_CLICK_OK", res.stdout)
        finally:
            xephyr.terminate()
            try:
                xephyr.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xephyr.kill()


if __name__ == "__main__":
    unittest.main()
