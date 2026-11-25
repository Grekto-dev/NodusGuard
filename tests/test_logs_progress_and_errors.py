"""Testes para barra global de atividade/progresso, aba Logs em Configurações e diagnóstico de erros."""

from __future__ import annotations

import errno
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mintsec.app_log import AppLogStore
from mintsec.auth import AuthorizationError, CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.formatting import build_error_report
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController


class _FakeDBusErr(Exception):
    def __init__(self, msg: str, dbus_name: str) -> None:
        super().__init__(msg)
        self._dbus_msg = msg
        self._dbus_name = dbus_name

    def get_dbus_message(self) -> str:
        return self._dbus_msg

    def get_dbus_name(self) -> str:
        return self._dbus_name


class _DummyRunner:
    def which(self, _b: str) -> str | None:
        return None

    def run(self, argv, **kw) -> CommandResult:
        return CommandResult(tuple(argv), 0, "", "")


class LogsProgressAndErrorsTests(unittest.TestCase):
    def test_app_log_store_record_filter_symlink_and_clear(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mintsec-applog-") as tmp:
            root = Path(tmp)
            log_path = root / "app.log.jsonl"
            store = AppLogStore(log_path, max_entries=60)

            store.record("INFO", "refresh", "Checking protections", source="controller")
            store.record("WARNING", "scans", "Scan cancelled by user", source="clamscan")
            store.record("ERROR", "firewall", "UFW rule rejected", details="invalid port 99999", source="ufw")
            self.assertEqual(store.count(), 3)

            all_items = store.list_entries()
            self.assertEqual(all_items[0].level, "ERROR")
            self.assertEqual(len(store.list_entries(level="WARNING")), 1)
            self.assertEqual(len(store.list_entries(query="99999")), 1)

            # Apara além de max_entries mantendo os mais recentes
            for idx in range(70):
                store.record("INFO", "bulk", f"Item {idx}")
            self.assertEqual(store.count(), 60)

            removed = store.clear()
            self.assertEqual(removed, 60)
            self.assertEqual(store.count(), 0)

            # Rejeita link simbólico no caminho do log
            sym_path = root / "sym.log.jsonl"
            sym_path.symlink_to(root / "target.txt")
            sym_store = AppLogStore(sym_path)
            with self.assertRaises(PermissionError):
                sym_store.record("INFO", "test", "blocked")

    def test_error_reports_classify_causes_and_suggestions_bilingual(self) -> None:
        rep_auth = build_error_report(
            AuthorizationError("Polkit denied org.mintsecurity.firewall.enable"),
            operation="Enable Firewall",
            lang="pt_BR",
        )
        self.assertEqual(rep_auth.error_code, "auth_denied")
        self.assertIn("Polkit", rep_auth.cause)
        self.assertIn("Enable Firewall", rep_auth.technical_details)

        rep_dbus = build_error_report(
            _FakeDBusErr(
                "The name org.mintsecurity.Firewall was not provided",
                "org.freedesktop.DBus.Error.ServiceUnknown",
            ),
            operation="Allow KDE Connect",
            lang="en",
        )
        self.assertEqual(rep_dbus.error_code, "dbus_unavailable")
        self.assertIn("D-Bus", rep_dbus.cause)

        rep_perm = build_error_report(PermissionError(errno.EPERM, "Você precisa ser superusuário"), lang="pt_BR")
        self.assertEqual(rep_perm.error_code, "permission_denied")

        rep_lock = build_error_report("ERROR: /var/lib/clamav/freshclam.dat is locked by another process", lang="en")
        self.assertEqual(rep_lock.error_code, "network_or_freshclam")

        rep_timeout = build_error_report(TimeoutError("freshclam timed out"), lang="en")
        self.assertEqual(rep_timeout.error_code, "timeout")

        rep_space = build_error_report(OSError(errno.ENOSPC, "No space left on device"), lang="pt_BR")
        self.assertEqual(rep_space.error_code, "storage_error")

        rep_fw = build_error_report(ValueError("Porta UFW inválida: 70000"), lang="en")
        self.assertEqual(rep_fw.error_code, "validation_or_engine")

        rep_missing = build_error_report(FileNotFoundError("clamscan not found"), lang="pt_BR")
        self.assertEqual(rep_missing.error_code, "not_found")

    def test_controller_progress_callbacks_and_logging(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mintsec-ctrl-prog-") as tmp:
            base = Path(tmp)
            ctrl = SuiteController(
                config_store=ConfigStore(base / "settings.json"),
                pending_store=PendingStore(base / "pending.json"),
                history_store=HistoryStore(base / "history.db"),
                incident_manager=IncidentManager(base / "incidents"),
                runner=_DummyRunner(),
                authorizer=CallerAuthorizer(test_decision=True),
                data_dir=base / "data",
                clamav_db_dir=base / "clamdb",
            )
            steps: list[tuple[int, int, str]] = []
            statuses = ctrl.all_statuses(on_progress=lambda d, t, m: steps.append((d, t, m)))
            self.assertEqual(len(steps), len(statuses))
            self.assertEqual(steps[-1][0], steps[-1][1])

            ctrl.pause_protection(mode="timed", minutes=5)
            ctrl.resume_protection()
            logs = ctrl.list_app_logs()
            self.assertGreaterEqual(len(logs), 2)

    def test_xephyr_activity_bar_logs_tab_clear_confirm_and_error_dialog(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        disp_num = next(
            (
                d
                for d in range(95, 118)
                if not Path(f"/tmp/.X{d}-lock").exists() and not Path(f"/tmp/.X11-unix/X{d}").exists()
            ),
            99,
        )
        disp = f":{disp_num}"
        xephyr = subprocess.Popen(
            ["Xephyr", disp, "-screen", "1400x900", "-ac", "-noreset"],
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
import tempfile, time
from pathlib import Path
from unittest import mock
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk
Gtk.init([])

from mintsec.auth import AuthorizationError, CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController
from mintsec_ui.dialogs.error_dialog import build_error_dialog
from mintsec_ui.window import SuiteWindow

class _DummyRunner:
    def which(self, _b):
        return None
    def run(self, argv, **kw):
        return CommandResult(tuple(argv), 0, "", "")

def flush(ms=80):
    end = time.monotonic() + (ms / 1000.0)
    ctx = GLib.MainContext.default()
    while time.monotonic() < end:
        while ctx.pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.01)

with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    db_dir = base / "clamdb"
    db_dir.mkdir()
    (db_dir / "daily.cld").write_bytes(b"ok")
    ctrl = SuiteController(
        config_store=ConfigStore(base / "settings.json"),
        pending_store=PendingStore(base / "pending.json"),
        history_store=HistoryStore(base / "history.db"),
        incident_manager=IncidentManager(base / "incidents"),
        runner=_DummyRunner(),
        authorizer=CallerAuthorizer(test_decision=True),
        data_dir=base / "data",
        clamav_db_dir=db_dir,
    )
    ctrl.config_store.update(first_run_completed=True, language="en")
    ctrl.log_event("INFO", "startup", "Suite initialized cleanly", source="app")
    ctrl.log_event("ERROR", "firewall", "UFW failure test", details="Exit code 2", source="ufw")

    win = SuiteWindow(None, controller=ctrl, initial_width=1200, initial_height=740)
    flush(100)

    # 1. Barra de atividade fica oculta e sem timer quando ociosa
    assert not win.activity_bar.get_visible()
    assert win._activity_pulse_id is None

    # 2. Exibir tarefa determinística atualiza rótulo, % e oculta ao concluir
    tid = win.begin_activity("Checking protections…", category="refresh", fraction=0.25)
    flush(40)
    assert win.activity_bar.get_visible()
    assert win.activity_meta_lbl.get_text() == "25%"
    win.update_activity(tid, label="Checking firewall…", fraction=0.75)
    flush(30)
    assert win.activity_lbl.get_text() == "Checking firewall…"
    assert win.activity_meta_lbl.get_text() == "75%"
    win.end_activity(tid)
    flush(40)
    assert not win.activity_bar.get_visible()
    assert win._activity_pulse_id is None

    # 3. Aba Logs em Configurações: exibe, filtra e exige confirmação antes de limpar
    win.navigate_to("settings", tab="logs")
    flush(60)
    sp = win.settings_page
    buf = sp.logs_text_view.get_buffer()
    text_all = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)
    assert "UFW failure test" in text_all, text_all
    assert "Suite initialized cleanly" in text_all, text_all

    sp.logs_level_combo.set_active_id("ERROR")
    flush(40)
    text_err = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)
    assert "UFW failure test" in text_err
    assert "Suite initialized cleanly" not in text_err

    sp.logs_level_combo.set_active_id("all")
    sp.logs_search_entry.set_text("Exit code 2")
    flush(40)
    text_q = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)
    assert "UFW failure test" in text_q
    sp.logs_search_entry.set_text("")
    flush(30)

    # Cancelar confirmação preserva logs
    with mock.patch("mintsec_ui.pages.settings.ask_action_confirmation", return_value=False) as m_conf:
        sp.clear_logs_btn.clicked()
        flush(30)
        m_conf.assert_called_once()
    assert ctrl.app_log.count() >= 2

    # Confirmar limpeza apaga logs e desabilita botão limpar
    with mock.patch("mintsec_ui.pages.settings.ask_action_confirmation", return_value=True) as m_conf2:
        sp.clear_logs_btn.clicked()
        flush(40)
        m_conf2.assert_called_once()
    assert ctrl.app_log.count() == 0
    assert not sp.clear_logs_btn.get_sensitive()

    # 4. Diálogo robusto de erro possui diagnóstico estruturado e botão único Close (+ Open Logs)
    dlg, rep = build_error_dialog(
        win,
        AuthorizationError("Not authorized to run freshclam"),
        operation="Update virus definitions",
        source="FreshClam",
        open_logs_cb=lambda: None,
    )
    flush(30)
    assert rep.error_code == "auth_denied"
    assert "Update virus definitions" in rep.technical_details
    dlg.destroy()

    win.destroy()
    flush(40)

print("XEPHYR_LOGS_PROGRESS_ERRORS_OK")
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
            self.assertIn("XEPHYR_LOGS_PROGRESS_ERRORS_OK", res.stdout)
        finally:
            xephyr.terminate()
            try:
                xephyr.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xephyr.kill()


if __name__ == "__main__":
    unittest.main()
