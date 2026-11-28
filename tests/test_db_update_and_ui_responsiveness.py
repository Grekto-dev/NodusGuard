"""Testes para atualização de definições ClamAV, conexões D-Bus privadas e responsividade da UI."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import types
import unittest
from datetime import datetime, timedelta
from pathlib import Path

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import ModuleState, load_manifests
from mintsec.dbus_client import SystemModuleClient
from mintsec.history import HistoryStore
from mintsec.packaging import PackageInspector
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.antimalware import AntimalwareService


class _FakeFreshclamRunner:
    def __init__(self, *, stdout: str = "daily.cld database is up-to-date\n", returncode: int = 0) -> None:
        self.stdout = stdout
        self.returncode = returncode
        self.calls: list[list[str]] = []

    def which(self, binary: str) -> str | None:
        if binary in ("clamscan", "freshclam"):
            return f"/usr/bin/{binary}"
        return None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        self.calls.append(list(argv))
        if argv[0] == "dpkg-query":
            if argv[-1] in ("clamav", "clamav-freshclam"):
                return CommandResult(tuple(argv), 0, "install ok installed\t1.0.7+dfsg-1\n", "")
            return CommandResult(tuple(argv), 1, "", "not installed")
        if argv[0] == "apt-cache":
            return CommandResult(
                tuple(argv),
                0,
                " *** 1.0.7+dfsg-1 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n",
                "",
            )
        return CommandResult(tuple(argv), self.returncode, self.stdout, "")


class DbUpdateAndUiResponsivenessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="mintsec-db-upd-")
        self.root = Path(self.tmp.name)
        self.db_dir = self.root / "clamdb"
        self.db_dir.mkdir()
        self.manifests = load_manifests()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_service(self, runner: _FakeFreshclamRunner) -> AntimalwareService:
        return AntimalwareService(
            manifest=self.manifests["antimalware"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            package_inspector=PackageInspector(runner),
            runner=runner,
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
            clamav_db_dir=self.db_dir,
            systemd_user_dir=self.root / "systemd_user",
        )

    def test_signature_status_tracks_freshclam_check_when_daily_cld_mtime_unchanged(self) -> None:
        daily = self.db_dir / "daily.cld"
        daily.write_bytes(b"cld-bytes")
        old_ts = time.time() - (80.0 * 3600.0)
        os.utime(daily, (old_ts, old_ts))

        runner = _FakeFreshclamRunner()
        svc = self._make_service(runner)
        svc.enable()

        # Estado inicial: arquivo antigo e sem last_signature_update_at -> obsoleto e degradado
        sig_before = svc.signature_status()
        self.assertTrue(sig_before["available"])
        self.assertTrue(sig_before["stale"])
        self.assertGreaterEqual(sig_before["age_hours"], 79.0)
        self.assertIsNone(sig_before["last_checked_at"])
        self.assertEqual(svc.query_status().state, ModuleState.DEGRADADO)

        # FreshClam confirma "up-to-date" sem alterar mtime do daily.cld
        res = svc.update_signatures(preauthorized=True)
        self.assertTrue(res["ok"])
        sig_after = svc.signature_status()
        self.assertTrue(sig_after["available"])
        self.assertFalse(sig_after["stale"])
        self.assertLess(sig_after["age_hours"], 1.0)
        self.assertIsNotNone(sig_after["last_checked_at"])
        self.assertNotEqual(sig_after["db_file_updated_at"], sig_after["updated_at"])
        self.assertEqual(svc.query_status().state, ModuleState.ATIVO)

        # Fallback por freshclam.dat quando não há registro no estado
        state = svc._load_state()
        state.pop("last_signature_update_at", None)
        svc._save_state(state)
        fresh_dat = self.db_dir / "freshclam.dat"
        fresh_dat.write_bytes(b"dat")
        sig_dat = svc.signature_status()
        self.assertFalse(sig_dat["stale"])
        self.assertIsNotNone(sig_dat["last_checked_at"])

        # Timestamp futuro inválido no JSON (> now + 5min) não mascara idade real
        fresh_dat.unlink()
        future_iso = (datetime.now().astimezone() + timedelta(days=30)).isoformat(timespec="seconds")
        state["last_signature_update_at"] = future_iso
        svc._save_state(state)
        sig_future = svc.signature_status()
        self.assertTrue(sig_future["stale"])
        self.assertIsNone(sig_future["last_checked_at"])

        # Sem banco .cvd/.cld no disco, status permanece indisponível e degradado mesmo após freshclam 0
        daily.unlink()
        res_empty = svc.update_signatures(preauthorized=True)
        self.assertTrue(res_empty["ok"])
        self.assertFalse(res_empty["signatures"]["available"])
        self.assertFalse(svc.signature_status()["available"])
        self.assertEqual(svc.query_status().state, ModuleState.DEGRADADO)

    def test_dbus_client_uses_private_system_bus_and_closes_when_uninjected(self) -> None:
        created_buses: list[object] = []
        closed: list[bool] = []
        glib_inits: list[bool] = []

        class _FakeBus:
            def __init__(self, private: bool = False) -> None:
                self.private = private
                created_buses.append(self)

            def get_object(self, _bus_name: str, _obj_path: str) -> object:
                return object()

            def close(self) -> None:
                closed.append(True)

        class _FakeIface:
            def __init__(self, _obj: object, _name: str) -> None:
                pass

            def UpdateSignatures(self, *, timeout: float = 180.0) -> str:
                return json.dumps({"ok": True, "timeout": timeout})

        fake_dbus = types.ModuleType("dbus")
        fake_dbus.SystemBus = lambda private=False: _FakeBus(private=private)
        fake_dbus.Interface = _FakeIface
        fake_dbus_mainloop = types.ModuleType("dbus.mainloop")
        fake_dbus_glib = types.ModuleType("dbus.mainloop.glib")
        fake_dbus_glib.threads_init = lambda: glib_inits.append(True)
        fake_dbus_mainloop.glib = fake_dbus_glib
        fake_dbus.mainloop = fake_dbus_mainloop

        orig = {
            k: sys.modules.get(k)
            for k in ("dbus", "dbus.mainloop", "dbus.mainloop.glib")
        }
        sys.modules["dbus"] = fake_dbus
        sys.modules["dbus.mainloop"] = fake_dbus_mainloop
        sys.modules["dbus.mainloop.glib"] = fake_dbus_glib
        try:
            client = SystemModuleClient(self.manifests)
            out = client.call_dbus("antimalware", "UpdateSignatures", timeout=42.0)
            self.assertEqual(out, {"ok": True, "timeout": 42.0})
            self.assertEqual(len(created_buses), 1)
            self.assertTrue(getattr(created_buses[0], "private", False))
            self.assertEqual(closed, [True])
            self.assertEqual(glib_inits, [True])

            # Com barramento injetado em testes, não tenta criar nem fechar conexão privada
            injected = _FakeBus(private=False)
            client_inj = SystemModuleClient(self.manifests, bus=injected)
            out_inj = client_inj.call_dbus("antimalware", "UpdateSignatures", timeout=15.0)
            self.assertEqual(out_inj, {"ok": True, "timeout": 15.0})
            self.assertEqual(len(closed), 1)
        finally:
            for k, v in orig.items():
                if v is None:
                    sys.modules.pop(k, None)
                else:
                    sys.modules[k] = v

    def test_xephyr_home_update_now_and_ui_handlers(self) -> None:
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
            ["Xephyr", disp, "-screen", "1280x860", "-ac", "-noreset"],
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
import os, tempfile, time
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
from mintsec_ui.i18n import tr
from mintsec_ui.window import SuiteWindow

class _FakeRunner:
    def __init__(self):
        self.freshclam_runs = 0

    def which(self, b):
        if b in ("clamscan", "freshclam", "ufw"):
            return f"/usr/bin/{b}"
        return None

    def run(self, argv, **kw):
        cmd = argv[0]
        if cmd == "dpkg-query":
            if argv[-1] in ("clamav", "clamav-freshclam", "ufw"):
                return CommandResult(tuple(argv), 0, "install ok installed\\t1.0\\n", "")
            return CommandResult(tuple(argv), 1, "", "not installed")
        if cmd == "apt-cache":
            return CommandResult(tuple(argv), 0, " *** 1.0 500\\n", "")
        if cmd == "/usr/bin/freshclam":
            self.freshclam_runs += 1
            return CommandResult(tuple(argv), 0, "daily.cld database is up-to-date\\n", "")
        if cmd in ("ufw", "/usr/bin/ufw"):
            if "status" in argv:
                return CommandResult(tuple(argv), 0, "Status: inactive\\n", "")
            return CommandResult(tuple(argv), 0, "Firewall active\\n", "")
        return CommandResult(tuple(argv), 0, "", "")

def flush(ms=80):
    end = time.monotonic() + (ms / 1000.0)
    ctx = GLib.MainContext.default()
    while time.monotonic() < end:
        while ctx.pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.01)

def collect_buttons(widget):
    out = []
    if isinstance(widget, Gtk.Button):
        out.append(widget)
    if isinstance(widget, Gtk.Container):
        for ch in widget.get_children():
            out.extend(collect_buttons(ch))
    return out

with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    db_dir = base / "clamdb"
    db_dir.mkdir()
    daily = db_dir / "daily.cld"
    daily.write_bytes(b"cld-old")
    old_ts = time.time() - (90.0 * 3600.0)
    os.utime(daily, (old_ts, old_ts))

    runner = _FakeRunner()
    ctrl = SuiteController(
        config_store=ConfigStore(base / "settings.json"),
        pending_store=PendingStore(base / "pending.json"),
        history_store=HistoryStore(base / "history.db"),
        incident_manager=IncidentManager(base / "incidents"),
        runner=runner,
        authorizer=CallerAuthorizer(test_decision=True),
        data_dir=base / "data",
        clamav_db_dir=db_dir,
    )
    ctrl.config_store.update(first_run_completed=True, language="en")
    ctrl.antimalware.enable()

    win = SuiteWindow(None, controller=ctrl, initial_width=1200, initial_height=760)
    shown_errors = []
    win.show_error = lambda err, **kw: shown_errors.append((str(err), kw))
    flush(120)

    # Verifica db_outdated nas recomendações e clica no botão "Update now" da recomendação
    rec_ids = [r["rec_id"] for r in win.home_page._last_recs_data]
    assert "db_outdated" in rec_ids, rec_ids

    update_rec_btn = next(
        (b for b in collect_buttons(win.home_page.recs_box) if (b.get_label() or "") == tr("home.rec_action_update_db")),
        None,
    )
    assert update_rec_btn is not None, [b.get_label() for b in collect_buttons(win.home_page.recs_box)]
    update_rec_btn.clicked()
    flush(120)

    assert not shown_errors, shown_errors
    assert runner.freshclam_runs == 1, runner.freshclam_runs
    assert not any(r["rec_id"] == "db_outdated" for r in win.home_page._last_recs_data), win.home_page._last_recs_data
    assert win.home_page.update_db_btn.get_sensitive()

    # Clica em recomendação genérica auto-aplicável ("Turn on") para validar desempacotamento de 4 itens
    fw_btn = next(
        (b for b in collect_buttons(win.home_page.recs_box) if (b.get_label() or "") == tr("home.rec_action_enable")),
        None,
    )
    assert fw_btn is not None, [b.get_label() for b in collect_buttons(win.home_page.recs_box)]
    fw_btn.clicked()
    flush(120)
    assert not shown_errors, shown_errors

    # Limpa last_signature_update_at para testar o botão principal update_db_btn no hero
    st_data = ctrl.antimalware._load_state()
    st_data.pop("last_signature_update_at", None)
    ctrl.antimalware._save_state(st_data)
    win.refresh_all(force=True)
    flush(80)
    assert any(r["rec_id"] == "db_outdated" for r in win.home_page._last_recs_data)
    win.home_page.update_db_btn.clicked()
    flush(120)
    assert not shown_errors, shown_errors
    assert runner.freshclam_runs == 2, runner.freshclam_runs
    assert not any(r["rec_id"] == "db_outdated" for r in win.home_page._last_recs_data)

    # Valida que _on_network_discover executa via run_ui_task sem erro nem travamento
    discovered = []
    ctrl.network.active_discover = lambda net_id: discovered.append(net_id) or {"discovered": 0}
    win.module_detail_page._on_network_discover("home")
    flush(80)
    assert discovered == ["home"], discovered
    assert not shown_errors, shown_errors
    print("XEPHYR_DB_UPDATE_OK")
"""
            env = os.environ.copy()
            env["DISPLAY"] = disp
            env["PYTHONPATH"] = str(repo_root / "src")
            proc = subprocess.run(
                [sys.executable, "-c", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=45,
            )
            self.assertEqual(proc.returncode, 0, proc.stdout + "\n" + proc.stderr)
            self.assertIn("XEPHYR_DB_UPDATE_OK", proc.stdout)
        finally:
            xephyr.terminate()
            xephyr.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
