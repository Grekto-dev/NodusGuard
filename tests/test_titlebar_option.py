"""Testes para opção de barra de título do sistema (SSD/CSD) em Configurações."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mintsec.config import ConfigStore, SuiteConfig


class TitlebarConfigAndUiTests(unittest.TestCase):
    def test_config_default_and_persistence(self) -> None:
        with tempfile.TemporaryDirectory(prefix="mintsec-tb-cfg-") as tmp:
            store = ConfigStore(Path(tmp) / "settings.json")
            cfg = store.load()
            self.assertTrue(cfg.use_system_titlebar)

            store.update(use_system_titlebar=False)
            self.assertFalse(store.load().use_system_titlebar)

            store.update(use_system_titlebar=True)
            self.assertTrue(store.load().use_system_titlebar)

            # Payloads malformados não quebram o carregamento
            parsed = SuiteConfig.from_dict({"use_system_titlebar": 0})
            self.assertFalse(parsed.use_system_titlebar)

    def test_xephyr_live_titlebar_switch_and_startup(self) -> None:
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

    # 1. Padrão: barra de título do sistema (SSD) ativa
    win = SuiteWindow(None, controller=ctrl, initial_width=1200, initial_height=740)
    flush(100)
    assert win.get_titlebar() is None, win.get_titlebar()
    assert win.get_decorated() is True
    assert win.settings_page.chk_system_titlebar.get_active() is True
    assert win.settings_page.chk_system_titlebar.get_label() == "Use system title bar"

    # 2. Desmarcar checkbox alterna ao vivo para CSD (Gtk.HeaderBar) e atualiza subtítulo ao navegar
    win.navigate_to("settings", tab="general")
    flush(60)
    win.settings_page.chk_system_titlebar.set_active(False)
    flush(100)
    hb = win.get_titlebar()
    assert isinstance(hb, Gtk.HeaderBar), hb
    assert ctrl.config_store.load().use_system_titlebar is False
    assert hb.get_subtitle() == "Settings", hb.get_subtitle()

    # Garante que os botões no_show_all continuam respeitados após show() no toggle
    assert not win.active_scan_btn.get_visible()

    # 3. Marcar checkbox alterna de volta ao vivo para barra de título do sistema (SSD)
    win.settings_page.chk_system_titlebar.set_active(True)
    flush(100)
    assert win.get_titlebar() is None, win.get_titlebar()
    assert win.get_decorated() is True
    assert ctrl.config_store.load().use_system_titlebar is True
    win.destroy()
    flush(40)

    # 4. Nova janela iniciada com use_system_titlebar=False já sobe em CSD antes da realização
    ctrl.config_store.update(use_system_titlebar=False, language="pt_BR")
    win2 = SuiteWindow(None, controller=ctrl, initial_width=1200, initial_height=740)
    flush(100)
    hb2 = win2.get_titlebar()
    assert isinstance(hb2, Gtk.HeaderBar), hb2
    assert win2.settings_page.chk_system_titlebar.get_active() is False
    assert win2.settings_page.chk_system_titlebar.get_label() == "Usar barra de título do sistema"
    win2.destroy()
    flush(40)

print("XEPHYR_TITLEBAR_OK")
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
            self.assertIn("XEPHYR_TITLEBAR_OK", res.stdout)
        finally:
            xephyr.terminate()
            try:
                xephyr.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xephyr.kill()


if __name__ == "__main__":
    unittest.main()
