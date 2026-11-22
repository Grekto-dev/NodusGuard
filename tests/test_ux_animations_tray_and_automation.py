"""Testes das melhorias de UX: animação Home, bandeja, pausa, sistema completo, ETA/%, Quarentena, Notificações e automação."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path

from mintsec.auth import CallerAuthorizer
from mintsec.autostart import get_autostart_file, sync_autostart
from mintsec.config import ConfigStore, SuiteConfig
from mintsec.contracts import ModuleState
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController


class _FakeUxRunner:
    def __init__(self, target_dir: Path) -> None:
        self.target_dir = target_dir
        self.calls: list[list[str]] = []
        self.available = {
            "clamscan": "/usr/bin/clamscan",
            "clamdscan": "/usr/bin/clamdscan",
            "clamav-freshclam": "/usr/bin/clamav-freshclam",
            "freshclam": "/usr/bin/freshclam",
            "ufw": "/usr/bin/ufw",
            "timeshift": "/usr/bin/timeshift",
            "systemctl": "/usr/bin/systemctl",
            "systemd-run": "/usr/bin/systemd-run",
        }

    def which(self, binary: str) -> str | None:
        return self.available.get(binary)

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        cmd = [str(a) for a in argv]
        self.calls.append(cmd)
        if cmd[0] == "dpkg-query":
            return CommandResult(tuple(cmd), 0, "install ok installed\t1.0.0\n", "")
        if cmd[0] == "apt-cache":
            return CommandResult(
                tuple(cmd),
                0,
                " *** 1.0.0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n",
                "",
            )
        if Path(cmd[0]).name == "clamscan":
            lines = [f"{p}: OK" for p in sorted(self.target_dir.glob("*")) if p.is_file()]
            if on_line:
                for line in lines:
                    on_line(line)
            return CommandResult(tuple(cmd), 0, "\n".join(lines) + "\n", "")
        if Path(cmd[0]).name == "ufw":
            return CommandResult(tuple(cmd), 0, "Status: active\n", "")
        if Path(cmd[0]).name == "systemctl":
            if "is-active" in cmd:
                return CommandResult(tuple(cmd), 0, "active\n", "")
            if "is-enabled" in cmd:
                return CommandResult(tuple(cmd), 0, "enabled\n", "")
            return CommandResult(tuple(cmd), 0, "", "")
        return CommandResult(tuple(cmd), 0, "", "")


def _make_controller(base: Path) -> tuple[SuiteController, _FakeUxRunner, Path, Path]:
    scan_target = base / "scan_target"
    scan_target.mkdir(parents=True, exist_ok=True)
    for idx in range(4):
        (scan_target / f"doc_{idx}.txt").write_text(f"clean {idx}\n", encoding="utf-8")

    db_dir = base / "clamdb"
    db_dir.mkdir(parents=True, exist_ok=True)
    (db_dir / "daily.cld").write_bytes(b"db")

    runner = _FakeUxRunner(scan_target)
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
    return ctrl, runner, scan_target, db_dir


class UxAutomationBackendTests(unittest.TestCase):
    def test_config_defaults_and_pause_validation(self) -> None:
        cfg = SuiteConfig()
        self.assertTrue(cfg.autostart_enabled)
        self.assertTrue(cfg.auto_quick_scan_enabled)
        self.assertEqual(cfg.auto_quick_scan_interval, "daily")
        self.assertTrue(cfg.auto_db_update_enabled)
        self.assertFalse(cfg.do_not_disturb)
        self.assertFalse(cfg.game_mode)
        self.assertFalse(cfg.protection_paused)
        self.assertEqual(cfg.protection_pause_mode, "none")

        with tempfile.TemporaryDirectory() as tmp:
            store = ConfigStore(Path(tmp) / "config.json")
            saved = store.update(
                autostart_enabled=False,
                auto_quick_scan_interval="6h",
                do_not_disturb=True,
                game_mode=True,
                ignored_recommendations=["db_outdated"],
            )
            self.assertFalse(saved.autostart_enabled)
            self.assertEqual(saved.auto_quick_scan_interval, "6h")
            self.assertTrue(saved.do_not_disturb)
            self.assertTrue(saved.game_mode)
            self.assertEqual(saved.ignored_recommendations, ["db_outdated"])

            with self.assertRaises(ValueError):
                store.update(auto_quick_scan_interval="2h")
            with self.assertRaises(ValueError):
                store.update(protection_pause_mode="forever")

        now = datetime.now().astimezone()
        expired_cfg = SuiteConfig(
            protection_paused=True,
            protection_pause_mode="timed",
            protection_paused_until=(now - timedelta(minutes=2)).isoformat(timespec="seconds"),
        )
        self.assertFalse(expired_cfg.is_protection_paused_now(now=now))
        active_cfg = SuiteConfig(
            protection_paused=True,
            protection_pause_mode="timed",
            protection_paused_until=(now + timedelta(minutes=10)).isoformat(timespec="seconds"),
        )
        self.assertTrue(active_cfg.is_protection_paused_now(now=now))
        restart_cfg = SuiteConfig(protection_paused=True, protection_pause_mode="until_restart")
        self.assertTrue(restart_cfg.is_protection_paused_now(now=now))

    def test_autostart_sync_creates_and_removes_desktop_file(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cfg_home = Path(tmp) / "xdg_cfg"
            desktop = sync_autostart(True, config_home=cfg_home)
            self.assertEqual(desktop, get_autostart_file(config_home=cfg_home))
            self.assertTrue(desktop.is_file())
            content = desktop.read_text(encoding="utf-8")
            self.assertIn("Exec=mint-security-suite --minimized", content)
            self.assertIn("X-GNOME-Autostart-enabled=true", content)

            removed = sync_autostart(False, config_home=cfg_home)
            self.assertFalse(removed.exists())

    def test_system_scan_scope_eta_stats_and_6h_12h_schedules(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctrl, runner, _target, _db_dir = _make_controller(Path(tmp))

            # Não caminhar "/" no host durante teste unitário
            ctrl.antimalware.estimate_scan_total = lambda *_args, **_kwargs: (4, True)  # type: ignore[method-assign]
            stats_events: list[dict] = []
            res = ctrl.antimalware.run_scan(scope="system", on_stats=stats_events.append)

            self.assertEqual(res.scope, "system")
            clam_calls = [c for c in runner.calls if c and Path(c[0]).name == "clamscan"]
            self.assertEqual(len(clam_calls), 1)
            self.assertIn("/", clam_calls[0])
            self.assertTrue(any(arg.startswith("--exclude-dir=") and "/proc" in arg for arg in clam_calls[0]))
            self.assertGreaterEqual(len(stats_events), 2)
            self.assertEqual(stats_events[0]["phase"], "counting")
            self.assertEqual(stats_events[-1]["phase"], "done")
            self.assertEqual(stats_events[-1]["percent"], 100.0)

            sched_6h = ctrl.antimalware.save_schedule(schedule_id="s6", scope="system", frequency="6h")
            sched_12h = ctrl.antimalware.save_schedule(schedule_id="s12", scope="quick", frequency="12h")
            self.assertEqual(sched_6h["scope"], "system")
            self.assertEqual(sched_6h["frequency"], "6h")
            self.assertEqual(sched_12h["frequency"], "12h")

    def test_controller_pause_health_recommendations_and_default_automation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            ctrl, _runner, target, db_dir = _make_controller(Path(tmp))

            ctrl.ensure_default_automation()
            schedules = ctrl.antimalware.list_schedules()
            self.assertTrue(any(s["schedule_id"] == "auto_quick" and s["frequency"] == "daily" for s in schedules))
            self.assertTrue(ctrl.is_auto_scan_due())

            ctrl.antimalware.run_scan(scope="custom", paths=[str(target)])
            self.assertFalse(ctrl.is_auto_scan_due())
            ctrl.config_store.update(game_mode=True)
            ctrl.antimalware._save_state({**ctrl.antimalware._load_state(), "last_scan": None})
            self.assertFalse(ctrl.is_auto_scan_due())
            ctrl.config_store.update(game_mode=False)

            ctrl.antimalware.run_scan(scope="custom", paths=[str(target)])
            statuses = ctrl.all_statuses()
            statuses_ok = {
                mid: replace(st, state=ModuleState.ATIVO, needs_setup=False)
                for mid, st in statuses.items()
            }
            self.assertEqual(ctrl.get_overall_health(statuses=statuses_ok), "ok")

            # Pausar proteção -> "paused" + recomendação "protection_paused"
            ctrl.pause_protection(mode="timed", minutes=15)
            self.assertEqual(ctrl.get_overall_health(statuses=statuses_ok), "paused")
            recs = ctrl.get_protection_recommendations(statuses=statuses_ok)
            self.assertEqual(recs[0]["rec_id"], "protection_paused")

            # Expiração automática da pausa
            past = (datetime.now().astimezone() - timedelta(minutes=1)).isoformat(timespec="seconds")
            ctrl.config_store.update(protection_paused_until=past)
            self.assertTrue(ctrl.check_pause_expiry())
            self.assertFalse(ctrl.config_store.load().protection_paused)

            # Pausa até reinício limpa no startup
            ctrl.pause_protection(mode="until_restart")
            self.assertEqual(ctrl.get_overall_health(statuses=statuses_ok), "paused")
            ctrl.clear_until_restart_pause_on_startup()
            self.assertFalse(ctrl.config_store.load().protection_paused)

            # Recomendação ignorável pode ser ocultada e restaurada
            (db_dir / "daily.cld").unlink()
            self.assertEqual(ctrl.get_overall_health(), "alert")
            recs_alert = ctrl.get_protection_recommendations()
            self.assertTrue(any(r["rec_id"] == "db_outdated" for r in recs_alert))
            ctrl.ignore_recommendation("db_outdated")
            recs_after_ignore = ctrl.get_protection_recommendations()
            self.assertFalse(any(r["rec_id"] == "db_outdated" for r in recs_after_ignore))
            ctrl.restore_ignored_recommendations()
            recs_restored = ctrl.get_protection_recommendations()
            self.assertTrue(any(r["rec_id"] == "db_outdated" for r in recs_restored))


class UxGtkXephyrTests(unittest.TestCase):
    def test_ui_animations_tray_pause_quarantine_notifications_and_screenshots(self) -> None:
        shot_dir = Path(
            "/home/pedro/.gemini/antigravity/brain/10e9e2c8-788a-420b-8635-b87c7f567263/scratch"
        )
        shot_dir.mkdir(parents=True, exist_ok=True)
        root_dir = Path(__file__).resolve().parents[1]

        script = r"""
import os, subprocess, tempfile, time
from dataclasses import replace
from pathlib import Path

def free_display():
    for n in range(110, 145):
        if not Path(f"/tmp/.X11-unix/X{n}").exists():
            return f":{n}"
    return ":149"

disp = free_display()
xephyr = subprocess.Popen(
    ["Xephyr", disp, "-screen", "1400x900", "-ac", "-noreset"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
try:
    os.environ["DISPLAY"] = disp
    os.environ["MINTSEC_DISABLE_TRAY"] = "1"
    time.sleep(0.6)
    assert xephyr.poll() is None, "Xephyr falhou ao iniciar"

    import gi
    gi.require_version("Gdk", "3.0")
    gi.require_version("GLib", "2.0")
    gi.require_version("Gtk", "3.0")
    from gi.repository import Gdk, GLib, Gtk

    Gtk.init([])

    from mintsec.auth import CallerAuthorizer
    from mintsec.config import ConfigStore
    from mintsec.contracts import ModuleState
    from mintsec.history import HistoryStore
    from mintsec.incident import IncidentManager
    from mintsec.pending import PendingStore
    from mintsec.runner import CommandResult
    from mintsec.services.catalog import SuiteController
    from mintsec_ui.dialogs.pause_protection import PauseProtectionDialog
    from mintsec_ui.i18n import tr
    from mintsec_ui.window import SuiteWindow

    class _UiRunner:
        def __init__(self, target):
            self.target = target
        def which(self, b):
            return f"/usr/bin/{b}" if b in ("clamscan", "freshclam", "ufw", "timeshift", "systemctl") else None
        def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None):
            cmd = [str(x) for x in argv]
            if cmd[0] == "dpkg-query":
                return CommandResult(tuple(cmd), 0, "install ok installed\t1.0.0\n", "")
            if cmd[0].endswith("clamscan"):
                line = f"{self.target}: OK"
                if on_line:
                    on_line(line)
                return CommandResult(tuple(cmd), 0, line + "\n", "")
            if cmd[0].endswith("ufw"):
                return CommandResult(tuple(cmd), 0, "Status: active\n", "")
            if cmd[0].endswith("systemctl"):
                if "is-active" in cmd:
                    return CommandResult(tuple(cmd), 0, "active\n", "")
                if "is-enabled" in cmd:
                    return CommandResult(tuple(cmd), 0, "enabled\n", "")
            return CommandResult(tuple(cmd), 0, "", "")

    def flush(ms=100):
        end = time.monotonic() + (ms / 1000.0)
        ctx = GLib.MainContext.default()
        while time.monotonic() < end:
            while ctx.pending():
                Gtk.main_iteration_do(False)
            time.sleep(0.01)

    def snap(win, out_path):
        flush(120)
        gw = win.get_window()
        assert gw is not None
        alloc = win.get_allocation()
        pb = Gdk.pixbuf_get_from_window(gw, 0, 0, max(1, alloc.width), max(1, alloc.height))
        if pb is not None:
            pb.savev(str(out_path), "png", [], [])

    with tempfile.TemporaryDirectory() as tmp:
        base = Path(tmp)
        db_dir = base / "clamdb"
        db_dir.mkdir()
        (db_dir / "daily.cld").write_bytes(b"ok")
        target = base / "files"
        target.mkdir()
        suspect = target / "sample.bin"
        suspect.write_bytes(b"eicar")

        ctrl = SuiteController(
            config_store=ConfigStore(base / "settings.json"),
            pending_store=PendingStore(base / "pending.json"),
            history_store=HistoryStore(base / "history.db"),
            incident_manager=IncidentManager(base / "incidents"),
            runner=_UiRunner(suspect),
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=base / "data",
            clamav_db_dir=db_dir,
        )
        ctrl.config_store.update(theme_mode="light", first_run_completed=True, language="en")
        ctrl.antimalware.run_scan(scope="custom", paths=[str(target)])

        win = SuiteWindow(None, controller=ctrl, initial_width=1280, initial_height=760)
        flush(150)

        healthy_statuses = {
            mid: replace(st, state=ModuleState.ATIVO, needs_setup=False)
            for mid, st in ctrl.all_statuses().items()
        }
        win.home_page.refresh(statuses=healthy_statuses)
        win.sync_tray(statuses=healthy_statuses)
        flush(180)

        # 1. Animação verde na Home quando tudo OK
        assert win.home_page.status_canvas._target_red == 0.0
        assert win.home_page.status_card.get_style_context().has_class("mintsec-hero-ok")
        shot_dir = Path(os.environ["SHOT_DIR"])
        snap(win, shot_dir / "home_green.png")

        # Animação ativa na Home vs zerada fora da Home ou com gtk-enable-animations=False
        gtk_settings = Gtk.Settings.get_default()
        gtk_settings.set_property("gtk-enable-animations", True)
        win.home_page.set_animations_active(True)
        canvas_draws = [0]
        def _count_draw(*_):
            canvas_draws[0] += 1
            return False
        hid = win.home_page.status_canvas.connect("draw", _count_draw)
        flush(300)
        assert canvas_draws[0] >= 2, f"Expected >=2 animation draws, got {canvas_draws[0]}"

        win.navigate_to("scans")
        flush(60)
        canvas_draws[0] = 0
        flush(250)
        assert canvas_draws[0] == 0, f"Expected 0 draws off-home, got {canvas_draws[0]}"

        win.navigate_to("home")
        win.home_page.refresh(statuses=healthy_statuses)
        gtk_settings.set_property("gtk-enable-animations", False)
        flush(240)
        assert win.home_page.status_canvas._timer_id is None
        canvas_draws[0] = 0
        flush(250)
        assert canvas_draws[0] == 0, f"Expected 0 draws when animations disabled, got {canvas_draws[0]}"
        win.home_page.status_canvas.disconnect(hid)
        gtk_settings.set_property("gtk-enable-animations", True)

        # 2. Sino no rodapé esquerdo ao lado esquerdo de Settings + página Notificações
        bell_alloc = win.bell_btn.get_allocation()
        sett_alloc = win._sidebar_buttons["settings"].get_allocation()
        assert bell_alloc.x + bell_alloc.width <= sett_alloc.x + 2, (bell_alloc.x, bell_alloc.width, sett_alloc.x)

        win.bell_btn.clicked()
        flush(120)
        assert win.current_page == "notifications"
        snap(win, shot_dir / "notifications.png")

        # 3. Página dedicada Quarentena
        ctrl.antimalware.quarantine_file(suspect, detection_name="Eicar-Test-Signature", confirmed=True)
        win.navigate_to("quarantine")
        flush(150)
        assert win.current_page == "quarantine"
        assert len(win.quarantine_page.list_box.get_children()) == 1
        snap(win, shot_dir / "quarantine.png")

        # 4. Home vermelha com recomendações + Ignore/Restore + Last scan + Virus DB
        win.navigate_to("home")
        (db_dir / "daily.cld").unlink()
        alert_statuses = ctrl.all_statuses()
        win.home_page.refresh(statuses=alert_statuses)
        win.sync_tray(statuses=alert_statuses)
        flush(240)
        assert win.home_page.status_canvas._target_red == 1.0
        assert win.home_page.status_card.get_style_context().has_class("mintsec-hero-alert")
        snap(win, shot_dir / "home_red_recs.png")

        # Testa botão Ignore e Restaurar Ignoradas na Home
        ignore_btns = []
        for row in win.home_page.recs_box.get_children():
            for child in row.get_children():
                if isinstance(child, Gtk.Button) and child.get_label() == tr("home.rec_ignore_btn"):
                    ignore_btns.append(child)
        assert len(ignore_btns) >= 1, "Expected at least 1 Ignore button in Home recommendations"
        ignore_btns[0].clicked()
        flush(80)
        assert len(ctrl.config_store.load().ignored_recommendations) == 1
        assert win.home_page.restore_ignored_btn.get_visible()
        win.home_page.restore_ignored_btn.clicked()
        flush(80)
        assert ctrl.config_store.load().ignored_recommendations == []

        # 5. Página Scans com Scan Completo do Sistema e card ETA + %
        win.navigate_to("scans")
        assert win.scans_page.btn_system.get_visible()
        win.scans_page._scanning = True
        win.scans_page.progress_revealer.set_reveal_child(True)
        win.scans_page._on_scan_stats({
            "phase": "scanning",
            "items_scanned": 420,
            "total_estimated": 1000,
            "exact_total": True,
            "percent": 42.0,
            "eta_seconds": 95,
            "current_path": "/home/pedro/Documents/report.pdf",
        })
        flush(220)
        assert "42%" in win.scans_page.progress_pct_lbl.get_text()
        assert "~1m 35s" in win.scans_page.progress_eta_lbl.get_text()
        assert abs(win.scans_page.progress_bar.get_fraction() - 0.42) < 0.02
        snap(win, shot_dir / "scans_eta.png")
        win.scans_page._scanning = False
        win.scans_page.progress_revealer.set_reveal_child(False)

        # 6. Diálogo Pausar Proteção (exatamente 8 durações + 3 modos)
        dlg = PauseProtectionDialog(win)
        flush(120)
        combo_model = dlg.duration_combo.get_model()
        labels = [row[0] for row in combo_model]
        assert labels == [
            "1 minute", "3 minutes", "5 minutes", "15 minutes",
            "30 minutes", "1 hour", "3 hours", "5 hours",
        ], labels
        dlg.duration_combo.set_active_id("60")
        assert dlg.get_selection() == ("timed", 60)
        dlg.radio_restart.set_active(True)
        assert dlg.get_selection() == ("until_restart", None)
        dlg.radio_indefinite.set_active(True)
        assert dlg.get_selection() == ("indefinite", None)
        snap(dlg, shot_dir / "pause_dialog.png")
        dlg.destroy()

        # 7. Tray context menu items (EN & PT-BR) + DND/Game Mode sync
        tray = win.tray
        assert tray.item_open.get_label() == "NodusGuard"
        assert tray.item_pause.get_label() == "Pause Protection…"
        assert tray.item_settings.get_label() == "Settings"
        assert tray.item_dnd.get_label() == "Enable Do Not Disturb"
        assert tray.item_game.get_label() == "Game Mode"
        assert tray.item_about.get_label() == "About"
        assert tray.item_quit.get_label() == "Quit"
        assert not tray.item_resume.get_visible()

        ctrl.pause_protection(mode="indefinite")
        win.refresh_all(force=False)
        assert tray.item_resume.get_visible()

        tray.item_dnd.set_active(True)
        tray.item_game.set_active(True)
        flush(40)
        assert ctrl.config_store.load().do_not_disturb
        assert ctrl.config_store.load().game_mode

        ctrl.config_store.update(language="pt_BR")
        win.apply_language()
        flush(60)
        assert tray.item_pause.get_label() == "Pausar Proteção…"
        assert tray.item_dnd.get_label() == "Ativar o Modo Não Perturbe"
        assert tray.item_game.get_label() == "Modo de Jogo"
        assert tray.item_about.get_label() == "Sobre"
        assert tray.item_quit.get_label() == "Sair"

        win.destroy()
        flush(40)
finally:
    xephyr.terminate()
    try:
        xephyr.wait(timeout=3)
    except subprocess.TimeoutExpired:
        xephyr.kill()
"""
        env = dict(os.environ)
        env["PYTHONPATH"] = str(root_dir / "src")
        env["SHOT_DIR"] = str(shot_dir)
        proc = subprocess.run(
            [sys.executable, "-c", script],
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, f"STDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")


if __name__ == "__main__":
    unittest.main()
