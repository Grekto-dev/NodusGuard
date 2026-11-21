"""Ensaios automatizados H8 (GTK 3 em Xephyr): contraste, teclado/ATK, área útil e zero repinturas."""

from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController


class FakeUiRunner:
    def __init__(self, target_file: Path) -> None:
        self.target_file = target_file

    def which(self, binary: str) -> str | None:
        return f"/usr/bin/{binary}" if binary in ("clamscan", "ufw") else None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        if argv[0] == "dpkg-query":
            pkg = argv[-1]
            if pkg in ("clamav", "clamav-freshclam", "ufw"):
                return CommandResult(tuple(argv), 0, "install ok installed\t1.0.0\n", "")
            return CommandResult(tuple(argv), 1, "", "not installed")
        if argv[0] == "apt-cache":
            return CommandResult(
                tuple(argv),
                0,
                " *** 1.0.0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n",
                "",
            )
        if argv[0].endswith("clamscan"):
            line = f"{self.target_file}: Eicar-Test-Signature FOUND"
            if on_line:
                on_line(line)
            return CommandResult(tuple(argv), 1, line + "\n", "")
        if argv[0].endswith("ufw"):
            return CommandResult(tuple(argv), 0, "Status: inactive\n", "")
        return CommandResult(tuple(argv), 0, "", "")


def _pick_free_display() -> str:
    for disp in range(95, 115):
        if not Path(f"/tmp/.X{disp}-lock").exists() and not Path(f"/tmp/.X11-unix/X{disp}").exists():
            return f":{disp}"
    return ":99"


class H8UiTests(unittest.TestCase):
    xephyr_proc: subprocess.Popen[str] | None = None
    orig_display: str | None = None
    tmp_dir: tempfile.TemporaryDirectory[str] | None = None

    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp_dir = tempfile.TemporaryDirectory(prefix="mintsec-h8-")
        cls.orig_display = os.environ.get("DISPLAY")
        if not os.environ.get("MINTSEC_XEPHYR_ACTIVE"):
            disp = _pick_free_display()
            cls.xephyr_proc = subprocess.Popen(
                ["Xephyr", disp, "-screen", "1400x900", "-ac", "-noreset"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                text=True,
            )
            os.environ["DISPLAY"] = disp
            time.sleep(0.5)
            if cls.xephyr_proc.poll() is not None:
                raise RuntimeError("Não foi possível iniciar Xephyr isolado para o ensaio H8.")

        import gi

        gi.require_version("Atk", "1.0")
        gi.require_version("Gdk", "3.0")
        gi.require_version("Gtk", "3.0")
        from gi.repository import Gtk

        Gtk.init([])
        cls.metrics: dict[str, object] = {}

    @classmethod
    def tearDownClass(cls) -> None:
        if cls.xephyr_proc is not None:
            cls.xephyr_proc.terminate()
            try:
                cls.xephyr_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                cls.xephyr_proc.kill()
        if cls.orig_display is not None:
            os.environ["DISPLAY"] = cls.orig_display
        if cls.tmp_dir is not None:
            cls.tmp_dir.cleanup()

    def _flush_gtk(self, duration_ms: int = 80) -> None:
        from gi.repository import GLib, Gtk

        end = time.monotonic() + (duration_ms / 1000.0)
        ctx = GLib.MainContext.default()
        while time.monotonic() < end:
            while ctx.pending():
                Gtk.main_iteration_do(False)
            time.sleep(0.01)

    def _make_controller(self, subdir: str) -> tuple[SuiteController, Path]:
        base = Path(self.tmp_dir.name) / subdir  # type: ignore[union-attr]
        base.mkdir(parents=True, exist_ok=True)
        suspect = base / "amostra_eicar.bin"
        suspect.write_bytes(b"eicar-demo")
        runner = FakeUiRunner(suspect)
        db_dir = base / "clamav"
        db_dir.mkdir()
        (db_dir / "daily.cld").write_bytes(b"db")
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
        return ctrl, suspect

    def test_01_rendered_contrast_light_dark_and_high_contrast(self) -> None:
        import cairo
        from gi.repository import Gtk

        from mintsec_ui.theme import (
            LAVENDER_TOKENS,
            THEME_PRESETS,
            build_css,
            contrast_ratio,
            hex_to_rgb,
            resolve_theme_info,
            rgba_to_rgb,
        )
        from mintsec_ui.window import SuiteWindow

        # Verifica razão matemática dos tokens da Seção 5.3 e todos os presets da Fase 2
        for preset_name, tokens in THEME_PRESETS.items():
            cr_p = contrast_ratio(hex_to_rgb(tokens["text_primary"]), hex_to_rgb(tokens["page_bg"]))
            cr_s = contrast_ratio(hex_to_rgb(tokens["text_secondary"]), hex_to_rgb(tokens["card_bg"]))
            cr_ct = contrast_ratio(hex_to_rgb(tokens["accent_fg"]), hex_to_rgb(tokens["accent"]))
            cr_cb = contrast_ratio(hex_to_rgb(tokens["accent"]), hex_to_rgb(tokens["page_bg"]))
            cr_bd = contrast_ratio(hex_to_rgb(tokens["border"]), hex_to_rgb(tokens["card_bg"]))
            self.assertGreaterEqual(cr_p, 4.5, f"{preset_name} text_primary")
            self.assertGreaterEqual(cr_s, 4.5, f"{preset_name} text_secondary")
            self.assertGreaterEqual(cr_ct, 4.5, f"{preset_name} accent_fg")
            self.assertGreaterEqual(cr_cb, 3.0, f"{preset_name} accent_bg")
            self.assertGreaterEqual(cr_bd, 3.0, f"{preset_name} border")

        cr_primary = contrast_ratio(
            hex_to_rgb(LAVENDER_TOKENS["text_primary"]),
            hex_to_rgb(LAVENDER_TOKENS["page_bg"]),
        )
        cr_secondary = contrast_ratio(
            hex_to_rgb(LAVENDER_TOKENS["text_secondary"]),
            hex_to_rgb(LAVENDER_TOKENS["card_bg"]),
        )
        cr_cta_text = contrast_ratio(
            hex_to_rgb(LAVENDER_TOKENS["accent_fg"]),
            hex_to_rgb(LAVENDER_TOKENS["accent"]),
        )
        cr_cta_bg = contrast_ratio(
            hex_to_rgb(LAVENDER_TOKENS["accent"]),
            hex_to_rgb(LAVENDER_TOKENS["page_bg"]),
        )
        cr_border = contrast_ratio(
            hex_to_rgb(LAVENDER_TOKENS["border"]),
            hex_to_rgb(LAVENDER_TOKENS["card_bg"]),
        )
        self.assertGreaterEqual(cr_primary, 14.0)
        self.assertGreaterEqual(cr_secondary, 4.5)
        self.assertGreaterEqual(cr_cta_text, 4.5)
        self.assertGreaterEqual(cr_cta_bg, 3.0)
        self.assertGreaterEqual(cr_border, 3.0)

        ctrl, _ = self._make_controller("contrast")
        ctrl.config_store.update(theme_mode="light", first_run_completed=True)
        win = SuiteWindow(None, controller=ctrl, initial_width=1366, initial_height=768)
        self._flush_gtk(120)

        # Renderiza em superfície Cairo e amostra cor de fundo real (#F0EFFA -> ~(240,239,250))
        alloc = win.get_allocation()
        surface = cairo.ImageSurface(cairo.FORMAT_ARGB32, max(1, alloc.width), max(1, alloc.height))
        cr = cairo.Context(surface)
        win.draw(cr)
        surface.flush()
        data = bytes(surface.get_data())
        stride = surface.get_stride()
        # Amostra canto inferior direito da área de conteúdo (BGRA em little-endian)
        px_x = max(10, alloc.width - 20)
        px_y = max(10, alloc.height - 20)
        off = px_y * stride + px_x * 4
        b, g, r, _a = data[off : off + 4]
        sampled_bg = (r / 255.0, g / 255.0, b / 255.0)
        self.assertGreater(
            contrast_ratio(hex_to_rgb(LAVENDER_TOKENS["text_primary"]), sampled_bg),
            12.0,
        )

        # Modo escuro nativo (Adwaita-dark / Mint-Y-Dark-Aqua)
        settings = Gtk.Settings.get_default()
        orig_theme = settings.get_property("gtk-theme-name")
        try:
            settings.set_property("gtk-theme-name", "Mint-Y-Dark-Aqua")
            ctrl.config_store.update(theme_mode="follow_system")
            win.apply_theme()
            self._flush_gtk(100)
            self.assertEqual(win.theme_manager.current_info.mode, "dark")
            ctx = win.get_style_context()
            ok_bg, bg = ctx.lookup_color("theme_bg_color")
            ok_fg, fg = ctx.lookup_color("theme_fg_color")
            if ok_bg and ok_fg:
                self.assertGreaterEqual(contrast_ratio(rgba_to_rgb(fg), rgba_to_rgb(bg)), 4.5)

            # Modo Alto Contraste: CSS customizado completamente omitido
            settings.set_property("gtk-theme-name", "HighContrast")
            self._flush_gtk(80)
            hc_info = resolve_theme_info(theme_mode="follow_system", probe_widget=win)
            self.assertEqual(hc_info.mode, "high_contrast")
            self.assertEqual(build_css(hc_info), "")
            ok_bg, bg = ctx.lookup_color("theme_bg_color")
            ok_fg, fg = ctx.lookup_color("theme_fg_color")
            if ok_bg and ok_fg:
                self.assertGreaterEqual(contrast_ratio(rgba_to_rgb(fg), rgba_to_rgb(bg)), 7.0)
        finally:
            settings.set_property("gtk-theme-name", orig_theme)
            win.destroy()
            self._flush_gtk(40)

    def test_02_keyboard_atk_and_paused_app_workflow(self) -> None:
        from gi.repository import Gtk

        from mintsec_ui.dialogs.first_run import FirstRunDialog
        from mintsec_ui.dialogs.paused_app import PausedAppDialog
        from mintsec_ui.window import SuiteWindow

        ctrl, suspect = self._make_controller("kbd_atk")
        ctrl.config_store.update(theme_mode="light", first_run_completed=True)
        win = SuiteWindow(None, controller=ctrl, initial_width=1280, initial_height=768)
        self._flush_gtk(100)

        # Verifica nomes acessíveis ATK em botões de navegação e cartões do Início
        def _collect_interactive(container: Gtk.Widget) -> list[Gtk.Widget]:
            found: list[Gtk.Widget] = []
            if isinstance(container, (Gtk.Button, Gtk.Entry, Gtk.ComboBox)):
                found.append(container)
            if isinstance(container, Gtk.Container):
                for ch in container.get_children():
                    found.extend(_collect_interactive(ch))
            return found

        for page_name in ("home", "scans", "protections", "recovery", "activity", "settings"):
            win.navigate_to(page_name)
            self._flush_gtk(40)
            for widget in _collect_interactive(win.pages[page_name]):
                if widget.get_visible():
                    acc_name = widget.get_accessible().get_name()
                    self.assertTrue(
                        bool(acc_name and acc_name.strip()),
                        f"Controle visível sem nome ATK na página {page_name}: {widget}",
                    )

        for mod_id in ("antimalware", "firewall", "recovery", "network", "browsing", "isolation", "rescue"):
            win.open_module_detail(mod_id)
            self._flush_gtk(30)
            for widget in _collect_interactive(win.module_detail_page):
                if widget.get_visible():
                    acc_name = widget.get_accessible().get_name()
                    self.assertTrue(
                        bool(acc_name and acc_name.strip()),
                        f"Controle visível sem nome ATK no detalhe {mod_id}: {widget}",
                    )

        # Assistente inicial sem pré-seleção
        fr = FirstRunDialog(win, ctrl)
        self.assertIsNone(fr.selected_pause_policy())
        fr.destroy()

        # Fluxo sem mouse: verificação de pasta -> quarentena confirmada -> restauração em outro destino
        win.navigate_to("scans", tab="scan")
        win.scans_page.start_scan("custom", custom_paths=[str(suspect.parent)])
        self._flush_gtk(200)
        self.assertEqual(ctrl.pending_store.count_open(), 1)
        pending_det = ctrl.pending_store.list_open()[0]
        q_item = ctrl.antimalware.quarantine_file(
            suspect,
            detection_name="Eicar-Test-Signature",
            confirmed=True,
            pending_id=pending_det.pending_id,
        )
        alt_dest = suspect.parent / "destino_alternativo" / "recuperado.bin"
        restored = ctrl.antimalware.restore_quarantined(q_item.item_id, destination_path=alt_dest)
        self.assertTrue(restored.is_file())

        # Diálogo de aplicativo pausado com FAN_Q_OVERFLOW: foco inicial em Manter pausado
        paused_dec = ctrl.pending_store.create(
            kind="paused_app",
            module_id="recovery",
            app_name="ransom-sim",
            title="Um aplicativo está pausado",
            summary="Alteração em canário detectada.",
            evidence="Canário alterado + cgroup exclusivo",
            fan_q_overflow=True,
            affected_paths=["/tmp/doc1.odt"],
        )
        win.refresh_all()
        self._flush_gtk(50)
        self.assertEqual(win.bell_count_lbl.get_text(), "1")

        dlg = PausedAppDialog(win, controller=ctrl, decision=paused_dec)
        self._flush_gtk(80)
        self.assertIs(dlg.get_focus(), dlg.keep_btn)
        self.assertEqual(dlg.restore_btn.get_label(), "Restore detected files…")
        self.assertIsNotNone(dlg.open_full_backup_btn)
        self.assertTrue(dlg.open_full_backup_btn.get_visible())

        # Fechar o diálogo preserva a pausa e a pendência no sino
        dlg.emit("delete-event", None)
        dlg.destroy()
        win.refresh_all()
        self._flush_gtk(40)
        self.assertEqual(ctrl.pending_store.count_open(), 1)
        self.assertEqual(win.bell_count_lbl.get_text(), "1")
        win.destroy()
        self._flush_gtk(40)

    def test_03_responsive_viewports_and_enlarged_font(self) -> None:
        from gi.repository import Gtk

        from mintsec_ui.window import SuiteWindow

        ctrl, _ = self._make_controller("responsive")
        ctrl.config_store.update(theme_mode="light", first_run_completed=True)
        win = SuiteWindow(None, controller=ctrl, initial_width=1366, initial_height=768)
        self._flush_gtk(120)

        # Em 1366x768: lateral visível + escudo e 3 cartões antes da primeira rolagem
        self.assertTrue(win.sidebar.get_visible())
        self.assertFalse(win.menu_btn.get_visible())
        cards = win.home_page.cards_box.get_children()
        self.assertEqual(len(cards), 3)
        for card in cards:
            alloc = card.get_allocation()
            self.assertLessEqual(alloc.y + alloc.height, 740)

        # Em 1024x600: lateral recolhe em Menu, escudo reduz e cartões reorganizam
        win.resize(1024, 600)
        self._flush_gtk(150)
        self.assertFalse(win.sidebar.get_visible())
        self.assertTrue(win.menu_btn.get_visible())
        self.assertEqual(win.home_page.shield_icon.get_pixel_size(), 36)

        # Fonte ampliada (1.5x) em 1024x600: controles alcançáveis sem overflow horizontal
        settings = Gtk.Settings.get_default()
        orig_font = settings.get_property("gtk-font-name")
        try:
            settings.set_property("gtk-font-name", "Sans 15")
            win.resize(1024, 600)
            self._flush_gtk(150)
            self.assertFalse(win.sidebar.get_visible())
            self.assertTrue(win.menu_btn.get_visible())
            vadj = win.scroller.get_vadjustment()
            self.assertGreater(vadj.get_upper(), 0)
            for card in win.home_page.cards_box.get_children():
                alloc = card.get_allocation()
                self.assertLessEqual(alloc.x + alloc.width, 1024)
        finally:
            settings.set_property("gtk-font-name", orig_font)
            win.destroy()
            self._flush_gtk(40)

    def test_04_legacy_hardware_zero_idle_repaints_and_tab_latency(self) -> None:
        from gi.repository import GLib, Gtk

        from mintsec_ui.window import SuiteWindow

        ctrl, _ = self._make_controller("perf")
        ctrl.config_store.update(theme_mode="light", first_run_completed=True)
        win = SuiteWindow(None, controller=ctrl, initial_width=1366, initial_height=768)
        self._flush_gtk(200)

        # Latência de troca de aba/página
        tab_latencies_ms: dict[str, float] = {}
        for page_id in ("scans", "protections", "recovery", "activity", "settings", "home"):
            t0 = time.perf_counter()
            win.navigate_to(page_id)
            while Gtk.events_pending():
                Gtk.main_iteration_do(False)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            tab_latencies_ms[page_id] = round(elapsed_ms, 2)
            self.assertLess(elapsed_ms, 300.0)

        # Estabiliza e mede repinturas durante 3.0s ociosos
        self._flush_gtk(300)
        draw_count = 0

        def _on_draw(_widget: Gtk.Widget, _cr: object) -> bool:
            nonlocal draw_count
            draw_count += 1
            return False

        handler_id = win.connect("draw", _on_draw)
        try:
            ctx = GLib.MainContext.default()
            end = time.monotonic() + 3.0
            while time.monotonic() < end:
                while ctx.pending():
                    Gtk.main_iteration_do(False)
                time.sleep(0.02)
        finally:
            win.disconnect(handler_id)

        self.assertEqual(
            draw_count,
            0,
            f"Detectadas {draw_count} repintura(s) em painel estabilizado sem eventos!",
        )
        H8UiTests.metrics["idle_repaints"] = draw_count
        H8UiTests.metrics["tab_latencies_ms"] = tab_latencies_ms
        win.destroy()
        self._flush_gtk(40)


if __name__ == "__main__":
    unittest.main()
