"""Testes de idioma (inglês padrão + pt_BR), página Sobre (v0.1.0 + créditos) e ícones."""

from __future__ import annotations

import os
import re
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

from PIL import Image

from mintsec import APP_NAME, __version__
from mintsec.config import ConfigStore, SuiteConfig
from mintsec_ui.i18n import TRANSLATIONS


def _pick_free_display(start: int = 92) -> tuple[int, str]:
    for disp in range(start, start + 30):
        if not Path(f"/tmp/.X{disp}-lock").exists() and not Path(f"/tmp/.X11-unix/X{disp}").exists():
            return disp, f":{disp}"
    return 118, ":118"


class I18nAndAboutTests(unittest.TestCase):
    def test_config_language_default_and_validation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            store = ConfigStore(Path(tmp) / "settings.json")
            cfg = store.load()
            self.assertEqual(cfg.language, "en")

            updated = store.update(language="pt_BR")
            self.assertEqual(updated.language, "pt_BR")
            reloaded = ConfigStore(store.path).load()
            self.assertEqual(reloaded.language, "pt_BR")

            with self.assertRaises(ValueError):
                SuiteConfig(language="fr").validate()

    def test_translation_catalog_parity_and_no_forbidden_labels(self) -> None:
        self.assertEqual(set(TRANSLATIONS.keys()), {"en", "pt_BR"})
        en_keys = set(TRANSLATIONS["en"].keys())
        pt_keys = set(TRANSLATIONS["pt_BR"].keys())
        self.assertEqual(en_keys, pt_keys)

        forbidden = re.compile(r"\b(avançad[oa]s?|simpl[ea]s?|advanced|simple)\b", re.IGNORECASE)
        for lang, catalog in TRANSLATIONS.items():
            for key, val in catalog.items():
                self.assertIsInstance(val, str)
                self.assertTrue(val.strip(), f"Empty translation for {lang}.{key}")
                self.assertIsNone(forbidden.search(val), f"Forbidden wording in {lang}.{key}: {val!r}")

    def test_multisize_app_icons_valid(self) -> None:
        assets_dir = Path(__file__).resolve().parents[1] / "src" / "mintsec_ui" / "assets"
        expected = {
            "nodusguard_icon_48.png": 48,
            "nodusguard_icon_64.png": 64,
            "nodusguard_logo.png": 128,
            "nodusguard_icon_256.png": 256,
        }
        for filename, size in expected.items():
            path = assets_dir / filename
            self.assertTrue(path.is_file(), f"Missing icon asset: {path}")
            with Image.open(path) as im:
                self.assertEqual(im.mode, "RGBA", f"Expected RGBA mode in {filename}")
                self.assertEqual(im.size, (size, size), f"Expected {(size, size)} in {filename}")
                self.assertEqual(im.getpixel((0, 0))[3], 0, f"Expected transparent corner in {filename}")

    def test_ui_language_switch_and_about_page_in_xephyr(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        disp_num, disp = _pick_free_display(92)
        xephyr = subprocess.Popen(
            ["Xephyr", disp, "-screen", "1280x800", "-ac", "-noreset"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        try:
            sock = Path(f"/tmp/.X11-unix/X{disp_num}")
            for _ in range(50):
                if sock.exists():
                    break
                time.sleep(0.1)
            self.assertTrue(sock.exists(), f"Xephyr failed to start on {disp}")

            script = textwrap.dedent(
                f"""
                import tempfile
                from pathlib import Path
                import gi

                gi.require_version("Gtk", "3.0")
                from gi.repository import GLib, Gtk

                from mintsec.auth import CallerAuthorizer
                from mintsec.config import ConfigStore
                from mintsec.history import HistoryStore
                from mintsec.incident import IncidentManager
                from mintsec.pending import PendingStore
                from mintsec.runner import CommandResult
                from mintsec.services.catalog import SuiteController
                from mintsec_ui.dialogs.paused_app import PausedAppDialog
                from mintsec_ui.window import SuiteWindow


                class _StubRunner:
                    def which(self, binary: str):
                        return f"/usr/bin/{{binary}}" if binary in ("clamscan", "ufw") else None

                    def run(self, argv, **_kwargs):
                        if argv[0] == "dpkg-query":
                            pkg = argv[-1]
                            if pkg in ("clamav", "clamav-freshclam", "ufw"):
                                return CommandResult(tuple(argv), 0, "install ok installed\\t1.0.0\\n", "")
                            return CommandResult(tuple(argv), 1, "", "not installed")
                        return CommandResult(tuple(argv), 0, "", "")


                def flush(ms=40):
                    done = False
                    def _stop():
                        nonlocal done
                        done = True
                        return False
                    GLib.timeout_add(ms, _stop)
                    while not done:
                        Gtk.main_iteration_do(True)


                def collect_labels(widget):
                    out = []
                    if isinstance(widget, Gtk.Label):
                        txt = widget.get_text()
                        if txt:
                            out.append(txt)
                    if isinstance(widget, Gtk.Container):
                        for ch in widget.get_children():
                            out.extend(collect_labels(ch))
                    return out


                with tempfile.TemporaryDirectory() as tmp:
                    root = Path(tmp)
                    ctrl = SuiteController(
                        runner=_StubRunner(),
                        config_store=ConfigStore(root / "settings.json"),
                        history_store=HistoryStore(root / "history.sqlite"),
                        pending_store=PendingStore(root / "pending.json"),
                        incident_manager=IncidentManager(root / "incidents"),
                        authorizer=CallerAuthorizer(),
                        data_dir=root / "data",
                    )
                    win = SuiteWindow(None, controller=ctrl)
                    flush(80)

                    # Default icon list registered
                    icons = Gtk.Window.get_default_icon_list()
                    assert sorted(p.get_width() for p in icons) == [48, 64, 128, 256], f"Bad icons: {{icons}}"

                    # Default English UI
                    assert win.page_title_lbl.get_text() == "Home", win.page_title_lbl.get_text()
                    assert win._sidebar_labels["protections"].get_text() == "Protections"
                    assert win._sidebar_labels["settings"].get_text() == "Settings"

                    # About tab in English
                    win.navigate_to("settings")
                    flush(40)
                    assert win.page_title_lbl.get_text() == "Settings"
                    nb = win.settings_page.notebook
                    assert nb.get_n_pages() == 3
                    assert nb.get_tab_label_text(nb.get_nth_page(2)) == "About"
                    about_texts = "\\n".join(collect_labels(win.settings_page.about_tab))
                    for required in ("{APP_NAME}", "{__version__}", "Version {__version__}", "GTK 3", "Rust", "ClamAV", "UFW", "restic", "Timeshift", "ComfyUI", "Qwen Image 2.1"):
                        assert required in about_texts, f"Missing {{required!r}} in About tab: {{about_texts}}"

                    # Live switch to Portuguese (Brazil)
                    assert win.settings_page.language_combo.set_active_id("pt_BR")
                    flush(60)
                    assert ctrl.config_store.load().language == "pt_BR"
                    assert win.page_title_lbl.get_text() == "Configurações"
                    assert win._sidebar_labels["home"].get_text() == "Início"
                    assert win._sidebar_labels["protections"].get_text() == "Proteções"
                    assert nb.get_tab_label_text(nb.get_nth_page(2)) == "Sobre"
                    about_pt = "\\n".join(collect_labels(win.settings_page.about_tab))
                    assert "Versão {__version__}" in about_pt, about_pt
                    assert "Créditos e projetos utilizados" in about_pt, about_pt

                    paused = ctrl.pending_store.create(
                        kind="paused_app",
                        module_id="recovery",
                        app_name="sim-app",
                        title="App paused",
                        summary="Canary modified.",
                        evidence="Canary",
                        fan_q_overflow=True,
                    )
                    dlg = PausedAppDialog(win, controller=ctrl, decision=paused)
                    flush(40)
                    assert dlg.restore_btn.get_label() == "Restaurar arquivos detectados…"
                    dlg.destroy()

                    # Switch back to English live
                    assert win.settings_page.language_combo.set_active_id("en")
                    flush(60)
                    assert ctrl.config_store.load().language == "en"
                    assert win.page_title_lbl.get_text() == "Settings"
                    assert win._sidebar_labels["home"].get_text() == "Home"
                    assert nb.get_tab_label_text(nb.get_nth_page(2)) == "About"

                    win.destroy()
                    flush(40)
                """
            )
            env = dict(os.environ)
            env["DISPLAY"] = disp
            env["PYTHONPATH"] = str(repo_root / "src")
            res = subprocess.run(
                [sys.executable, "-c", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(
                res.returncode,
                0,
                f"Subprocess failed (rc={res.returncode}):\nSTDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}",
            )
        finally:
            xephyr.terminate()
            try:
                xephyr.wait(timeout=5)
            except subprocess.TimeoutExpired:
                xephyr.kill()
                xephyr.wait(timeout=5)
