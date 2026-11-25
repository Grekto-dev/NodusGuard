"""Testes de isolamento de idioma garantindo zero vazamento entre EN e PT-BR na interface."""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from mintsec.formatting import format_bytes, format_confirmed_at, format_local_datetime
from mintsec_ui.i18n import localize_text, set_language


class LanguageIsolationTests(unittest.TestCase):
    def test_formatting_and_localize_text_bidirectional(self) -> None:
        self.assertEqual(format_local_datetime(None, lang="en"), "No record")
        self.assertEqual(format_local_datetime(None, lang="pt_BR"), "Sem registro")
        self.assertEqual(format_confirmed_at(None, lang="en"), "No recent confirmation")
        self.assertIn("Confirmed on ", format_confirmed_at("2026-11-25T10:30:00-03:00", lang="en"))
        self.assertEqual(format_bytes(2048, lang="en"), "2.0 KiB")
        self.assertEqual(format_bytes(2048, lang="pt_BR"), "2,0 KiB")

        set_language("en")
        self.assertEqual(localize_text("Não instalado"), "Not installed")
        self.assertEqual(localize_text("Pacote local (1.0.0)"), "Local package (1.0.0)")
        self.assertEqual(localize_text("Antivírus ativado"), "Antivirus enabled")
        self.assertEqual(localize_text("Proteção pausada (timed)"), "Protection paused (timed)")
        self.assertEqual(localize_text("Aplicativo liberado no firewall: KDE Connect"), "App allowed in firewall: KDE Connect")

        set_language("pt_BR")
        self.assertEqual(localize_text("Antivirus enabled"), "Antivírus ativado")
        self.assertEqual(localize_text("Module enabled: firewall"), "Módulo ativado: firewall")
        set_language("en")

    def test_xephyr_english_ui_zero_portuguese_leaks(self) -> None:
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
import re, tempfile, time
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

class _MockHostRunner:
    def which(self, b):
        if b in ("ufw","clamscan","freshclam","dnsmasq","restic","timeshift","nmcli","bwrap","aa-status","udisksctl","ip","ss"):
            return f"/usr/bin/{b}"
        return None
    def run(self, argv, **kw):
        n = Path(argv[0]).name
        if n == "dpkg-query":
            return CommandResult(tuple(argv), 0, "install ok installed\\t1.0\\n", "")
        if n == "ufw":
            return CommandResult(tuple(argv), 0, "Status: inactive\\n", "")
        return CommandResult(tuple(argv), 0, "", "")

def flush(ms=60):
    end = time.monotonic() + (ms / 1000.0)
    ctx = GLib.MainContext.default()
    while time.monotonic() < end:
        while ctx.pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.01)

pt_re = re.compile(
    r"[áàâãéêíóôõúçÁÀÂÃÉÊÍÓÔÕÚÇ]|\\b("
    r"Sem|Módulo|Ativo|Desativado|Falha|Varredura|Proteção|Verificação|Configuração|"
    r"Aplicativo|Regra|Confirmado|Atualização|Pausado|Retomado|Desconhecido|"
    r"Recomendação|Usuário|Sistema|Operação|Ação|Início|Não|Cópias|Navegação|"
    r"Pendrive|Histórico|Quarentena|Notificações|Sobre|às"
    r")\\b"
)

def collect_texts(widget):
    out = []
    if isinstance(widget, Gtk.Label):
        t = widget.get_text() or ""
        if t:
            out.append(t)
    elif isinstance(widget, Gtk.Button):
        t = widget.get_label() or ""
        if t:
            out.append(t)
    elif isinstance(widget, Gtk.Expander):
        t = widget.get_label() or ""
        if t:
            out.append(t)
    elif isinstance(widget, Gtk.TextView):
        buf = widget.get_buffer()
        t = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)
        if t:
            out.append(t)
    if isinstance(widget, Gtk.Container):
        for ch in widget.get_children():
            out.extend(collect_texts(ch))
    return out

with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    ctrl = SuiteController(
        config_store=ConfigStore(base / "settings.json"),
        pending_store=PendingStore(base / "pending.json"),
        history_store=HistoryStore(base / "history.db"),
        incident_manager=IncidentManager(base / "incidents"),
        runner=_MockHostRunner(),
        authorizer=CallerAuthorizer(test_decision=True),
        data_dir=base / "data",
        clamav_db_dir=base / "clamdb",
    )
    ctrl.config_store.update(first_run_completed=True, language="en")
    ctrl.enable_module("antimalware")
    ctrl.pause_protection(mode="timed", minutes=5)
    ctrl.resume_protection()

    win = SuiteWindow(None, controller=ctrl, initial_width=1280, initial_height=760)
    flush(100)

    leaks = []
    for pg in ("home", "scans", "quarantine", "protections", "recovery", "activity", "notifications", "settings"):
        win.navigate_to(pg)
        if pg == "settings":
            win.settings_page.select_tab("logs")
        flush(40)
        for txt in collect_texts(win.pages[pg]):
            if pt_re.search(txt):
                leaks.append(f"PAGE[{pg}]: {txt!r}")

    for mid in ("antimalware", "firewall", "recovery", "network", "browsing", "isolation", "rescue"):
        win.open_module_detail(mid)
        flush(40)
        for txt in collect_texts(win.module_detail_page):
            if pt_re.search(txt):
                leaks.append(f"DETAIL[{mid}]: {txt!r}")

    assert not leaks, "Portuguese text leaked into English UI:\\n" + "\\n".join(leaks)

    # Troca ao vivo para pt_BR exibe logs e páginas em português
    win.navigate_to("settings", tab="logs")
    assert win.settings_page.language_combo.set_active_id("pt_BR")
    flush(60)
    assert win.page_title_lbl.get_text() == "Configurações"
    buf = win.settings_page.logs_text_view.get_buffer()
    pt_log_txt = buf.get_text(buf.get_start_iter(), buf.get_end_iter(), True)
    assert "Proteção retomada" in pt_log_txt, pt_log_txt

    # Troca de volta para EN limpa novamente qualquer texto em português
    assert win.settings_page.language_combo.set_active_id("en")
    flush(60)
    buf_en = win.settings_page.logs_text_view.get_buffer()
    en_log_txt = buf_en.get_text(buf_en.get_start_iter(), buf_en.get_end_iter(), True)
    assert not pt_re.search(en_log_txt), en_log_txt

    win.destroy()
    flush(40)

print("XEPHYR_LANG_ISOLATION_OK")
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
            self.assertIn("XEPHYR_LANG_ISOLATION_OK", res.stdout)
        finally:
            xephyr.terminate()
            try:
                xephyr.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xephyr.kill()


if __name__ == "__main__":
    unittest.main()
