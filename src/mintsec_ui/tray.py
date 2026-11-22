"""Ícone e menu de contexto na bandeja do sistema (XApp / AyatanaAppIndicator3)."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Callable

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402

_log = logging.getLogger(__name__)
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"

_TRAY_FILES = {
    "ok": "nodusguard_tray_ok.png",
    "alert": "nodusguard_tray_alert.png",
    "paused": "nodusguard_tray_paused.png",
}
_TRAY_ICON_NAMES = {
    "ok": "nodusguard_tray_ok",
    "alert": "nodusguard_tray_alert",
    "paused": "nodusguard_tray_paused",
}


class NodusGuardTray:
    """Gerencia o ícone de status na bandeja e seu menu de contexto."""

    def __init__(
        self,
        *,
        on_open: Callable[[], None],
        on_pause: Callable[[], None],
        on_resume: Callable[[], None],
        on_settings: Callable[[], None],
        on_toggle_dnd: Callable[[bool], None],
        on_toggle_game_mode: Callable[[bool], None],
        on_about: Callable[[], None],
        on_quit: Callable[[], None],
    ) -> None:
        self._on_open = on_open
        self._on_pause = on_pause
        self._on_resume = on_resume
        self._on_settings = on_settings
        self._on_toggle_dnd = on_toggle_dnd
        self._on_toggle_game_mode = on_toggle_game_mode
        self._on_about = on_about
        self._on_quit = on_quit

        self._syncing = False
        self._last_health = "ok"
        self._last_paused = False
        self._last_dnd = False
        self._last_game_mode = False
        self._last_rec_count = 0
        self._last_emitted_sig: tuple[str, str, str, str] | None = None

        self.menu = Gtk.Menu()
        self.item_open = Gtk.MenuItem(label=tr("tray.open"))
        self.item_pause = Gtk.MenuItem(label=tr("tray.pause"))
        self.item_resume = Gtk.MenuItem(label=tr("tray.resume"))
        self.item_settings = Gtk.MenuItem(label=tr("tray.settings"))
        self.item_dnd = Gtk.CheckMenuItem(label=tr("tray.dnd"))
        self.item_game = Gtk.CheckMenuItem(label=tr("tray.game_mode"))
        self.item_about = Gtk.MenuItem(label=tr("tray.about"))
        self.item_quit = Gtk.MenuItem(label=tr("tray.quit"))

        self._build_menu()

        self._xapp_icon = None
        self._indicator = None
        self.active_backend = "none"
        self._init_backend()
        self.update_status("ok", paused=False, dnd=False, game_mode=False, rec_count=0)

    def _build_menu(self) -> None:
        self.item_open.connect("activate", lambda *_: self._on_open())
        self.item_pause.connect("activate", lambda *_: self._on_pause())
        self.item_resume.connect("activate", lambda *_: self._on_resume())
        self.item_settings.connect("activate", lambda *_: self._on_settings())
        self.item_dnd.connect("toggled", self._handle_dnd_toggled)
        self.item_game.connect("toggled", self._handle_game_toggled)
        self.item_about.connect("activate", lambda *_: self._on_about())
        self.item_quit.connect("activate", lambda *_: self._on_quit())

        self.menu.append(self.item_open)
        self.menu.append(Gtk.SeparatorMenuItem())
        self.menu.append(self.item_pause)
        self.menu.append(self.item_resume)
        self.menu.append(self.item_settings)
        self.menu.append(self.item_dnd)
        self.menu.append(self.item_game)
        self.menu.append(self.item_about)
        self.menu.append(Gtk.SeparatorMenuItem())
        self.menu.append(self.item_quit)

        self.menu.show_all()
        self.item_resume.set_no_show_all(True)
        self.item_resume.hide()
        self._sync_accessible_labels()

    def _sync_accessible_labels(self) -> None:
        set_accessible(self.item_open, tr("tray.open"))
        set_accessible(self.item_pause, tr("tray.pause"))
        set_accessible(self.item_resume, tr("tray.resume"))
        set_accessible(self.item_settings, tr("tray.settings"))
        set_accessible(self.item_dnd, tr("tray.dnd"))
        set_accessible(self.item_game, tr("tray.game_mode"))
        set_accessible(self.item_about, tr("tray.about"))
        set_accessible(self.item_quit, tr("tray.quit"))

    def _init_backend(self) -> None:
        if os.environ.get("MINTSEC_DISABLE_TRAY", "").strip() == "1":
            self.active_backend = "disabled"
            return

        if self._try_init_xapp():
            return
        self._try_init_ayatana()

    def _try_init_xapp(self) -> bool:
        try:
            gi.require_version("XApp", "1.0")
            from gi.repository import XApp
        except (ImportError, ValueError) as exc:
            _log.debug("XApp.StatusIcon unavailable: %s", exc)
            return False

        try:
            icon = XApp.StatusIcon()
            icon.set_name("NodusGuard")
            icon.set_secondary_menu(self.menu)
            icon.connect("activate", self._on_xapp_activate)
            icon.set_visible(True)
        except Exception as exc:  # noqa: BLE001 - falha não fatal de D-Bus/tray
            _log.debug("Failed to initialize XApp.StatusIcon: %s", exc)
            return False

        self._xapp_icon = icon
        self.active_backend = "xapp"
        return True

    def _try_init_ayatana(self) -> bool:
        try:
            gi.require_version("AyatanaAppIndicator3", "0.1")
            from gi.repository import AyatanaAppIndicator3
        except (ImportError, ValueError) as exc:
            _log.debug("AyatanaAppIndicator3 unavailable: %s", exc)
            return False

        try:
            indicator = AyatanaAppIndicator3.Indicator.new(
                "nodusguard",
                _TRAY_ICON_NAMES["ok"],
                AyatanaAppIndicator3.IndicatorCategory.APPLICATION_STATUS,
            )
            if _ASSETS_DIR.is_dir():
                indicator.set_icon_theme_path(str(_ASSETS_DIR))
            indicator.set_menu(self.menu)
            if hasattr(indicator, "set_secondary_activate_target"):
                indicator.set_secondary_activate_target(self.item_open)
            indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.ACTIVE)
        except Exception as exc:  # noqa: BLE001 - falha não fatal de D-Bus/tray
            _log.debug("Failed to initialize AyatanaAppIndicator3: %s", exc)
            return False

        self._indicator = indicator
        self.active_backend = "ayatana"
        return True

    @property
    def has_active_backend(self) -> bool:
        """Indica se há backend de bandeja ativo para ocultação ao fechar."""
        return self.active_backend in {"xapp", "ayatana"}

    def _on_xapp_activate(self, _icon: object = None, button: int = 1, _time: int = 0) -> None:
        if int(button) in (0, 1):
            self._on_open()

    def _handle_dnd_toggled(self, item: Gtk.CheckMenuItem) -> None:
        if self._syncing:
            return
        self._on_toggle_dnd(item.get_active())

    def _handle_game_toggled(self, item: Gtk.CheckMenuItem) -> None:
        if self._syncing:
            return
        self._on_toggle_game_mode(item.get_active())

    def _resolve_icon_target(self, health: str) -> tuple[str, str]:
        safe_health = health if health in _TRAY_FILES else "ok"
        icon_name = _TRAY_ICON_NAMES[safe_health]
        icon_file = _ASSETS_DIR / _TRAY_FILES[safe_health]
        icon_path = str(icon_file) if icon_file.is_file() else icon_name
        return icon_path, icon_name

    def _build_tooltip(self, health: str, rec_count: int) -> str:
        if health == "paused":
            return tr("tray.tooltip_paused")
        if health == "alert":
            return tr("tray.tooltip_alert", count=max(1, rec_count))
        return tr("tray.tooltip_ok")

    def apply_language(self) -> None:
        """Atualiza todos os rótulos do menu ao alternar idioma em runtime."""
        self.item_open.set_label(tr("tray.open"))
        self.item_pause.set_label(tr("tray.pause"))
        self.item_resume.set_label(tr("tray.resume"))
        self.item_settings.set_label(tr("tray.settings"))
        self.item_dnd.set_label(tr("tray.dnd"))
        self.item_game.set_label(tr("tray.game_mode"))
        self.item_about.set_label(tr("tray.about"))
        self.item_quit.set_label(tr("tray.quit"))
        self._sync_accessible_labels()
        self.update_status(
            self._last_health,
            paused=self._last_paused,
            dnd=self._last_dnd,
            game_mode=self._last_game_mode,
            rec_count=self._last_rec_count,
        )

    def update_status(
        self,
        health: str,
        *,
        paused: bool,
        dnd: bool,
        game_mode: bool,
        rec_count: int = 0,
    ) -> None:
        """Sincroniza ícone da bandeja, tooltip, pausa e toggles de DND/Jogo."""
        self._last_health = health
        self._last_paused = paused
        self._last_dnd = dnd
        self._last_game_mode = game_mode
        self._last_rec_count = rec_count

        self._syncing = True
        try:
            self.item_dnd.set_active(bool(dnd))
            self.item_game.set_active(bool(game_mode))
            if paused:
                self.item_resume.show()
            else:
                self.item_resume.hide()
        finally:
            self._syncing = False

        tooltip = self._build_tooltip(health, rec_count)
        icon_path, icon_name = self._resolve_icon_target(health)
        emit_sig = (health, icon_path, icon_name, tooltip)
        if emit_sig == self._last_emitted_sig:
            return
        self._last_emitted_sig = emit_sig

        if self._xapp_icon is not None:
            self._xapp_icon.set_icon_name(icon_path)
            self._xapp_icon.set_tooltip_text(tooltip)
        elif self._indicator is not None:
            self._indicator.set_icon_full(icon_name, tooltip)
            self._indicator.set_title(tooltip)

    def destroy(self) -> None:
        """Oculta e libera o ícone de bandeja no encerramento."""
        if self._xapp_icon is not None:
            try:
                self._xapp_icon.set_visible(False)
            except Exception:  # noqa: BLE001
                pass
            self._xapp_icon = None
        if self._indicator is not None:
            try:
                from gi.repository import AyatanaAppIndicator3

                self._indicator.set_status(AyatanaAppIndicator3.IndicatorStatus.PASSIVE)
            except Exception:  # noqa: BLE001
                pass
            self._indicator = None
        self.active_backend = "none"
