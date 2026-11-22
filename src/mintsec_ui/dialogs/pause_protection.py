"""Diálogo modal para escolher duração ou modo de pausa da proteção."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402

PAUSE_DURATION_OPTIONS: tuple[tuple[str, str], ...] = (
    ("1", "pause_dlg.dur_1m"),
    ("3", "pause_dlg.dur_3m"),
    ("5", "pause_dlg.dur_5m"),
    ("15", "pause_dlg.dur_15m"),
    ("30", "pause_dlg.dur_30m"),
    ("60", "pause_dlg.dur_60m"),
    ("180", "pause_dlg.dur_180m"),
    ("300", "pause_dlg.dur_300m"),
)


class PauseProtectionDialog(Gtk.Dialog):
    """Popup com opções de pausa temporária, até reinício ou manual."""

    def __init__(self, parent: Gtk.Window | None = None) -> None:
        super().__init__(
            title=tr("pause_dlg.title"),
            transient_for=parent,
            modal=True,
        )
        self.get_style_context().add_class("mintsec-dialog")
        self.set_default_size(460, -1)
        self.set_resizable(False)

        self.cancel_btn = self.add_button(tr("pause_dlg.cancel"), Gtk.ResponseType.CANCEL)
        self.confirm_btn = self.add_button(tr("pause_dlg.confirm"), Gtk.ResponseType.OK)
        self.confirm_btn.get_style_context().add_class("suggested-action")
        set_accessible(self.cancel_btn, tr("pause_dlg.cancel"))
        set_accessible(self.confirm_btn, tr("pause_dlg.confirm"))

        area = self.get_content_area()
        area.set_spacing(12)
        area.set_margin_top(16)
        area.set_margin_bottom(12)
        area.set_margin_start(18)
        area.set_margin_end(18)

        subtitle = Gtk.Label(label=tr("pause_dlg.subtitle"), xalign=0.0)
        subtitle.set_line_wrap(True)
        subtitle.get_style_context().add_class("mintsec-muted")
        area.pack_start(subtitle, False, False, 0)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.get_style_context().add_class("mintsec-card")

        timed_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.radio_timed = Gtk.RadioButton.new_with_label_from_widget(
            None,
            tr("pause_dlg.mode_for"),
        )
        set_accessible(
            self.radio_timed,
            tr("pause_dlg.mode_for"),
            tr("pause_dlg.mode_for_a11y"),
        )
        self.radio_timed.connect("toggled", self._on_mode_toggled)
        timed_row.pack_start(self.radio_timed, False, False, 0)

        self.duration_combo = Gtk.ComboBoxText()
        for minutes_id, key in PAUSE_DURATION_OPTIONS:
            self.duration_combo.append(minutes_id, tr(key))
        self.duration_combo.set_active_id("15")
        self.duration_combo.set_hexpand(True)
        set_accessible(
            self.duration_combo,
            tr("pause_dlg.duration_a11y"),
            tr("pause_dlg.mode_for_a11y"),
        )
        timed_row.pack_start(self.duration_combo, True, True, 0)
        card.pack_start(timed_row, False, False, 0)

        self.radio_restart = Gtk.RadioButton.new_with_label_from_widget(
            self.radio_timed,
            tr("pause_dlg.mode_restart"),
        )
        set_accessible(self.radio_restart, tr("pause_dlg.mode_restart"))
        self.radio_restart.connect("toggled", self._on_mode_toggled)
        card.pack_start(self.radio_restart, False, False, 0)

        self.radio_indefinite = Gtk.RadioButton.new_with_label_from_widget(
            self.radio_timed,
            tr("pause_dlg.mode_indefinite"),
        )
        set_accessible(self.radio_indefinite, tr("pause_dlg.mode_indefinite"))
        self.radio_indefinite.connect("toggled", self._on_mode_toggled)
        card.pack_start(self.radio_indefinite, False, False, 0)

        area.pack_start(card, False, False, 0)
        self._sync_combo_sensitivity()
        self.show_all()

    def _on_mode_toggled(self, _btn: Gtk.RadioButton) -> None:
        self._sync_combo_sensitivity()

    def _sync_combo_sensitivity(self) -> None:
        self.duration_combo.set_sensitive(self.radio_timed.get_active())

    def get_selection(self) -> tuple[str, int | None]:
        """Retorna ``(mode, minutes)`` escolhido pelo usuário."""
        if self.radio_restart.get_active():
            return ("until_restart", None)
        if self.radio_indefinite.get_active():
            return ("indefinite", None)
        raw_id = self.duration_combo.get_active_id() or "15"
        try:
            minutes = int(raw_id)
        except ValueError:
            minutes = 15
        return ("timed", minutes)

    def get_selected_duration_label(self) -> str | None:
        """Retorna rótulo legível da duração selecionada quando em modo timed."""
        mode, _minutes = self.get_selection()
        if mode != "timed":
            return None
        return self.duration_combo.get_active_text()
