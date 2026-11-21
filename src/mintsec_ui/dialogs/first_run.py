"""Assistente de primeiro uso sem pré-seleção da política de contenção."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec.services.catalog import SuiteController  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.widgets import friendly_module_state_label  # noqa: E402


class FirstRunDialog(Gtk.Dialog):
    """Apresenta configuração recomendada e escolha única sem pré-seleção (Seção 3 e 5.1)."""

    def __init__(self, parent: Gtk.Window | None, controller: SuiteController) -> None:
        super().__init__(
            title=tr("first_run.title"),
            transient_for=parent,
            modal=True,
        )
        self.get_style_context().add_class("mintsec-dialog")
        self.controller = controller
        self.selected_action: str = "deferred"
        self.set_default_size(560, -1)

        defer_lbl = tr("first_run.defer_btn")
        modules_lbl = tr("first_run.modules_btn")
        apply_lbl = tr("first_run.apply_btn")
        defer_btn = self.add_button(defer_lbl, Gtk.ResponseType.CANCEL)
        modules_btn = self.add_button(modules_lbl, Gtk.ResponseType.HELP)
        apply_btn = self.add_button(apply_lbl, Gtk.ResponseType.OK)
        apply_btn.get_style_context().add_class("suggested-action")
        set_accessible(defer_btn, defer_lbl, tr("first_run.defer_desc"))
        set_accessible(modules_btn, modules_lbl, tr("first_run.modules_desc"))
        set_accessible(apply_btn, apply_lbl, tr("first_run.apply_desc"))

        area = self.get_content_area()
        area.set_spacing(12)
        area.set_margin_top(16)
        area.set_margin_bottom(12)
        area.set_margin_start(18)
        area.set_margin_end(18)

        statuses = controller.all_statuses(use_cache=True)
        summary = Gtk.Label(label=tr("first_run.summary"), xalign=0.0)
        summary.set_line_wrap(True)
        area.pack_start(summary, False, False, 0)

        pkg_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        pkg_card.get_style_context().add_class("mintsec-card")
        pkg_hdr = Gtk.Label(label=tr("first_run.pkg_hdr"), xalign=0.0)
        pkg_hdr.get_style_context().add_class("mintsec-title")
        pkg_card.pack_start(pkg_hdr, False, False, 0)

        self.chk_antimalware = Gtk.CheckButton(
            label=tr("first_run.chk_am", state=friendly_module_state_label(statuses["antimalware"].state))
        )
        self.chk_antimalware.set_sensitive(statuses["antimalware"].state != ModuleState.AUSENTE)
        self.chk_firewall = Gtk.CheckButton(
            label=tr("first_run.chk_fw", state=friendly_module_state_label(statuses["firewall"].state))
        )
        self.chk_firewall.set_sensitive(statuses["firewall"].state != ModuleState.AUSENTE)
        pkg_card.pack_start(self.chk_antimalware, False, False, 0)
        pkg_card.pack_start(self.chk_firewall, False, False, 0)
        area.pack_start(pkg_card, False, False, 0)

        # Escolha sem pré-seleção: botão âncora oculto para o grupo de rádio
        policy_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        policy_card.get_style_context().add_class("mintsec-card")
        pol_hdr = Gtk.Label(label=tr("first_run.pol_hdr"), xalign=0.0)
        pol_hdr.set_line_wrap(True)
        pol_hdr.get_style_context().add_class("mintsec-title")
        policy_card.pack_start(pol_hdr, False, False, 0)

        self._anchor_radio = Gtk.RadioButton.new_with_label(None, "_anchor")
        self._anchor_radio.set_no_show_all(True)
        self._anchor_radio.set_active(True)

        self.radio_alert_only = Gtk.RadioButton.new_with_label_from_widget(
            self._anchor_radio,
            tr("first_run.radio_alert"),
        )
        self.radio_auto_pause = Gtk.RadioButton.new_with_label_from_widget(
            self._anchor_radio,
            tr("first_run.radio_pause"),
        )
        set_accessible(
            self.radio_alert_only,
            tr("first_run.radio_alert_a11y"),
            tr("first_run.radio_alert_desc"),
        )
        set_accessible(
            self.radio_auto_pause,
            tr("first_run.radio_pause_a11y"),
            tr("first_run.radio_pause_desc"),
        )
        policy_card.pack_start(self.radio_alert_only, False, False, 0)
        policy_card.pack_start(self.radio_auto_pause, False, False, 0)
        area.pack_start(policy_card, False, False, 0)

        self.show_all()

    def selected_pause_policy(self) -> str | None:
        if self.radio_alert_only.get_active():
            return "alert_only"
        if self.radio_auto_pause.get_active():
            return "auto_pause"
        return None
