"""Página Verificações do NodusGuard: fluxo direto, ilustração editorial e quarentena."""

from __future__ import annotations

import inspect
import threading
import time
from pathlib import Path
from typing import Any

import gi

gi.require_version("Gtk", "3.0")
gi.require_version("Pango", "1.0")
from gi.repository import GLib, Gtk, Pango  # noqa: E402

from mintsec.formatting import format_bytes, format_local_datetime  # noqa: E402
from mintsec.services.antimalware import ScanResult  # noqa: E402
from mintsec_ui.a11y import relate_label, set_accessible  # noqa: E402
from mintsec_ui.animations import format_eta  # noqa: E402
from mintsec_ui.dialogs.quarantine_restore import (  # noqa: E402
    confirm_quarantine,
    restore_quarantine_interactive,
)
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    clear_container,
    make_empty_state,
    make_icon_chip,
    make_illustration,
    make_pill,
)


class ScansPage(Gtk.Box):
    """Página minimalista com abas Verificar, Agendamentos e Quarentena."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self._cancel_event: threading.Event | None = None
        self._pause_event: threading.Event | None = None
        self._paused = False
        self._scanning = False
        self._loading_post_action = False
        self._post_action_override = False
        self.post_action_countdown_secs = 10
        self._post_action_timer_id: int | None = None
        self._post_action_pending: str | None = None
        self._post_action_remaining: int = 0
        self._last_result: ScanResult | None = None
        self._last_stats: dict[str, Any] | None = None
        self._last_sched_sig: tuple[Any, ...] | None = None
        self._last_quar_sig: tuple[Any, ...] | None = None

        self.notebook = Gtk.Notebook()
        self.notebook.get_style_context().add_class("mintsec-tabs")
        self.pack_start(self.notebook, True, True, 0)

        # Aba 1: Verificar
        self.scan_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.scan_tab.set_margin_top(6)
        self.scan_tab.set_margin_bottom(12)
        self._build_scan_tab()
        self._tab_scan_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.scan_tab, self._tab_scan_lbl)

        # Aba 2: Agendamentos
        self.sched_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.sched_tab.set_margin_top(6)
        self.sched_tab.set_margin_bottom(12)
        self._build_schedules_tab()
        self._tab_sched_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.sched_tab, self._tab_sched_lbl)

        # Aba 3: Quarentena
        self.quar_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.quar_tab.set_margin_top(6)
        self.quar_tab.set_margin_bottom(12)
        self._build_quarantine_tab()
        self._tab_quar_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.quar_tab, self._tab_quar_lbl)

        self.apply_language()

    def select_tab(self, tab_name: str) -> None:
        mapping = {"scan": 0, "schedules": 1, "quarantine": 2}
        if tab_name in mapping:
            self.notebook.set_current_page(mapping[tab_name])

    def _build_scan_tab(self) -> None:
        hero_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        hero_card.get_style_context().add_class("mintsec-hero-card")

        left = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        left.set_valign(Gtk.Align.CENTER)

        self._hero_title = Gtk.Label(label="", xalign=0.0)
        self._hero_title.get_style_context().add_class("mintsec-hero-title")
        self._hero_desc = Gtk.Label(label="", xalign=0.0)
        self._hero_desc.set_line_wrap(True)
        self._hero_desc.get_style_context().add_class("mintsec-muted")
        left.pack_start(self._hero_title, False, False, 0)
        left.pack_start(self._hero_desc, False, False, 0)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.btn_quick = Gtk.Button(label="")
        self.btn_quick.get_style_context().add_class("mintsec-primary-cta")
        self.btn_quick.connect("clicked", lambda *_: self.start_scan("quick"))

        self.btn_system = Gtk.Button(label="")
        self.btn_system.connect("clicked", lambda *_: self.start_scan("system"))

        self.btn_choose = Gtk.Button(label="")
        self.btn_choose.connect("clicked", self._on_choose_path)

        self.btn_pause = Gtk.Button(label="")
        self.btn_pause.set_sensitive(False)
        self.btn_pause.set_no_show_all(True)
        self.btn_pause.connect("clicked", lambda *_: self.toggle_pause_scan())

        self.btn_cancel = Gtk.Button(label="")
        self.btn_cancel.get_style_context().add_class("destructive-action")
        self.btn_cancel.set_sensitive(False)
        self.btn_cancel.set_no_show_all(True)
        self.btn_cancel.connect("clicked", lambda *_: self.cancel_scan())

        btn_row.pack_start(self.btn_quick, False, False, 0)
        btn_row.pack_start(self.btn_system, False, False, 0)
        btn_row.pack_start(self.btn_choose, False, False, 0)
        btn_row.pack_start(self.btn_pause, False, False, 0)
        btn_row.pack_start(self.btn_cancel, False, False, 0)
        left.pack_start(btn_row, False, False, 0)

        post_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._post_action_lbl = Gtk.Label(label="", xalign=0.0)
        self._post_action_lbl.get_style_context().add_class("mintsec-muted")
        self.post_action_combo = Gtk.ComboBoxText()
        self.post_action_combo.set_size_request(190, -1)
        self.post_action_combo.connect("changed", self._on_post_action_changed)
        post_row.pack_start(self._post_action_lbl, False, False, 0)
        post_row.pack_start(self.post_action_combo, False, False, 0)
        left.pack_start(post_row, False, False, 0)

        hero_card.pack_start(left, True, True, 0)
        self._spot_art = make_illustration(
            "spot_scan.png",
            108,
            fallback_icon="system-search-symbolic",
        )
        self._spot_art.set_valign(Gtk.Align.CENTER)
        hero_card.pack_end(self._spot_art, False, False, 0)
        self.scan_tab.pack_start(hero_card, False, False, 0)

        # Card animado de progresso em tempo real (% + ETA + barra)
        self.progress_revealer = Gtk.Revealer()
        self.progress_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
        self.progress_revealer.set_transition_duration(180)
        self.progress_revealer.set_reveal_child(False)

        prog_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        prog_card.get_style_context().add_class("mintsec-card")

        prog_hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.progress_phase_lbl = Gtk.Label(label="", xalign=0.0)
        self.progress_phase_lbl.get_style_context().add_class("mintsec-subtitle")
        self.progress_pct_lbl = Gtk.Label(label="", xalign=0.0)
        self.progress_pct_lbl.get_style_context().add_class("mintsec-subtitle")
        self.progress_eta_lbl = Gtk.Label(label="", xalign=1.0)
        self.progress_eta_lbl.get_style_context().add_class("mintsec-muted")
        prog_hdr.pack_start(self.progress_phase_lbl, False, False, 0)
        prog_hdr.pack_start(self.progress_pct_lbl, True, True, 0)
        prog_hdr.pack_end(self.progress_eta_lbl, False, False, 0)
        prog_card.pack_start(prog_hdr, False, False, 0)

        self.progress_bar = Gtk.ProgressBar()
        self.progress_bar.get_style_context().add_class("mintsec-progress")
        self.progress_bar.set_show_text(False)
        prog_card.pack_start(self.progress_bar, False, False, 0)

        self.progress_path_lbl = Gtk.Label(label="", xalign=0.0)
        self.progress_path_lbl.set_ellipsize(Pango.EllipsizeMode.START)
        self.progress_path_lbl.get_style_context().add_class("mintsec-muted")
        prog_card.pack_start(self.progress_path_lbl, False, False, 0)

        self.post_action_hint_lbl = Gtk.Label(label="", xalign=0.0)
        self.post_action_hint_lbl.set_no_show_all(True)
        self.post_action_hint_lbl.get_style_context().add_class("mintsec-muted")
        prog_card.pack_start(self.post_action_hint_lbl, False, False, 0)

        self.progress_revealer.add(prog_card)
        self.scan_tab.pack_start(self.progress_revealer, False, False, 0)

        # Opções adicionais recolhidas para manter visual limpo
        self._more_exp = Gtk.Expander(label="")
        more_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        more_box.get_style_context().add_class("mintsec-card")
        more_box.set_margin_top(6)

        self._scope_note = Gtk.Label(label="", xalign=0.0)
        self._scope_note.set_line_wrap(True)
        self._scope_note.get_style_context().add_class("mintsec-muted")
        more_box.pack_start(self._scope_note, False, False, 0)

        full_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.btn_full = Gtk.Button(label="")
        self.btn_full.connect("clicked", lambda *_: self.start_scan("full"))
        full_row.pack_start(self.btn_full, False, False, 0)

        self.btn_open_quarantine = Gtk.Button(label="")
        self.btn_open_quarantine.connect("clicked", lambda *_: self.app_window.navigate_to("quarantine"))
        full_row.pack_start(self.btn_open_quarantine, False, False, 0)

        more_box.pack_start(full_row, False, False, 0)
        self._more_exp.add(more_box)
        self.scan_tab.pack_start(self._more_exp, False, False, 0)

        status_callout = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        status_callout.get_style_context().add_class("mintsec-callout")
        self.scan_status_lbl = Gtk.Label(label="", xalign=0.0)
        self.scan_status_lbl.set_line_wrap(True)
        self.scan_status_lbl.get_style_context().add_class("mintsec-muted")
        status_callout.pack_start(self.scan_status_lbl, True, True, 0)
        self.scan_tab.pack_start(status_callout, False, False, 0)

        self.post_action_revealer = Gtk.Revealer()
        self.post_action_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
        self.post_action_revealer.set_transition_duration(180)
        self.post_action_revealer.set_reveal_child(False)

        post_banner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        post_banner.get_style_context().add_class("mintsec-callout")
        post_banner.get_style_context().add_class("mintsec-callout-warn")
        self.post_action_countdown_lbl = Gtk.Label(label="", xalign=0.0)
        self.post_action_countdown_lbl.set_line_wrap(True)
        self.btn_post_now = Gtk.Button(label="")
        self.btn_post_now.get_style_context().add_class("destructive-action")
        self.btn_post_now.connect(
            "clicked",
            lambda *_: self._execute_pending_post_action(self._post_action_pending or "none"),
        )
        self.btn_post_cancel = Gtk.Button(label="")
        self.btn_post_cancel.connect(
            "clicked",
            lambda *_: self.cancel_post_action_countdown(notify_status=True),
        )
        post_banner.pack_start(self.post_action_countdown_lbl, True, True, 0)
        post_banner.pack_start(self.btn_post_now, False, False, 0)
        post_banner.pack_start(self.btn_post_cancel, False, False, 0)
        self.post_action_revealer.add(post_banner)
        self.scan_tab.pack_start(self.post_action_revealer, False, False, 0)

        self.result_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.scan_tab.pack_start(self.result_box, False, False, 0)

    def _build_schedules_tab(self) -> None:
        form_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        form_card.get_style_context().add_class("mintsec-card")

        self._sched_title = Gtk.Label(label="", xalign=0.0)
        self._sched_title.get_style_context().add_class("mintsec-section-title")
        self._sched_sub = Gtk.Label(label="", xalign=0.0)
        self._sched_sub.get_style_context().add_class("mintsec-muted")
        form_card.pack_start(self._sched_title, False, False, 0)
        form_card.pack_start(self._sched_sub, False, False, 0)

        form = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)

        self.sched_scope = Gtk.ComboBoxText()
        self.sched_freq = Gtk.ComboBoxText()

        self._sched_add_btn = Gtk.Button(label="")
        self._sched_add_btn.get_style_context().add_class("mintsec-primary-cta")
        self._sched_add_btn.connect("clicked", self._on_save_schedule)

        form.pack_start(self.sched_scope, True, True, 0)
        form.pack_start(self.sched_freq, False, False, 0)
        form.pack_start(self._sched_add_btn, False, False, 0)
        form_card.pack_start(form, False, False, 0)
        self.sched_tab.pack_start(form_card, False, False, 0)

        self.sched_list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.sched_tab.pack_start(self.sched_list_box, False, False, 0)

    def _build_quarantine_tab(self) -> None:
        self.quar_list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.quar_tab.pack_start(self.quar_list_box, False, False, 0)

    def apply_language(self) -> None:
        self._tab_scan_lbl.set_text(tr("scans.tab_scan"))
        self._tab_sched_lbl.set_text(tr("scans.tab_schedules"))
        self._tab_quar_lbl.set_text(tr("scans.tab_quarantine"))

        self._hero_title.set_text(tr("scans.hero_title"))
        self._hero_desc.set_text(tr("scans.hero_desc"))
        quick_lbl = tr("scans.btn_quick")
        self.btn_quick.set_label(quick_lbl)
        set_accessible(self.btn_quick, quick_lbl, tr("scans.btn_quick_desc"))
        sys_lbl = tr("scans.btn_system")
        self.btn_system.set_label(sys_lbl)
        set_accessible(self.btn_system, sys_lbl, tr("scans.btn_system_desc"))
        self.btn_choose.set_label(tr("scans.btn_choose"))
        set_accessible(self.btn_choose, tr("scans.btn_choose_a11y"), tr("scans.btn_choose_desc"))
        self._update_pause_button_ui()
        self.btn_cancel.set_label(tr("common.cancel"))
        set_accessible(self.btn_cancel, tr("scans.btn_cancel_a11y"), tr("scans.btn_cancel_desc"))
        set_accessible(self._spot_art, tr("scans.spot_a11y"), tr("scans.spot_a11y"))

        self._loading_post_action = True
        try:
            default_action = self.app_window.controller.config_store.load().default_scan_post_action
            cur_action = self.post_action_combo.get_active_id() or default_action
            self.post_action_combo.remove_all()
            self.post_action_combo.append("none", tr("scans.post_none"))
            self.post_action_combo.append("suspend", tr("scans.post_suspend"))
            self.post_action_combo.append("shutdown", tr("scans.post_shutdown"))
            self.post_action_combo.set_active_id(cur_action if cur_action in {"none", "suspend", "shutdown"} else "none")
            self._post_action_lbl.set_text(tr("scans.post_action_label"))
            relate_label(self._post_action_lbl, self.post_action_combo)
            set_accessible(self.post_action_combo, tr("scans.post_action_a11y"), tr("scans.post_action_desc"))
        finally:
            self._loading_post_action = False

        self.btn_post_now.set_label(tr("scans.post_now_btn"))
        set_accessible(self.btn_post_now, tr("scans.post_now_a11y"), tr("scans.post_now_desc"))
        self.btn_post_cancel.set_label(tr("scans.post_cancel_btn"))
        set_accessible(self.btn_post_cancel, tr("scans.post_cancel_a11y"), tr("scans.post_cancel_desc"))
        self._update_post_action_hint()
        if self._post_action_pending is not None:
            self._update_countdown_label()

        self._more_exp.set_label(tr("scans.more_expander"))
        set_accessible(self._more_exp, tr("scans.more_expander"), tr("scans.more_expander_desc"))
        self._scope_note.set_text(tr("scans.scope_note"))
        self.btn_full.set_label(tr("scans.btn_full"))
        set_accessible(self.btn_full, tr("scans.btn_full_a11y"), tr("scans.btn_full_desc"))
        self.btn_open_quarantine.set_label(tr("scans.btn_quarantine_page"))
        set_accessible(self.btn_open_quarantine, tr("scans.btn_quarantine_page"))

        if self._scanning and self._last_stats is not None:
            self._apply_stats_ui(self._last_stats)
        elif not self._scanning and self._last_result is None:
            self.scan_status_lbl.set_text(tr("scans.status_idle"))
        elif self._last_result is not None and not self._scanning:
            self._render_scan_result(self._last_result)

        self._sched_title.set_text(tr("scans.sched_title"))
        self._sched_sub.set_text(tr("scans.sched_sub"))

        scope_id = self.sched_scope.get_active_id() or "quick"
        self.sched_scope.remove_all()
        self.sched_scope.append("quick", tr("scans.scope_quick"))
        self.sched_scope.append("full", tr("scans.scope_full"))
        self.sched_scope.append("system", tr("scans.scope_system_short"))
        self.sched_scope.set_active_id(scope_id)
        set_accessible(self.sched_scope, tr("scans.scope_a11y"), tr("scans.scope_desc"))

        freq_id = self.sched_freq.get_active_id() or "weekly"
        self.sched_freq.remove_all()
        self.sched_freq.append("6h", tr("scans.freq_6h"))
        self.sched_freq.append("12h", tr("scans.freq_12h"))
        self.sched_freq.append("daily", tr("scans.freq_daily"))
        self.sched_freq.append("weekly", tr("scans.freq_weekly"))
        self.sched_freq.append("monthly", tr("scans.freq_monthly"))
        self.sched_freq.set_active_id(freq_id)
        set_accessible(self.sched_freq, tr("scans.freq_a11y"), tr("scans.freq_desc"))

        self._sched_add_btn.set_label(tr("scans.sched_add_btn"))
        set_accessible(self._sched_add_btn, tr("scans.sched_add_a11y"), tr("scans.sched_add_desc"))

        self._last_sched_sig = None
        self._last_quar_sig = None

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        if not self._scanning and self._post_action_pending is None and not self._post_action_override:
            default_action = self.app_window.controller.config_store.load().default_scan_post_action
            self._set_post_action_combo(default_action)
        self._refresh_schedules()
        self._refresh_quarantine()

    def get_selected_post_action(self) -> str:
        val = self.post_action_combo.get_active_id() or "none"
        return val if val in {"none", "suspend", "shutdown"} else "none"

    def _set_post_action_combo(self, action: str) -> None:
        clean = action if action in {"none", "suspend", "shutdown"} else "none"
        if self.post_action_combo.get_active_id() == clean:
            return
        self._loading_post_action = True
        try:
            self.post_action_combo.set_active_id(clean)
        finally:
            self._loading_post_action = False
        self._update_post_action_hint()

    def sync_default_post_action(self, default_action: str) -> None:
        """Sincroniza dropdown quando padrão muda em Configurações."""
        if self._scanning and self._post_action_override:
            return
        self._post_action_override = False
        self._set_post_action_combo(default_action)

    def _update_post_action_hint(self) -> None:
        action = self.get_selected_post_action()
        if self._scanning and action == "suspend":
            self.post_action_hint_lbl.set_text(tr("scans.post_hint_suspend"))
            self.post_action_hint_lbl.show()
        elif self._scanning and action == "shutdown":
            self.post_action_hint_lbl.set_text(tr("scans.post_hint_shutdown"))
            self.post_action_hint_lbl.show()
        else:
            self.post_action_hint_lbl.set_text("")
            self.post_action_hint_lbl.hide()

    def _on_post_action_changed(self, *_args: object) -> None:
        if self._loading_post_action:
            return
        self._post_action_override = True
        action = self.get_selected_post_action()
        self._update_post_action_hint()
        if self._post_action_pending is not None:
            if action == "none":
                self.cancel_post_action_countdown(notify_status=True)
            else:
                self._post_action_pending = action
                self._update_countdown_label()

    def _update_pause_button_ui(self) -> None:
        if self._paused:
            self.btn_pause.set_label(tr("scans.btn_resume"))
            set_accessible(self.btn_pause, tr("scans.btn_resume_a11y"), tr("scans.btn_resume_desc"))
        else:
            self.btn_pause.set_label(tr("scans.btn_pause"))
            set_accessible(self.btn_pause, tr("scans.btn_pause_a11y"), tr("scans.btn_pause_desc"))

    def _refresh_schedules(self) -> None:
        lang = self.app_window.controller.config_store.load().language
        schedules = self.app_window.controller.antimalware.list_schedules()
        sig = (lang, tuple((s["schedule_id"], s["scope"], s["frequency"]) for s in schedules))
        if sig == self._last_sched_sig:
            return
        self._last_sched_sig = sig

        clear_container(self.sched_list_box)
        if not schedules:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "system-search-symbolic",
                    tr("scans.sched_empty_title"),
                    tr("scans.sched_empty_sub"),
                ),
                False,
                False,
                0,
            )
            self.sched_list_box.pack_start(empty, False, False, 0)
        else:
            scope_labels = {
                "quick": tr("scans.sched_scope_quick_short"),
                "full": tr("scans.sched_scope_full_short"),
                "system": tr("scans.scope_system_short"),
            }
            freq_labels = {
                "6h": tr("scans.freq_6h"),
                "12h": tr("scans.freq_12h"),
                "daily": tr("scans.freq_daily"),
                "weekly": tr("scans.freq_weekly"),
                "monthly": tr("scans.freq_monthly"),
            }
            for item in schedules:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                row.get_style_context().add_class("mintsec-card")
                row.pack_start(make_icon_chip("system-search-symbolic", pixel_size=18, tone="ok"), False, False, 0)

                info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                scope_txt = scope_labels.get(item["scope"], item["scope"])
                freq_txt = freq_labels.get(item["frequency"], item["frequency"]).lower()
                t_lbl = Gtk.Label(label=tr("scans.sched_item_title", scope=scope_txt), xalign=0.0)
                t_lbl.get_style_context().add_class("mintsec-subtitle")
                m_lbl = Gtk.Label(label=tr("scans.sched_item_sub", freq=freq_txt), xalign=0.0)
                m_lbl.get_style_context().add_class("mintsec-muted")
                info.pack_start(t_lbl, False, False, 0)
                info.pack_start(m_lbl, False, False, 0)

                rm_btn = Gtk.Button(label=tr("common.remove"))
                rm_btn.get_style_context().add_class("mintsec-ghost-btn")
                set_accessible(
                    rm_btn,
                    tr("scans.sched_rm_a11y", sid=item["schedule_id"]),
                    tr("scans.sched_rm_desc"),
                )
                rm_btn.connect(
                    "clicked",
                    lambda _b, sid=item["schedule_id"]: self._on_remove_schedule(sid),
                )
                row.pack_start(info, True, True, 0)
                row.pack_start(make_pill(tr("common.active"), tone="ok"), False, False, 0)
                row.pack_start(rm_btn, False, False, 0)
                self.sched_list_box.pack_start(row, False, False, 0)
        self.sched_list_box.show_all()

    def _refresh_quarantine(self) -> None:
        lang = self.app_window.controller.config_store.load().language
        items = self.app_window.controller.antimalware.list_quarantine()
        sig = (lang, tuple((it.item_id, it.quarantined_at, it.size_bytes) for it in items))
        if sig == self._last_quar_sig:
            return
        self._last_quar_sig = sig

        clear_container(self.quar_list_box)
        if not items:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "security-high-symbolic",
                    tr("scans.quar_empty_title"),
                    tr("scans.quar_empty_sub"),
                    illustration="spot_calm.png",
                    illustration_size=88,
                ),
                False,
                False,
                0,
            )
            self.quar_list_box.pack_start(empty, False, False, 0)
        else:
            for item in items:
                card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                card.get_style_context().add_class("mintsec-card")
                card.pack_start(make_icon_chip("security-low-symbolic", pixel_size=18, tone="warn"), False, False, 0)

                info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
                t_lbl = Gtk.Label(label=f"{Path(item.original_path).name} — {item.detection_name}", xalign=0.0)
                t_lbl.get_style_context().add_class("mintsec-subtitle")
                m_lbl = Gtk.Label(
                    label=tr(
                        "scans.quar_meta",
                        path=item.original_path,
                        date=format_local_datetime(item.quarantined_at),
                        size=format_bytes(item.size_bytes),
                    ),
                    xalign=0.0,
                )
                m_lbl.set_line_wrap(True)
                m_lbl.get_style_context().add_class("mintsec-muted")
                info.pack_start(t_lbl, False, False, 0)
                info.pack_start(m_lbl, False, False, 0)

                restore_btn = Gtk.Button(label=tr("scans.quar_restore_btn"))
                restore_btn.set_valign(Gtk.Align.CENTER)
                set_accessible(
                    restore_btn,
                    tr("scans.quar_restore_a11y", name=Path(item.original_path).name),
                    tr("scans.quar_restore_desc"),
                )
                restore_btn.connect("clicked", lambda _b, it=item: self._on_restore_item(it))
                card.pack_start(info, True, True, 0)
                card.pack_start(restore_btn, False, False, 0)
                self.quar_list_box.pack_start(card, False, False, 0)
        self.quar_list_box.show_all()

    def _on_choose_path(self, *_args: object) -> None:
        chooser = Gtk.FileChooserDialog(
            title=tr("scans.choose_title"),
            transient_for=self.app_window,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        chooser.add_buttons(
            tr("common.cancel"),
            Gtk.ResponseType.CANCEL,
            tr("scans.choose_ok"),
            Gtk.ResponseType.OK,
        )
        if chooser.run() == Gtk.ResponseType.OK and chooser.get_filename():
            chosen = chooser.get_filename()
            chooser.destroy()
            self.start_scan("custom", custom_paths=[chosen])
            return
        chooser.destroy()

    def start_scan(self, scope: str, custom_paths: list[str] | None = None) -> None:
        if self._scanning:
            return
        service = self.app_window.controller.antimalware
        if service.runner.which("clamscan") is None:
            self.scan_status_lbl.set_text(tr("scans.not_installed_status"))
            self._render_scan_error(tr("scans.not_installed_err"))
            return

        self.cancel_post_action_countdown()
        self._scanning = True
        self._paused = False
        self._last_stats = None
        self._cancel_event = threading.Event()
        self._pause_event = threading.Event()
        self._update_pause_button_ui()
        self.btn_pause.set_sensitive(True)
        self.btn_pause.show()
        self.btn_cancel.set_sensitive(True)
        self.btn_cancel.show()
        self._update_post_action_hint()
        self.progress_bar.set_fraction(0.0)
        self.progress_phase_lbl.set_text(tr("scans.phase_counting"))
        self.progress_pct_lbl.set_text("0%")
        self.progress_eta_lbl.set_text(
            tr("scans.eta_label", eta=tr("scans.eta_calculating"))
        )
        self.progress_path_lbl.set_text("")
        self.progress_revealer.set_reveal_child(True)
        self.scan_status_lbl.set_text(tr("scans.running_status", count=0))
        self.app_window.set_active_scan_banner(True, tr("scans.running_banner", count=0))

        try:
            sig = inspect.signature(service.run_scan)
            accepts_pause = any(
                p.kind == inspect.Parameter.VAR_KEYWORD or p.name == "pause_event"
                for p in sig.parameters.values()
            )
        except (TypeError, ValueError):
            accepts_pause = False

        pause_ev = self._pause_event
        cancel_ev = self._cancel_event

        def _worker() -> None:
            last_emit = [0.0]
            last_phase = [""]
            saw_stats = [False]
            try:
                def _prog(count: int, _line: str) -> None:
                    if saw_stats[0]:
                        return
                    now = time.monotonic()
                    if count <= 1 or (now - last_emit[0]) >= 0.12:
                        last_emit[0] = now
                        GLib.idle_add(self._on_scan_progress, count)

                def _stats(stats: dict[str, Any]) -> None:
                    saw_stats[0] = True
                    now = time.monotonic()
                    phase = str(stats.get("phase", ""))
                    if (
                        phase != last_phase[0]
                        or phase == "paused"
                        or (now - last_emit[0]) >= 0.12
                        or phase == "done"
                    ):
                        last_phase[0] = phase
                        last_emit[0] = now
                        GLib.idle_add(self._on_scan_stats, dict(stats))

                scan_kwargs: dict[str, Any] = {
                    "scope": scope,
                    "paths": custom_paths,
                    "on_progress": _prog,
                    "on_stats": _stats,
                    "cancel_event": cancel_ev,
                }
                if accepts_pause:
                    scan_kwargs["pause_event"] = pause_ev
                res = service.run_scan(**scan_kwargs)
                GLib.idle_add(self._on_scan_finished, res, None)
            except Exception as exc:
                GLib.idle_add(self._on_scan_finished, None, str(exc))

        threading.Thread(target=_worker, daemon=True).start()

    def toggle_pause_scan(self) -> None:
        if not self._scanning or self._pause_event is None:
            return
        self._paused = not self._paused
        if self._paused:
            self._pause_event.set()
            self.progress_phase_lbl.set_text(tr("scans.phase_paused"))
            self.progress_eta_lbl.set_text(tr("scans.eta_paused"))
            pct = float((self._last_stats or {}).get("percent", 0.0))
            paused_msg = tr("scans.paused_banner", pct=pct)
            self.scan_status_lbl.set_text(paused_msg)
            self.app_window.set_active_scan_banner(True, paused_msg)
        else:
            self._pause_event.clear()
            if self._last_stats is not None:
                self._apply_stats_ui({**self._last_stats, "phase": "scanning"})
            else:
                self.progress_phase_lbl.set_text(tr("scans.phase_scanning"))
        self._update_pause_button_ui()

    def cancel_scan(self) -> None:
        if self._cancel_event is not None:
            self._paused = False
            if self._pause_event is not None:
                self._pause_event.clear()
            self.btn_pause.set_sensitive(False)
            self._update_pause_button_ui()
            self._cancel_event.set()
            if self._scanning:
                self.progress_phase_lbl.set_text(tr("scans.phase_cancelling"))

    def _apply_stats_ui(self, stats: dict[str, Any]) -> None:
        phase = str(stats.get("phase", "scanning"))
        cancelling = self._cancel_event is not None and self._cancel_event.is_set()
        paused = (phase == "paused" or self._paused) and not cancelling
        if cancelling or phase == "cancelled":
            self.progress_phase_lbl.set_text(tr("scans.phase_cancelling"))
        elif paused:
            self.progress_phase_lbl.set_text(tr("scans.phase_paused"))
        elif phase == "counting":
            self.progress_phase_lbl.set_text(tr("scans.phase_counting"))
        else:
            self.progress_phase_lbl.set_text(tr("scans.phase_scanning"))

        pct = float(stats.get("percent", 0.0))
        scanned = int(stats.get("items_scanned", 0))
        total = int(stats.get("total_estimated", 0))
        exact = bool(stats.get("exact_total"))
        eta_txt = format_eta(stats.get("eta_seconds"))
        cur_path = str(stats.get("current_path") or "")

        if phase == "counting" and not paused:
            self.progress_bar.pulse()
        else:
            self.progress_bar.set_fraction(max(0.0, min(1.0, pct / 100.0)))

        if exact and total > 0:
            pct_line = tr("scans.progress_exact", pct=pct, scanned=scanned, total=total)
        else:
            pct_line = tr("scans.progress_approx", pct=pct, scanned=scanned)
        self.progress_pct_lbl.set_text(pct_line)
        self.progress_eta_lbl.set_text(
            tr("scans.eta_paused") if paused else tr("scans.eta_label", eta=eta_txt)
        )
        self.progress_path_lbl.set_text(cur_path)

        if paused:
            banner_txt = tr("scans.paused_banner", pct=pct)
        else:
            banner_path = Path(cur_path).name if cur_path else "…"
            banner_txt = tr("scans.running_banner_eta", pct=pct, eta=eta_txt, path=banner_path)
        self.scan_status_lbl.set_text(banner_txt)
        self.app_window.set_active_scan_banner(True, banner_txt)

    def _on_scan_stats(self, stats: dict[str, Any]) -> bool:
        if self.app_window._destroyed or not self._scanning:
            return False
        self._last_stats = stats
        self._apply_stats_ui(stats)
        return False

    def _on_scan_progress(self, count: int) -> bool:
        if self.app_window._destroyed or not self._scanning:
            return False
        self.progress_phase_lbl.set_text(tr("scans.phase_paused") if self._paused else tr("scans.phase_scanning"))
        self.progress_pct_lbl.set_text(tr("scans.progress_approx", pct=0.0, scanned=count))
        msg = tr("scans.paused_banner", pct=0.0) if self._paused else tr("scans.running_banner", count=count)
        self.scan_status_lbl.set_text(msg)
        self.app_window.set_active_scan_banner(True, msg)
        return False

    def _update_countdown_label(self) -> None:
        if self._post_action_pending == "suspend":
            self.post_action_countdown_lbl.set_text(
                tr("scans.post_countdown_suspend", secs=self._post_action_remaining)
            )
        elif self._post_action_pending == "shutdown":
            self.post_action_countdown_lbl.set_text(
                tr("scans.post_countdown_shutdown", secs=self._post_action_remaining)
            )

    def cancel_post_action_countdown(self, *, notify_status: bool = False) -> None:
        if self._post_action_timer_id is not None:
            GLib.source_remove(self._post_action_timer_id)
            self._post_action_timer_id = None
        was_pending = self._post_action_pending is not None
        self._post_action_pending = None
        self._post_action_remaining = 0
        self.post_action_revealer.set_reveal_child(False)
        if notify_status and was_pending:
            self.scan_status_lbl.set_text(tr("scans.post_cancelled_note"))

    def _start_post_action_countdown(self, action: str) -> None:
        if action not in {"suspend", "shutdown"}:
            return
        secs = int(self.post_action_countdown_secs)
        if secs <= 0:
            self._execute_pending_post_action(action)
            return
        self.cancel_post_action_countdown()
        self._post_action_pending = action
        self._post_action_remaining = secs
        self._update_countdown_label()
        self.post_action_revealer.set_reveal_child(True)
        self._post_action_timer_id = GLib.timeout_add_seconds(1, self._on_post_action_tick)

    def _on_post_action_tick(self) -> bool:
        if self.app_window._destroyed or self._post_action_pending is None:
            self._post_action_timer_id = None
            return False
        self._post_action_remaining -= 1
        if self._post_action_remaining <= 0:
            action = self._post_action_pending
            self._post_action_timer_id = None
            self._execute_pending_post_action(action)
            return False
        self._update_countdown_label()
        return True

    def _execute_pending_post_action(self, action: str) -> None:
        self.cancel_post_action_countdown()
        default_action = self.app_window.controller.config_store.load().default_scan_post_action
        self._post_action_override = False
        self._set_post_action_combo(default_action)
        if action not in {"suspend", "shutdown"}:
            return
        try:
            res = self.app_window.controller.execute_post_scan_action(action)
            if not res.get("ok"):
                err = str(res.get("error") or tr("scans.unknown_err"))
                self._render_scan_error(tr("scans.post_failed_err", err=err))
        except Exception as exc:  # noqa: BLE001
            self._render_scan_error(tr("scans.post_failed_err", err=str(exc)))

    def _on_scan_finished(self, result: ScanResult | None, err: str | None) -> bool:
        if self.app_window._destroyed:
            return False
        selected_post_action = self.get_selected_post_action()
        self._scanning = False
        self._paused = False
        self._pause_event = None
        self._last_stats = None
        self._post_action_override = False
        self.btn_pause.set_sensitive(False)
        self.btn_pause.hide()
        self._update_pause_button_ui()
        self.btn_cancel.set_sensitive(False)
        self.btn_cancel.hide()
        self.progress_revealer.set_reveal_child(False)
        self._update_post_action_hint()
        self.app_window.set_active_scan_banner(False, "")
        if err is not None or result is None:
            self.scan_status_lbl.set_text(tr("scans.failed_status", err=err))
            self._render_scan_error(err or tr("scans.unknown_err"))
            return False

        self._last_result = result
        summary = tr("scans.done_status", items=result.items_scanned, detections=len(result.detections))
        if result.incomplete:
            summary = tr(
                "scans.incomplete_status",
                items=result.items_scanned,
                unverified=len(result.unverified_items),
            )
        self.scan_status_lbl.set_text(summary)
        self._render_scan_result(result)
        self.app_window.refresh_all(force=True)
        if (
            not result.cancelled
            and result.error_message is None
            and selected_post_action in {"suspend", "shutdown"}
        ):
            self._start_post_action_countdown(selected_post_action)
        return False

    def _render_scan_error(self, msg: str) -> None:
        clear_container(self.result_box)
        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        card.get_style_context().add_class("mintsec-callout")
        card.get_style_context().add_class("mintsec-callout-warn")
        lbl = Gtk.Label(label=msg, xalign=0.0)
        lbl.set_line_wrap(True)
        card.pack_start(lbl, True, True, 0)
        self.result_box.pack_start(card, False, False, 0)
        self.result_box.show_all()

    def _render_scan_result(self, result: ScanResult) -> None:
        clear_container(self.result_box)

        if result.unverified_items:
            unv_btn = Gtk.Button(label=tr("scans.unverified_btn", count=len(result.unverified_items)))
            set_accessible(
                unv_btn,
                tr("scans.unverified_a11y"),
                tr("scans.unverified_desc"),
            )
            unv_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            unv_list.get_style_context().add_class("mintsec-card")
            unv_list.set_no_show_all(True)
            for item in result.unverified_items[:25]:
                lbl = Gtk.Label(label=f"{item['path']} — {item['reason']}", xalign=0.0)
                lbl.set_line_wrap(True)
                lbl.get_style_context().add_class("mintsec-muted")
                unv_list.pack_start(lbl, False, False, 0)

            def _toggle(_b: Gtk.Button) -> None:
                if unv_list.get_visible():
                    unv_list.hide()
                else:
                    unv_list.show_all()

            unv_btn.connect("clicked", _toggle)
            self.result_box.pack_start(unv_btn, False, False, 0)
            self.result_box.pack_start(unv_list, False, False, 0)

        for finding in result.detections:
            card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            card.get_style_context().add_class("mintsec-card")
            card.pack_start(make_icon_chip("security-low-symbolic", pixel_size=18, tone="crit"), False, False, 0)
            lbl = Gtk.Label(
                label=f"{Path(finding.path).name} — {finding.detection_name}",
                xalign=0.0,
            )
            lbl.set_line_wrap(True)
            rev_btn = Gtk.Button(label=tr("scans.review_btn"))
            rev_btn.get_style_context().add_class("mintsec-primary-cta")
            set_accessible(
                rev_btn,
                tr("scans.review_a11y", name=Path(finding.path).name),
                tr("scans.review_desc"),
            )
            rev_btn.connect("clicked", lambda _b, f=finding: self._on_review_finding(f))
            card.pack_start(lbl, True, True, 0)
            card.pack_start(rev_btn, False, False, 0)
            self.result_box.pack_start(card, False, False, 0)

        self.result_box.show_all()

    def _on_review_finding(self, finding: Any) -> None:
        if confirm_quarantine(
            self.app_window,
            file_path=finding.path,
            detection_name=finding.detection_name,
        ):
            self.app_window.controller.antimalware.quarantine_file(
                finding.path,
                detection_name=finding.detection_name,
                confirmed=True,
                pending_id=finding.pending_id,
            )
            self.select_tab("quarantine")
            self.app_window.refresh_all(force=False)

    def _on_restore_item(self, item: Any) -> None:
        restored = restore_quarantine_interactive(
            self.app_window,
            service=self.app_window.controller.antimalware,
            item=item,
        )
        if restored is not None:
            self.scan_status_lbl.set_text(tr("scans.restored_status", path=restored))
            self.app_window.refresh_all(force=False)

    def _on_save_schedule(self, *_args: object) -> None:
        scope = self.sched_scope.get_active_id() or "quick"
        freq = self.sched_freq.get_active_id() or "weekly"
        self.app_window.controller.antimalware.save_schedule(
            schedule_id="padrao",
            scope=scope,
            frequency=freq,
        )
        self.app_window.refresh_all(force=False)

    def _on_remove_schedule(self, schedule_id: str) -> None:
        self.app_window.controller.antimalware.remove_schedule(schedule_id)
        self.app_window.refresh_all(force=False)
