"""Página Configurações em Flat Design: Aparência, Alertas e Opções de Proteção."""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec import APP_NAME, __version__  # noqa: E402
from mintsec_ui.a11y import relate_label, set_accessible  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import get_language, localize_log_entry, tr  # noqa: E402
from mintsec_ui.widgets import clear_container, make_illustration, make_pill  # noqa: E402


def _make_pref_row(
    title: str,
    subtitle: str,
    control: Gtk.Widget,
) -> tuple[Gtk.Box, Gtk.Label, Gtk.Label]:
    """Linha de preferência limpa: título e explicação à esquerda, controle à direita."""
    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=16)
    row.set_margin_top(6)
    row.set_margin_bottom(6)

    txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
    t_lbl = Gtk.Label(label=title, xalign=0.0)
    t_lbl.set_line_wrap(True)
    t_lbl.get_style_context().add_class("mintsec-subtitle")
    s_lbl = Gtk.Label(label=subtitle, xalign=0.0)
    s_lbl.set_line_wrap(True)
    s_lbl.get_style_context().add_class("mintsec-muted")
    txt.pack_start(t_lbl, False, False, 0)
    txt.pack_start(s_lbl, False, False, 0)
    relate_label(t_lbl, control)

    control.set_valign(Gtk.Align.CENTER)
    row.pack_start(txt, True, True, 0)
    row.pack_start(control, False, False, 0)
    return row, t_lbl, s_lbl


def _add_divider(box: Gtk.Box) -> None:
    sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
    sep.get_style_context().add_class("mintsec-divider")
    box.pack_start(sep, False, False, 4)


def _repopulate_combo(combo: Gtk.ComboBoxText, items: tuple[tuple[str, str], ...], active_id: str | None) -> None:
    combo.remove_all()
    for item_id, label in items:
        combo.append(item_id, label)
    if active_id:
        combo.set_active_id(active_id)


class SettingsPage(Gtk.Box):
    """Apresenta idioma, aparência, alertas e informações Sobre o NodusGuard."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self._loading = False
        self._about_lang: str | None = None
        self._last_theme_sig: tuple[str, str] | None = None

        self.notebook = Gtk.Notebook()
        self.notebook.get_style_context().add_class("mintsec-tabs")
        self.pack_start(self.notebook, True, True, 0)

        # Aba 1: Geral (Idioma + Aparência)
        app_wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        app_wrap.set_margin_top(6)
        app_wrap.set_margin_bottom(12)
        app_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        app_card.get_style_context().add_class("mintsec-list-card")

        self.language_combo = Gtk.ComboBoxText()
        self.language_combo.append("en", tr("settings.lang_en"))
        self.language_combo.append("pt_BR", tr("settings.lang_pt_br"))
        self.language_combo.set_size_request(220, -1)
        self.language_combo.connect("changed", self._on_changed)

        self.theme_combo = Gtk.ComboBoxText()
        self.theme_combo.set_size_request(220, -1)
        self.theme_combo.connect("changed", self._on_changed)

        self.preset_combo = Gtk.ComboBoxText()
        self.preset_combo.set_size_request(220, -1)
        self.preset_combo.connect("changed", self._on_changed)

        self.density_combo = Gtk.ComboBoxText()
        self.density_combo.set_size_request(220, -1)
        self.density_combo.connect("changed", self._on_changed)

        lang_row, self._lang_title_lbl, self._lang_sub_lbl = _make_pref_row("", "", self.language_combo)
        theme_row, self._theme_title_lbl, self._theme_sub_lbl = _make_pref_row("", "", self.theme_combo)
        preset_row, self._preset_title_lbl, self._preset_sub_lbl = _make_pref_row("", "", self.preset_combo)

        app_card.pack_start(lang_row, False, False, 0)
        _add_divider(app_card)
        app_card.pack_start(theme_row, False, False, 0)
        _add_divider(app_card)
        app_card.pack_start(preset_row, False, False, 0)
        _add_divider(app_card)

        self.chk_system_titlebar = Gtk.CheckButton(label="")
        self.chk_system_titlebar.connect("toggled", self._on_changed)
        self._sys_titlebar_note_lbl = Gtk.Label(label="", xalign=0.0)
        self._sys_titlebar_note_lbl.set_line_wrap(True)
        self._sys_titlebar_note_lbl.get_style_context().add_class("mintsec-muted")
        app_card.pack_start(self.chk_system_titlebar, False, False, 0)
        app_card.pack_start(self._sys_titlebar_note_lbl, False, False, 0)
        app_wrap.pack_start(app_card, False, False, 0)

        startup_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        startup_card.get_style_context().add_class("mintsec-list-card")
        self._startup_title_lbl = Gtk.Label(label="", xalign=0.0)
        self._startup_title_lbl.get_style_context().add_class("mintsec-section-title")
        startup_card.pack_start(self._startup_title_lbl, False, False, 0)

        self.autostart_switch = Gtk.Switch()
        self.autostart_switch.connect("notify::active", self._on_changed)
        autostart_row, self._autostart_title_lbl, self._autostart_sub_lbl = _make_pref_row(
            "", "", self.autostart_switch
        )
        startup_card.pack_start(autostart_row, False, False, 0)
        app_wrap.pack_start(startup_card, False, False, 0)

        disp_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        disp_card.get_style_context().add_class("mintsec-card")
        self._disp_exp = Gtk.Expander(label="")
        self._disp_exp.get_style_context().add_class("mintsec-expander")
        disp_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        disp_box.set_margin_top(8)
        dens_row, self._dens_title_lbl, self._dens_sub_lbl = _make_pref_row("", "", self.density_combo)
        disp_box.pack_start(dens_row, False, False, 0)
        self._disp_exp.add(disp_box)
        disp_card.pack_start(self._disp_exp, False, False, 0)
        app_wrap.pack_start(disp_card, False, False, 0)
        self._tab_general_lbl = Gtk.Label(label="")
        self.notebook.append_page(app_wrap, self._tab_general_lbl)

        # Aba 2: Alertas e proteção
        pref_wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        pref_wrap.set_margin_top(6)
        pref_wrap.set_margin_bottom(12)

        auto_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        auto_card.get_style_context().add_class("mintsec-list-card")
        self._automation_title_lbl = Gtk.Label(label="", xalign=0.0)
        self._automation_title_lbl.get_style_context().add_class("mintsec-section-title")
        auto_card.pack_start(self._automation_title_lbl, False, False, 0)

        self.auto_scan_switch = Gtk.Switch()
        self.auto_scan_switch.connect("notify::active", self._on_changed)
        as_row, self._auto_scan_title_lbl, self._auto_scan_sub_lbl = _make_pref_row(
            "", "", self.auto_scan_switch
        )
        auto_card.pack_start(as_row, False, False, 0)
        _add_divider(auto_card)

        self.auto_scan_interval_combo = Gtk.ComboBoxText()
        self.auto_scan_interval_combo.set_size_request(220, -1)
        self.auto_scan_interval_combo.connect("changed", self._on_changed)
        asi_row, self._auto_scan_int_title_lbl, _ = _make_pref_row(
            "", "", self.auto_scan_interval_combo
        )
        auto_card.pack_start(asi_row, False, False, 0)
        _add_divider(auto_card)

        self.post_scan_action_combo = Gtk.ComboBoxText()
        self.post_scan_action_combo.set_size_request(220, -1)
        self.post_scan_action_combo.connect("changed", self._on_changed)
        psa_row, self._post_scan_title_lbl, self._post_scan_sub_lbl = _make_pref_row(
            "", "", self.post_scan_action_combo
        )
        auto_card.pack_start(psa_row, False, False, 0)
        _add_divider(auto_card)

        self.auto_db_switch = Gtk.Switch()
        self.auto_db_switch.connect("notify::active", self._on_changed)
        adb_row, self._auto_db_title_lbl, self._auto_db_sub_lbl = _make_pref_row(
            "", "", self.auto_db_switch
        )
        auto_card.pack_start(adb_row, False, False, 0)
        _add_divider(auto_card)

        self.dnd_switch = Gtk.Switch()
        self.dnd_switch.connect("notify::active", self._on_changed)
        dnd_row, self._dnd_title_lbl, self._dnd_sub_lbl = _make_pref_row(
            "", "", self.dnd_switch
        )
        auto_card.pack_start(dnd_row, False, False, 0)
        _add_divider(auto_card)

        self.game_mode_switch = Gtk.Switch()
        self.game_mode_switch.connect("notify::active", self._on_changed)
        gm_row, self._game_mode_title_lbl, self._game_mode_sub_lbl = _make_pref_row(
            "", "", self.game_mode_switch
        )
        auto_card.pack_start(gm_row, False, False, 0)
        _add_divider(auto_card)

        self.restore_recs_btn = Gtk.Button(label="")
        self.restore_recs_btn.connect("clicked", self._on_restore_ignored_recs)
        rec_row, self._restore_recs_title_lbl, _ = _make_pref_row(
            "", "", self.restore_recs_btn
        )
        auto_card.pack_start(rec_row, False, False, 0)

        pref_wrap.pack_start(auto_card, False, False, 0)

        notif_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        notif_card.get_style_context().add_class("mintsec-list-card")

        self.chk_grouped = Gtk.CheckButton(label="")
        self.chk_grouped.connect("toggled", self._on_changed)

        self.chk_media = Gtk.CheckButton(label="")
        self.chk_media.connect("toggled", self._on_changed)

        notif_card.pack_start(self.chk_grouped, False, False, 0)
        _add_divider(notif_card)
        notif_card.pack_start(self.chk_media, False, False, 0)
        pref_wrap.pack_start(notif_card, False, False, 0)

        extra_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        extra_card.get_style_context().add_class("mintsec-card")
        self._extra_exp = Gtk.Expander(label="")
        self._extra_exp.get_style_context().add_class("mintsec-expander")
        extra_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        extra_box.set_margin_top(8)

        self.policy_combo = Gtk.ComboBoxText()
        self.policy_combo.set_size_request(220, -1)
        self.policy_combo.connect("changed", self._on_changed)

        pol_row, self._pol_title_lbl, self._pol_sub_lbl = _make_pref_row("", "", self.policy_combo)
        extra_box.pack_start(pol_row, False, False, 0)
        _add_divider(extra_box)

        self.chk_history = Gtk.CheckButton(label="")
        self.chk_history.connect("toggled", self._on_changed)

        self._hist_note_lbl = Gtk.Label(label="", xalign=0.0)
        self._hist_note_lbl.set_line_wrap(True)
        self._hist_note_lbl.get_style_context().add_class("mintsec-muted")

        extra_box.pack_start(self.chk_history, False, False, 0)
        extra_box.pack_start(self._hist_note_lbl, False, False, 0)
        self._extra_exp.add(extra_box)
        extra_card.pack_start(self._extra_exp, False, False, 0)
        pref_wrap.pack_start(extra_card, False, False, 0)

        self._tab_alerts_lbl = Gtk.Label(label="")
        self.notebook.append_page(pref_wrap, self._tab_alerts_lbl)

        # Aba 3: Logs operacionais e diagnóstico
        self.logs_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.logs_tab.set_margin_top(6)
        self.logs_tab.set_margin_bottom(12)
        self._logs_populating = False

        logs_hdr_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        logs_hdr_card.get_style_context().add_class("mintsec-list-card")

        logs_title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self._logs_title_lbl = Gtk.Label(label="", xalign=0.0)
        self._logs_title_lbl.get_style_context().add_class("mintsec-section-title")
        self.logs_count_lbl = Gtk.Label(label="", xalign=1.0)
        self.logs_count_lbl.get_style_context().add_class("mintsec-muted")
        logs_title_row.pack_start(self._logs_title_lbl, True, True, 0)
        logs_title_row.pack_start(self.logs_count_lbl, False, False, 0)
        logs_hdr_card.pack_start(logs_title_row, False, False, 0)

        self._logs_sub_lbl = Gtk.Label(label="", xalign=0.0)
        self._logs_sub_lbl.set_line_wrap(True)
        self._logs_sub_lbl.get_style_context().add_class("mintsec-muted")
        logs_hdr_card.pack_start(self._logs_sub_lbl, False, False, 0)

        logs_ctrl_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.logs_level_combo = Gtk.ComboBoxText()
        self.logs_level_combo.set_size_request(150, -1)
        self.logs_level_combo.connect("changed", lambda *_: self.refresh_logs() if not self._logs_populating else None)

        self.logs_search_entry = Gtk.SearchEntry()
        self.logs_search_entry.connect("changed", lambda *_: self.refresh_logs() if not self._logs_populating else None)

        self.refresh_logs_btn = Gtk.Button(label="")
        self.refresh_logs_btn.connect("clicked", lambda *_: self.refresh_logs())

        self.clear_logs_btn = Gtk.Button(label="")
        self.clear_logs_btn.get_style_context().add_class("destructive-action")
        self.clear_logs_btn.connect("clicked", self._on_clear_logs)

        logs_ctrl_row.pack_start(self.logs_level_combo, False, False, 0)
        logs_ctrl_row.pack_start(self.logs_search_entry, True, True, 0)
        logs_ctrl_row.pack_start(self.refresh_logs_btn, False, False, 0)
        logs_ctrl_row.pack_start(self.clear_logs_btn, False, False, 0)
        logs_hdr_card.pack_start(logs_ctrl_row, False, False, 0)
        self.logs_tab.pack_start(logs_hdr_card, False, False, 0)

        logs_view_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        logs_view_card.get_style_context().add_class("mintsec-card")
        logs_scroller = Gtk.ScrolledWindow()
        logs_scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
        logs_scroller.set_min_content_height(320)
        self.logs_text_view = Gtk.TextView()
        self.logs_text_view.set_editable(False)
        self.logs_text_view.set_cursor_visible(False)
        self.logs_text_view.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
        self.logs_text_view.get_style_context().add_class("mintsec-log-view")
        logs_scroller.add(self.logs_text_view)
        logs_view_card.pack_start(logs_scroller, True, True, 0)
        self.logs_tab.pack_start(logs_view_card, True, True, 0)

        self._tab_logs_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.logs_tab, self._tab_logs_lbl)

        # Aba 4: Sobre / About (nome, versão e créditos de código aberto)
        self.about_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.about_tab.set_margin_top(6)
        self.about_tab.set_margin_bottom(12)
        self._tab_about_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.about_tab, self._tab_about_lbl)
        self.notebook.connect("switch-page", self._on_notebook_switch_page)

        self.apply_language()

    def select_tab(self, tab_name: str) -> None:
        mapping = {"general": 0, "alerts": 1, "logs": 2, "about": 3}
        if tab_name in mapping:
            self.notebook.set_current_page(mapping[tab_name])
            if tab_name == "logs":
                self.refresh_logs()

    def _on_notebook_switch_page(self, _nb: Gtk.Notebook, page: Gtk.Widget, _idx: int) -> None:
        if page is self.logs_tab:
            self.refresh_logs()

    def _populate_combos(
        self,
        *,
        theme_mode: str | None = None,
        theme_preset: str | None = None,
        density: str | None = None,
        pause_policy: str | None = None,
        auto_scan_interval: str | None = None,
        default_scan_post_action: str | None = None,
    ) -> None:
        _repopulate_combo(
            self.theme_combo,
            (
                ("follow_system", tr("settings.theme_follow")),
                ("light", tr("settings.theme_light")),
                ("dark", tr("settings.theme_dark")),
            ),
            theme_mode,
        )
        _repopulate_combo(
            self.preset_combo,
            (
                ("lavender", tr("settings.preset_lavender")),
                ("neutral_light", tr("settings.preset_neutral")),
                ("system_dark", tr("settings.preset_sys_dark")),
                ("graphite_dark", tr("settings.preset_graphite")),
            ),
            theme_preset,
        )
        _repopulate_combo(
            self.density_combo,
            (
                ("essential", tr("settings.density_essential")),
                ("detailed", tr("settings.density_detailed")),
            ),
            density,
        )
        _repopulate_combo(
            self.policy_combo,
            (
                ("unset", tr("settings.policy_unset")),
                ("alert_only", tr("settings.policy_alert")),
                ("auto_pause", tr("settings.policy_pause")),
            ),
            pause_policy,
        )
        _repopulate_combo(
            self.auto_scan_interval_combo,
            (
                ("6h", tr("settings.interval_6h")),
                ("12h", tr("settings.interval_12h")),
                ("daily", tr("settings.interval_daily")),
                ("weekly", tr("settings.interval_weekly")),
            ),
            auto_scan_interval,
        )
        _repopulate_combo(
            self.post_scan_action_combo,
            (
                ("none", tr("scans.post_none")),
                ("suspend", tr("scans.post_suspend")),
                ("shutdown", tr("scans.post_shutdown")),
            ),
            default_scan_post_action,
        )

    def _populate_about(self) -> None:
        clear_container(self.about_tab)

        hero = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        hero.get_style_context().add_class("mintsec-hero-card")
        icon_art = make_illustration(
            "nodusguard_icon_256.png",
            72,
            fallback_icon="security-high-symbolic",
            a11y_name=tr("about.icon_a11y"),
        )
        icon_art.set_valign(Gtk.Align.CENTER)
        hero.pack_start(icon_art, False, False, 0)

        hcol = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        hcol.set_valign(Gtk.Align.CENTER)
        title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        name_lbl = Gtk.Label(label=APP_NAME, xalign=0.0)
        name_lbl.get_style_context().add_class("mintsec-page-title")
        title_row.pack_start(name_lbl, False, False, 0)
        title_row.pack_start(make_pill(f"v{__version__}", tone="neutral"), False, False, 0)
        hcol.pack_start(title_row, False, False, 0)

        ver_lbl = Gtk.Label(label=tr("about.version_line", version=__version__), xalign=0.0)
        ver_lbl.get_style_context().add_class("mintsec-subtitle")
        hcol.pack_start(ver_lbl, False, False, 0)

        tag_lbl = Gtk.Label(label=tr("about.tagline"), xalign=0.0)
        tag_lbl.set_line_wrap(True)
        tag_lbl.get_style_context().add_class("mintsec-muted")
        hcol.pack_start(tag_lbl, False, False, 0)

        hero.pack_start(hcol, True, True, 0)
        self.about_tab.pack_start(hero, False, False, 0)

        credits_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        credits_card.get_style_context().add_class("mintsec-list-card")

        c_title = Gtk.Label(label=tr("about.credits_title"), xalign=0.0)
        c_title.get_style_context().add_class("mintsec-section-title")
        c_intro = Gtk.Label(label=tr("about.credits_intro"), xalign=0.0)
        c_intro.set_line_wrap(True)
        c_intro.get_style_context().add_class("mintsec-muted")
        credits_card.pack_start(c_title, False, False, 0)
        credits_card.pack_start(c_intro, False, False, 0)

        categories = (
            ("about.cat_ui_title", "about.cat_ui_items"),
            ("about.cat_agent_title", "about.cat_agent_items"),
            ("about.cat_engines_title", "about.cat_engines_items"),
            ("about.cat_integration_title", "about.cat_integration_items"),
            ("about.cat_assets_title", "about.cat_assets_items"),
        )
        for idx, (cat_key, items_key) in enumerate(categories):
            if idx >= 0:
                _add_divider(credits_card)
            cat_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            cat_box.set_margin_top(2)
            cat_box.set_margin_bottom(2)
            ct = Gtk.Label(label=tr(cat_key), xalign=0.0)
            ct.get_style_context().add_class("mintsec-subtitle")
            ci = Gtk.Label(label=tr(items_key), xalign=0.0)
            ci.set_line_wrap(True)
            ci.get_style_context().add_class("mintsec-muted")
            cat_box.pack_start(ct, False, False, 0)
            cat_box.pack_start(ci, False, False, 0)
            credits_card.pack_start(cat_box, False, False, 0)

        self.about_tab.pack_start(credits_card, False, False, 0)
        self.about_tab.show_all()

    def apply_language(self) -> None:
        self._loading = True
        try:
            cfg = self.app_window.controller.config_store.load()
            self._tab_general_lbl.set_text(tr("settings.tab_general"))
            self._tab_alerts_lbl.set_text(tr("settings.tab_alerts"))
            self._tab_logs_lbl.set_text(tr("settings.tab_logs"))
            self._tab_about_lbl.set_text(tr("settings.tab_about"))

            self._logs_title_lbl.set_text(tr("settings.logs_title"))
            self._logs_sub_lbl.set_text(tr("settings.logs_sub"))
            self.logs_search_entry.set_placeholder_text(tr("settings.logs_search_ph"))
            set_accessible(
                self.logs_search_entry,
                tr("settings.logs_search_a11y"),
                tr("settings.logs_search_ph"),
            )
            self.refresh_logs_btn.set_label(tr("settings.logs_refresh_btn"))
            set_accessible(
                self.refresh_logs_btn,
                tr("settings.logs_refresh_btn"),
                tr("settings.logs_title"),
            )
            self.clear_logs_btn.set_label(tr("settings.logs_clear_btn"))
            set_accessible(
                self.clear_logs_btn,
                tr("settings.logs_clear_btn"),
                tr("settings.logs_clear_desc"),
            )
            self._logs_populating = True
            try:
                cur_lvl = self.logs_level_combo.get_active_id() or "all"
                _repopulate_combo(
                    self.logs_level_combo,
                    (
                        ("all", tr("settings.logs_level_all")),
                        ("INFO", tr("settings.logs_level_info")),
                        ("WARNING", tr("settings.logs_level_warn")),
                        ("ERROR", tr("settings.logs_level_error")),
                    ),
                    cur_lvl,
                )
            finally:
                self._logs_populating = False
            set_accessible(self.logs_level_combo, tr("settings.logs_level_a11y"))

            self._lang_title_lbl.set_text(tr("settings.lang_title"))
            self._lang_sub_lbl.set_text(tr("settings.lang_sub"))
            self.language_combo.set_active_id(cfg.language)
            set_accessible(self.language_combo, tr("settings.lang_a11y"), tr("settings.lang_desc"))

            self._theme_title_lbl.set_text(tr("settings.theme_mode_title"))
            self._theme_sub_lbl.set_text(tr("settings.theme_mode_sub"))
            set_accessible(self.theme_combo, tr("settings.theme_a11y"), tr("settings.theme_desc"))

            self._preset_title_lbl.set_text(tr("settings.preset_title"))
            self._preset_sub_lbl.set_text(tr("settings.preset_sub"))
            set_accessible(self.preset_combo, tr("settings.preset_a11y"), tr("settings.preset_desc"))

            self.chk_system_titlebar.set_label(tr("settings.chk_system_titlebar"))
            self.chk_system_titlebar.set_active(cfg.use_system_titlebar)
            set_accessible(
                self.chk_system_titlebar,
                tr("settings.chk_system_titlebar_a11y"),
                tr("settings.chk_system_titlebar_desc"),
            )
            self._sys_titlebar_note_lbl.set_text(tr("settings.chk_system_titlebar_note"))

            self._disp_exp.set_label(tr("settings.disp_expander"))
            set_accessible(self._disp_exp, tr("settings.disp_expander"), tr("settings.disp_expander_desc"))
            self._dens_title_lbl.set_text(tr("settings.density_title"))
            self._dens_sub_lbl.set_text(tr("settings.density_sub"))
            set_accessible(self.density_combo, tr("settings.density_a11y"), tr("settings.density_desc"))

            self._startup_title_lbl.set_text(tr("settings.startup_title"))
            self._autostart_title_lbl.set_text(tr("settings.autostart_row"))
            self._autostart_sub_lbl.set_text(tr("settings.autostart_desc"))
            self.autostart_switch.set_active(cfg.autostart_enabled)
            set_accessible(self.autostart_switch, tr("settings.autostart_row"), tr("settings.autostart_desc"))

            self._automation_title_lbl.set_text(tr("settings.automation_title"))
            self._auto_scan_title_lbl.set_text(tr("settings.auto_scan_row"))
            self._auto_scan_sub_lbl.set_text(tr("settings.auto_scan_desc"))
            self.auto_scan_switch.set_active(cfg.auto_quick_scan_enabled)
            set_accessible(self.auto_scan_switch, tr("settings.auto_scan_row"), tr("settings.auto_scan_desc"))

            self._auto_scan_int_title_lbl.set_text(tr("settings.auto_scan_interval_row"))
            set_accessible(self.auto_scan_interval_combo, tr("settings.auto_scan_interval_row"))
            self.auto_scan_interval_combo.set_sensitive(cfg.auto_quick_scan_enabled)

            self._post_scan_title_lbl.set_text(tr("settings.post_scan_row"))
            self._post_scan_sub_lbl.set_text(tr("settings.post_scan_sub"))
            set_accessible(
                self.post_scan_action_combo,
                tr("settings.post_scan_a11y"),
                tr("settings.post_scan_desc"),
            )

            self._auto_db_title_lbl.set_text(tr("settings.auto_db_row"))
            self._auto_db_sub_lbl.set_text(tr("settings.auto_db_desc"))
            self.auto_db_switch.set_active(cfg.auto_db_update_enabled)
            set_accessible(self.auto_db_switch, tr("settings.auto_db_row"), tr("settings.auto_db_desc"))

            self._dnd_title_lbl.set_text(tr("settings.dnd_row"))
            self._dnd_sub_lbl.set_text(tr("settings.dnd_desc"))
            self.dnd_switch.set_active(cfg.do_not_disturb)
            set_accessible(self.dnd_switch, tr("settings.dnd_row"), tr("settings.dnd_desc"))

            self._game_mode_title_lbl.set_text(tr("settings.game_mode_row"))
            self._game_mode_sub_lbl.set_text(tr("settings.game_mode_desc"))
            self.game_mode_switch.set_active(cfg.game_mode)
            set_accessible(self.game_mode_switch, tr("settings.game_mode_row"), tr("settings.game_mode_desc"))

            self._restore_recs_title_lbl.set_text(tr("settings.recs_restore_row"))
            self.restore_recs_btn.set_label(tr("settings.recs_restore_btn"))
            set_accessible(self.restore_recs_btn, tr("settings.recs_restore_btn"))
            self.restore_recs_btn.set_sensitive(bool(cfg.ignored_recommendations))

            self.chk_grouped.set_label(tr("settings.chk_grouped"))
            set_accessible(self.chk_grouped, tr("settings.chk_grouped_a11y"), tr("settings.chk_grouped_desc"))
            self.chk_media.set_label(tr("settings.chk_media"))
            set_accessible(self.chk_media, tr("settings.chk_media_a11y"), tr("settings.chk_media_desc"))

            self._extra_exp.set_label(tr("settings.extra_expander"))
            set_accessible(self._extra_exp, tr("settings.extra_expander"), tr("settings.extra_expander_desc"))
            self._pol_title_lbl.set_text(tr("settings.policy_title"))
            self._pol_sub_lbl.set_text(tr("settings.policy_sub"))
            set_accessible(self.policy_combo, tr("settings.policy_a11y"), tr("settings.policy_desc"))

            self.chk_history.set_label(tr("settings.chk_history"))
            set_accessible(self.chk_history, tr("settings.chk_history_a11y"), tr("settings.chk_history_desc"))
            self._hist_note_lbl.set_text(tr("settings.hist_note"))

            self._populate_combos(
                theme_mode=cfg.theme_mode,
                theme_preset=cfg.theme_preset,
                density=cfg.density,
                pause_policy=cfg.pause_policy,
                auto_scan_interval=cfg.auto_quick_scan_interval,
                default_scan_post_action=cfg.default_scan_post_action,
            )
            self._last_theme_sig = (cfg.theme_mode, cfg.theme_preset)
            self._about_lang = None
            self.refresh_logs()
            if self.get_mapped():
                self._ensure_about_populated(cfg.language)
        finally:
            self._loading = False

    def refresh_logs(self) -> None:
        """Recarrega e filtra os logs operacionais exibidos na aba Logs."""
        ctrl = self.app_window.controller
        level_id = self.logs_level_combo.get_active_id() or "all"
        level_filter = None if level_id == "all" else level_id
        query = self.logs_search_entry.get_text() if hasattr(self, "logs_search_entry") else ""
        entries = ctrl.list_app_logs(level=level_filter, query=query, limit=500)
        total = ctrl.app_log.count()
        self.logs_count_lbl.set_text(tr("settings.logs_count", count=total))
        self.clear_logs_btn.set_sensitive(total > 0)
        buf = self.logs_text_view.get_buffer()
        if entries:
            buf.set_text("\n".join(localize_log_entry(item) for item in entries))
        else:
            buf.set_text(tr("settings.logs_empty"))

    def _on_clear_logs(self, *_args: object) -> None:
        ctrl = self.app_window.controller
        total = ctrl.app_log.count()
        if total <= 0:
            return
        ok = ask_action_confirmation(
            self.app_window,
            title=tr("settings.logs_clear_confirm_title"),
            summary=tr("settings.logs_clear_confirm_summary", count=total),
            actor="NodusGuard",
            evidence=tr("settings.logs_clear_confirm_evidence"),
            confirm_label=tr("settings.logs_clear_confirm_btn"),
            confirm_effect=tr("settings.logs_clear_confirm_effect"),
            destructive=True,
        )
        if not ok:
            return
        ctrl.clear_app_logs()
        self.refresh_logs()

    def _ensure_about_populated(self, lang: str) -> None:
        if self._about_lang == lang:
            return
        self._populate_about()
        self._about_lang = lang

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        self._loading = True
        try:
            cfg = self.app_window.controller.config_store.load()
            self._ensure_about_populated(cfg.language)
            self._last_theme_sig = (cfg.theme_mode, cfg.theme_preset)
            self.language_combo.set_active_id(cfg.language)
            self.theme_combo.set_active_id(cfg.theme_mode)
            self.preset_combo.set_active_id(cfg.theme_preset)
            self.chk_system_titlebar.set_active(cfg.use_system_titlebar)
            self.density_combo.set_active_id(cfg.density)
            self.policy_combo.set_active_id(cfg.pause_policy)
            self.autostart_switch.set_active(cfg.autostart_enabled)
            self.auto_scan_switch.set_active(cfg.auto_quick_scan_enabled)
            self.auto_scan_interval_combo.set_active_id(cfg.auto_quick_scan_interval)
            self.auto_scan_interval_combo.set_sensitive(cfg.auto_quick_scan_enabled)
            self.post_scan_action_combo.set_active_id(cfg.default_scan_post_action)
            self.auto_db_switch.set_active(cfg.auto_db_update_enabled)
            self.dnd_switch.set_active(cfg.do_not_disturb)
            self.game_mode_switch.set_active(cfg.game_mode)
            self.restore_recs_btn.set_sensitive(bool(cfg.ignored_recommendations))
            self.chk_grouped.set_active(cfg.notifications_grouped)
            self.chk_media.set_active(cfg.removable_media_prompt)
            self.chk_history.set_active(cfg.history_enabled)
            self.refresh_logs()
        finally:
            self._loading = False

    def _on_restore_ignored_recs(self, *_args: object) -> None:
        self.app_window.controller.restore_ignored_recommendations()
        self.restore_recs_btn.set_sensitive(False)
        for page_name in ("home_page",):
            page = getattr(self.app_window, page_name, None)
            if page is not None and hasattr(page, "_last_render_sig"):
                page._last_render_sig = None
        self.app_window.refresh_all(force=False)

    def _on_changed(self, *_args: object) -> None:
        if self._loading:
            return
        new_lang = self.language_combo.get_active_id() or "en"
        lang_changed = new_lang != get_language()
        auto_scan_on = self.auto_scan_switch.get_active()
        self.auto_scan_interval_combo.set_sensitive(auto_scan_on)
        new_post_scan = self.post_scan_action_combo.get_active_id() or "none"
        use_sys_tb = self.chk_system_titlebar.get_active()

        self.app_window.controller.config_store.update(
            language=new_lang,
            theme_mode=self.theme_combo.get_active_id() or "follow_system",
            theme_preset=self.preset_combo.get_active_id() or "lavender",
            use_system_titlebar=use_sys_tb,
            density=self.density_combo.get_active_id() or "essential",
            pause_policy=self.policy_combo.get_active_id() or "unset",
            autostart_enabled=self.autostart_switch.get_active(),
            auto_quick_scan_enabled=auto_scan_on,
            auto_quick_scan_interval=self.auto_scan_interval_combo.get_active_id() or "daily",
            auto_db_update_enabled=self.auto_db_switch.get_active(),
            do_not_disturb=self.dnd_switch.get_active(),
            game_mode=self.game_mode_switch.get_active(),
            notifications_grouped=self.chk_grouped.get_active(),
            removable_media_prompt=self.chk_media.get_active(),
            history_enabled=self.chk_history.get_active(),
            default_scan_post_action=new_post_scan,
        )
        if hasattr(self.app_window, "apply_titlebar_preference"):
            self.app_window.apply_titlebar_preference(use_sys_tb)
        if hasattr(self.app_window, "scans_page"):
            self.app_window.scans_page.sync_default_post_action(new_post_scan)
        try:
            self.app_window.controller.ensure_default_automation()
        except Exception:  # noqa: BLE001
            pass
        if self.app_window.controller.is_live_host_runner:
            try:
                self.app_window.controller.sync_autostart()
            except Exception:  # noqa: BLE001
                pass

        new_theme_mode = self.theme_combo.get_active_id() or "follow_system"
        new_theme_preset = self.preset_combo.get_active_id() or "lavender"
        theme_sig = (new_theme_mode, new_theme_preset)
        if theme_sig != self._last_theme_sig:
            self._last_theme_sig = theme_sig
            self.app_window.apply_theme()
        if hasattr(self.app_window, "sync_tray"):
            self.app_window.sync_tray()
        if lang_changed:
            self.app_window.apply_language()
            return
        # Invalida somente o render visual sem redisparar subprocessos no host
        for page in (
            self.app_window.home_page,
            self.app_window.protections_page,
            self.app_window.activity_page,
            getattr(self.app_window, "notifications_page", None),
        ):
            if page is not None and hasattr(page, "_last_render_sig"):
                page._last_render_sig = None
            if page is not None and hasattr(page, "_last_hist_sig"):
                page._last_hist_sig = None
            if page is not None and hasattr(page, "_last_sig"):
                page._last_sig = None
        self.app_window.refresh_all(force=False)
