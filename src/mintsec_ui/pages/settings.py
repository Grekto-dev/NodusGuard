"""Página Configurações em Flat Design: Aparência, Alertas e Opções de Proteção."""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec import APP_NAME, __version__  # noqa: E402
from mintsec_ui.a11y import relate_label, set_accessible  # noqa: E402
from mintsec_ui.i18n import get_language, tr  # noqa: E402
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
        app_wrap.pack_start(app_card, False, False, 0)

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

        # Aba 3: Sobre / About (nome, versão e créditos de código aberto)
        self.about_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.about_tab.set_margin_top(6)
        self.about_tab.set_margin_bottom(12)
        self._tab_about_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.about_tab, self._tab_about_lbl)

        self.apply_language()

    def _populate_combos(
        self,
        *,
        theme_mode: str | None = None,
        theme_preset: str | None = None,
        density: str | None = None,
        pause_policy: str | None = None,
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
            self._tab_about_lbl.set_text(tr("settings.tab_about"))

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

            self._disp_exp.set_label(tr("settings.disp_expander"))
            set_accessible(self._disp_exp, tr("settings.disp_expander"), tr("settings.disp_expander_desc"))
            self._dens_title_lbl.set_text(tr("settings.density_title"))
            self._dens_sub_lbl.set_text(tr("settings.density_sub"))
            set_accessible(self.density_combo, tr("settings.density_a11y"), tr("settings.density_desc"))

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
            )
            self._populate_about()
        finally:
            self._loading = False

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        self._loading = True
        try:
            cfg = self.app_window.controller.config_store.load()
            self.language_combo.set_active_id(cfg.language)
            self.theme_combo.set_active_id(cfg.theme_mode)
            self.preset_combo.set_active_id(cfg.theme_preset)
            self.density_combo.set_active_id(cfg.density)
            self.policy_combo.set_active_id(cfg.pause_policy)
            self.chk_grouped.set_active(cfg.notifications_grouped)
            self.chk_media.set_active(cfg.removable_media_prompt)
            self.chk_history.set_active(cfg.history_enabled)
        finally:
            self._loading = False

    def _on_changed(self, *_args: object) -> None:
        if self._loading:
            return
        new_lang = self.language_combo.get_active_id() or "en"
        lang_changed = new_lang != get_language()
        self.app_window.controller.config_store.update(
            language=new_lang,
            theme_mode=self.theme_combo.get_active_id() or "follow_system",
            theme_preset=self.preset_combo.get_active_id() or "lavender",
            density=self.density_combo.get_active_id() or "essential",
            pause_policy=self.policy_combo.get_active_id() or "unset",
            notifications_grouped=self.chk_grouped.get_active(),
            removable_media_prompt=self.chk_media.get_active(),
            history_enabled=self.chk_history.get_active(),
        )
        self.app_window.apply_theme()
        if lang_changed:
            self.app_window.apply_language()
            return
        # Invalida somente o render visual sem redisparar subprocessos no host
        for page in (self.app_window.home_page, self.app_window.protections_page, self.app_window.activity_page):
            if hasattr(page, "_last_render_sig"):
                page._last_render_sig = None
            if hasattr(page, "_last_hist_sig"):
                page._last_hist_sig = None
        self.app_window.refresh_all(force=False)
