"""Página Início do NodusGuard: hero acolhedor com ilustração, atalhos e interruptores diretos."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote, urlparse

import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gdk, Gtk, Pango  # noqa: E402

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec.formatting import format_local_datetime  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.actions import handle_module_switch, trigger_module_install  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    MODULE_ICONS,
    clear_container,
    friendly_cta_label,
    friendly_module_name,
    friendly_state_text,
    friendly_verdict_text,
    load_pixbuf,
    make_empty_state,
    make_icon_chip,
    make_illustration,
    make_section_header,
)


CARD_ICON_MAP: dict[str, tuple[str, str]] = {
    "scan": ("system-search-symbolic", "accent"),
    "restore": ("document-revert-symbolic", "ok"),
    "network": ("network-wireless-symbolic", "neutral"),
    "isolated_browser": ("web-browser-symbolic", "accent"),
}

CARD_KEY_MAP: dict[str, tuple[str, str, str]] = {
    "scan": ("home.card_scan_title", "home.card_scan_sub", "home.card_scan_a11y"),
    "restore": ("home.card_restore_title", "home.card_restore_sub", "home.card_restore_a11y"),
    "network": ("home.card_network_title", "home.card_network_sub", "home.card_network_a11y"),
    "isolated_browser": ("home.card_isolated_title", "home.card_isolated_sub", "home.card_isolated_a11y"),
}


class HomePage(Gtk.Box):
    """Página inicial minimalista focada em ativação rápida e clareza para usuário leigo."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.app_window = app_window
        self.set_margin_top(2)
        self.set_margin_bottom(14)
        self._last_render_sig: tuple[Any, ...] | None = None
        self._hero_art_name = "hero_welcome.png"

        # 1. Hero Card com ilustração amigável Qwen Image 2.1 + estado + botão único
        self.status_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        self.status_card.get_style_context().add_class("mintsec-hero-card")
        self.pack_start(self.status_card, False, False, 0)

        left_hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        left_hero.set_valign(Gtk.Align.CENTER)

        top_status = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        self.shield_icon = Gtk.Image.new_from_icon_name("security-high-symbolic", Gtk.IconSize.DIALOG)
        self.shield_icon.set_pixel_size(52)
        self.shield_icon.set_valign(Gtk.Align.CENTER)
        self.shield_icon.get_style_context().add_class("mintsec-shield-badge")
        top_status.pack_start(self.shield_icon, False, False, 0)

        status_text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        status_text_box.set_valign(Gtk.Align.CENTER)
        self.headline_label = Gtk.Label(label="", xalign=0.0)
        self.headline_label.set_line_wrap(True)
        self.headline_label.get_style_context().add_class("mintsec-hero-title")
        self.evidence_label = Gtk.Label(label="", xalign=0.0)
        self.evidence_label.set_line_wrap(True)
        self.evidence_label.get_style_context().add_class("mintsec-muted")
        status_text_box.pack_start(self.headline_label, False, False, 0)
        status_text_box.pack_start(self.evidence_label, False, False, 0)
        top_status.pack_start(status_text_box, True, True, 0)
        left_hero.pack_start(top_status, False, False, 0)

        cta_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.primary_cta_btn = Gtk.Button(label=tr("cta.protect_now"))
        self.primary_cta_btn.get_style_context().add_class("mintsec-primary-cta")
        self.primary_cta_btn.set_valign(Gtk.Align.CENTER)
        self.primary_cta_btn.set_no_show_all(True)
        self.primary_cta_btn.connect("clicked", self._on_primary_cta)
        cta_row.pack_start(self.primary_cta_btn, False, False, 0)
        left_hero.pack_start(cta_row, False, False, 0)

        self.status_card.pack_start(left_hero, True, True, 0)

        self.hero_art = make_illustration(
            "hero_welcome.png",
            116,
            fallback_icon="security-high-symbolic",
        )
        self.hero_art.set_valign(Gtk.Align.CENTER)
        self.status_card.pack_end(self.hero_art, False, False, 0)

        # 2. Três cartões de ação rápida (visíveis acima da dobra em 1366x768)
        self.cards_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.cards_box.set_homogeneous(True)
        self.pack_start(self.cards_box, False, False, 0)

        # 3. Lista minimalista de proteções com ativação direta
        self.coverage_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        self.coverage_card.get_style_context().add_class("mintsec-list-card")
        self._cov_hdr = make_section_header(
            tr("home.protections_title"),
            action_label=tr("home.see_all"),
            on_action=lambda *_: self.app_window.navigate_to("protections"),
            action_a11y_name=tr("home.see_all_a11y"),
            action_a11y_desc=tr("home.see_all_desc"),
        )
        self.coverage_card.pack_start(self._cov_hdr, False, False, 0)
        self.coverage_flow = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        self.coverage_card.pack_start(self.coverage_flow, False, False, 0)
        self.pack_start(self.coverage_card, False, False, 0)

        # 4. Faixa inferior compacta: Atividade recente + Resumo ativo
        self.bottom_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        self.bottom_box.set_homogeneous(True)
        self.pack_start(self.bottom_box, False, False, 0)

        self.recent_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.recent_card.get_style_context().add_class("mintsec-list-card")
        self.bottom_box.pack_start(self.recent_card, True, True, 0)

        self.in_use_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.in_use_card.get_style_context().add_class("mintsec-list-card")
        self.bottom_box.pack_start(self.in_use_card, True, True, 0)

        self._cta_action: str | None = None
        self._cta_target: str | None = None

    def apply_language(self) -> None:
        """Reaplica idioma nos textos fixos e invalida assinatura visual."""
        children = self._cov_hdr.get_children()
        if children and isinstance(children[0], Gtk.Label):
            children[0].set_text(tr("home.protections_title"))
        if len(children) > 1 and isinstance(children[1], Gtk.Button):
            children[1].set_label(tr("home.see_all"))
            set_accessible(children[1], tr("home.see_all_a11y"), tr("home.see_all_desc"))
        self._last_render_sig = None

    def set_compact(self, compact: bool) -> None:
        """Adapta escudo, ilustração e cartões para telas compactas (ex.: 1024x600)."""
        self.shield_icon.set_pixel_size(36 if compact else 52)
        if compact:
            self.hero_art.hide()
        else:
            pix = load_pixbuf(self._hero_art_name, 116)
            if pix is not None:
                self.hero_art.set_from_pixbuf(pix)
            self.hero_art.show()
        self.cards_box.set_orientation(
            Gtk.Orientation.VERTICAL if compact else Gtk.Orientation.HORIZONTAL
        )
        self.bottom_box.set_orientation(
            Gtk.Orientation.VERTICAL if compact else Gtk.Orientation.HORIZONTAL
        )

    def _update_shield_and_art(self, severity: str) -> None:
        ctx = self.shield_icon.get_style_context()
        for cls in ("mintsec-shield-ok", "mintsec-shield-warn", "mintsec-shield-crit"):
            ctx.remove_class(cls)
        if severity == "ok":
            ctx.add_class("mintsec-shield-ok")
            art_name = "hero_protected.png"
        elif severity == "warning":
            ctx.add_class("mintsec-shield-warn")
            art_name = "hero_welcome.png"
        elif severity == "critical":
            ctx.add_class("mintsec-shield-crit")
            art_name = "hero_welcome.png"
        else:
            art_name = "hero_welcome.png"

        if art_name != self._hero_art_name:
            self._hero_art_name = art_name
            pix = load_pixbuf(art_name, 116)
            if pix is not None:
                self.hero_art.set_from_pixbuf(pix)

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        controller = self.app_window.controller
        cfg = controller.reload_config()

        if statuses is None:
            if controller.is_live_host_runner:
                cached = controller.get_cached_statuses()
                if cached is None:
                    self._render_loading_skeleton()
                    return
                statuses = cached
            else:
                statuses = controller.all_statuses()

        open_pending = controller.pending_store.list_open()
        verdict = controller.get_home_verdict(statuses=statuses, cfg=cfg, open_pending=open_pending)

        icon_map = {
            "ok": "security-high-symbolic",
            "setup": "security-medium-symbolic",
            "warning": "security-medium-symbolic",
            "critical": "security-low-symbolic",
        }
        self.shield_icon.set_from_icon_name(icon_map.get(verdict.severity, "security-high-symbolic"), Gtk.IconSize.DIALOG)
        self._update_shield_and_art(verdict.severity)

        headline, subtitle = friendly_verdict_text(verdict, statuses=statuses, open_pending=open_pending)
        self.headline_label.set_text(headline)
        self.evidence_label.set_text(subtitle)

        self._cta_action = verdict.primary_cta_action
        self._cta_target = verdict.primary_cta_target
        cta_lbl = friendly_cta_label(verdict, statuses=statuses)
        if cta_lbl:
            self.primary_cta_btn.set_label(cta_lbl)
            set_accessible(self.primary_cta_btn, cta_lbl, f"{headline}. {subtitle}")
            self.primary_cta_btn.show()
        else:
            self.primary_cta_btn.hide()

        events = controller.history_store.query(limit=3) if cfg.history_enabled else []
        render_sig = (
            cfg.first_run_completed,
            cfg.history_enabled,
            cfg.language,
            tuple(
                (mid, st.state.value, st.needs_setup)
                for mid, st in statuses.items()
            ),
            tuple((ev.event_id, ev.action) for ev in events),
        )
        if render_sig == self._last_render_sig:
            return
        self._last_render_sig = render_sig

        # 3 cartões principais
        clear_container(self.cards_box)
        for card in controller.home_cards(statuses=statuses):
            self.cards_box.pack_start(self._make_quick_card_button(card), True, True, 0)

        # Lista minimalista com interruptor direto para o usuário leigo
        clear_container(self.coverage_flow)
        items = list(statuses.items())
        for idx, (mod_id, st) in enumerate(items):
            if idx > 0:
                sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
                sep.get_style_context().add_class("mintsec-divider")
                self.coverage_flow.pack_start(sep, False, False, 0)

            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            row.set_margin_top(8)
            row.set_margin_bottom(8)

            friendly_name = friendly_module_name(mod_id, st.display_name)
            ic = Gtk.Image.new_from_icon_name(MODULE_ICONS.get(mod_id, "security-high-symbolic"), Gtk.IconSize.MENU)
            ic.set_pixel_size(16)
            ic.get_style_context().add_class("mintsec-muted")

            name_lbl = Gtk.Label(label=friendly_name, xalign=0.0)
            name_lbl.set_width_chars(20)
            name_lbl.get_style_context().add_class("mintsec-subtitle")

            state_txt = friendly_state_text(mod_id, st)
            mode_lbl = Gtk.Label(label=state_txt, xalign=0.0)
            mode_lbl.set_ellipsize(Pango.EllipsizeMode.END)
            mode_lbl.get_style_context().add_class("mintsec-muted")

            row.pack_start(ic, False, False, 0)
            row.pack_start(name_lbl, False, False, 0)
            row.pack_start(mode_lbl, True, True, 0)

            if st.state == ModuleState.AUSENTE:
                inst_btn = Gtk.Button(label=tr("common.install"))
                inst_btn.set_valign(Gtk.Align.CENTER)
                set_accessible(
                    inst_btn,
                    tr("home.install_a11y", name=friendly_name),
                    tr("home.install_desc", name=friendly_name),
                )
                inst_btn.connect("clicked", lambda _b, mid=mod_id: trigger_module_install(self.app_window, mid))
                row.pack_start(inst_btn, False, False, 0)
            elif mod_id == "recovery" and st.needs_setup:
                cfg_btn = Gtk.Button(label=tr("common.configure"))
                cfg_btn.set_valign(Gtk.Align.CENTER)
                set_accessible(
                    cfg_btn,
                    tr("home.configure_a11y", name=friendly_name),
                    tr("home.configure_desc"),
                )
                cfg_btn.connect("clicked", lambda _b: self.app_window.navigate_to("recovery", tab="files"))
                row.pack_start(cfg_btn, False, False, 0)
            else:
                sw = Gtk.Switch()
                sw.set_valign(Gtk.Align.CENTER)
                sw.set_active(st.state == ModuleState.ATIVO)
                set_accessible(
                    sw,
                    tr("home.toggle_a11y", name=friendly_name),
                    tr("home.toggle_desc", name=friendly_name, state=state_txt),
                )
                sw.connect(
                    "state-set",
                    lambda _sw, active, mid=mod_id: handle_module_switch(self.app_window, mid, bool(active)),
                )
                row.pack_start(sw, False, False, 0)

                opt_btn = Gtk.Button(label=tr("common.options"))
                opt_btn.get_style_context().add_class("mintsec-ghost-btn")
                set_accessible(
                    opt_btn,
                    tr("home.options_a11y", name=friendly_name),
                    tr("home.options_desc", name=friendly_name),
                )
                opt_btn.connect("clicked", lambda _b, mid=mod_id: self.app_window.open_module_detail(mid))
                row.pack_start(opt_btn, False, False, 0)

            row.show_all()
            self.coverage_flow.pack_start(row, False, False, 0)

        self._populate_bottom_cards(statuses, cfg, events)

    def _make_quick_card_button(self, card: dict[str, str]) -> Gtk.Button:
        btn = Gtk.Button()
        btn.get_style_context().add_class("mintsec-action-card")
        inner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        ic_name, ic_tone = CARD_ICON_MAP.get(card["card_id"], ("security-high-symbolic", "neutral"))
        inner.pack_start(make_icon_chip(ic_name, pixel_size=18, tone=ic_tone), False, False, 0)

        keys = CARD_KEY_MAP.get(card["card_id"])
        if keys:
            title_txt, sub_txt, a11y_txt = tr(keys[0]), tr(keys[1]), tr(keys[2])
        else:
            title_txt, sub_txt, a11y_txt = card["title"], card["subtitle"], card["a11y_name"]
        txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        t_lbl = Gtk.Label(label=title_txt, xalign=0.0)
        t_lbl.get_style_context().add_class("mintsec-subtitle")
        s_lbl = Gtk.Label(label=sub_txt, xalign=0.0)
        s_lbl.set_line_wrap(True)
        s_lbl.get_style_context().add_class("mintsec-muted")
        txt.pack_start(t_lbl, False, False, 0)
        txt.pack_start(s_lbl, False, False, 0)
        inner.pack_start(txt, True, True, 0)

        btn.add(inner)
        set_accessible(btn, a11y_txt, sub_txt)
        btn.connect("clicked", self._on_card_clicked, card["action"])

        if card["card_id"] == "scan":
            btn.drag_dest_set(Gtk.DestDefaults.ALL, [], Gdk.DragAction.COPY)
            btn.drag_dest_add_uri_targets()
            btn.connect("drag-data-received", self._on_scan_drop)

        btn.show_all()
        return btn

    def _render_loading_skeleton(self) -> None:
        self.shield_icon.set_from_icon_name("security-medium-symbolic", Gtk.IconSize.DIALOG)
        self._update_shield_and_art("setup")
        self.headline_label.set_text(tr("home.loading_headline"))
        self.evidence_label.set_text(tr("home.loading_subtitle"))
        self.primary_cta_btn.hide()

        if not self.cards_box.get_children():
            for card in self.app_window.controller.home_cards(statuses={}):
                self.cards_box.pack_start(self._make_quick_card_button(card), True, True, 0)

    def _populate_bottom_cards(self, statuses: dict[str, Any], cfg: Any, events: list[Any]) -> None:
        clear_container(self.recent_card)
        clear_container(self.in_use_card)

        self.recent_card.pack_start(
            make_section_header(
                tr("home.recent_title"),
                action_label=tr("home.see_everything"),
                on_action=lambda *_: self.app_window.navigate_to("activity"),
                action_a11y_name=tr("home.see_everything_a11y"),
                action_a11y_desc=tr("home.see_everything_desc"),
            ),
            False,
            False,
            0,
        )

        if not cfg.history_enabled:
            self.recent_card.pack_start(
                make_empty_state(
                    "view-list-symbolic",
                    tr("home.history_paused_title"),
                    tr("home.history_paused_sub"),
                ),
                False,
                False,
                0,
            )
        elif not events:
            self.recent_card.pack_start(
                make_empty_state(
                    "view-list-symbolic",
                    tr("home.no_events_title"),
                    tr("home.no_events_sub"),
                ),
                False,
                False,
                0,
            )
        else:
            for ev in events:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                t_lbl = Gtk.Label(label=ev.action, xalign=0.0)
                t_lbl.set_ellipsize(Pango.EllipsizeMode.END)
                dt_lbl = Gtk.Label(label=format_local_datetime(ev.timestamp), xalign=1.0)
                dt_lbl.get_style_context().add_class("mintsec-muted")
                row.pack_start(t_lbl, True, True, 0)
                row.pack_start(dt_lbl, False, False, 0)
                self.recent_card.pack_start(row, False, False, 0)
        self.recent_card.show_all()

        self.in_use_card.pack_start(
            make_section_header(
                tr("home.active_title"),
                action_label=tr("home.manage"),
                on_action=lambda *_: self.app_window.navigate_to("protections"),
                action_a11y_name=tr("home.manage_a11y"),
                action_a11y_desc=tr("home.manage_desc"),
            ),
            False,
            False,
            0,
        )

        active = [st for st in statuses.values() if st.state == ModuleState.ATIVO]
        if not active:
            self.in_use_card.pack_start(
                make_empty_state(
                    "security-medium-symbolic",
                    tr("home.no_active_title"),
                    tr("home.no_active_sub"),
                ),
                False,
                False,
                0,
            )
        else:
            for st in active:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                n_lbl = Gtk.Label(
                    label=friendly_module_name(st.module_id, st.display_name),
                    xalign=0.0,
                )
                n_lbl.get_style_context().add_class("mintsec-subtitle")
                m_lbl = Gtk.Label(label=tr("home.active_badge"), xalign=1.0)
                m_lbl.get_style_context().add_class("mintsec-muted")
                row.pack_start(n_lbl, True, True, 0)
                row.pack_start(m_lbl, False, False, 0)
                self.in_use_card.pack_start(row, False, False, 0)
        self.in_use_card.show_all()

    def _on_primary_cta(self, *_args: object) -> None:
        action = self._cta_action
        target = self._cta_target
        if action == "review_pending" and target:
            self.app_window.open_pending_review(target)
        elif action == "open_pending":
            self.app_window.navigate_to("activity", tab="pending")
        elif action == "open_first_run":
            self.app_window.open_first_run_wizard()
        elif action == "open_scans":
            self.app_window.navigate_to("scans", tab="scan")
        elif action == "open_module" and target:
            self.app_window.open_module_detail(target)
        elif action == "open_protections":
            self.app_window.navigate_to("protections")

    def _on_card_clicked(self, _btn: Gtk.Button, action: str) -> None:
        if action == "quick_scan":
            self.app_window.navigate_to("scans", tab="scan")
            self.app_window.scans_page.start_scan("quick")
        elif action == "open_recovery_files":
            self.app_window.navigate_to("recovery", tab="files")
        elif action.startswith("open_module:"):
            mod_id = action.split(":", 1)[1]
            self.app_window.open_module_detail(mod_id)

    def _on_scan_drop(
        self,
        _widget: Gtk.Widget,
        _drag_context: Gdk.DragContext,
        _x: int,
        _y: int,
        selection_data: Gtk.SelectionData,
        _info: int,
        _time: int,
    ) -> None:
        uris = selection_data.get_uris()
        paths = []
        for uri in uris:
            parsed = urlparse(uri)
            if parsed.scheme == "file":
                paths.append(unquote(parsed.path))
        if paths:
            self.app_window.navigate_to("scans", tab="scan")
            self.app_window.scans_page.start_scan("custom", custom_paths=paths)
