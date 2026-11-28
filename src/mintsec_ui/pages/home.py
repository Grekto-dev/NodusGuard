"""Página Início do NodusGuard: animação Cairo verde/vermelha, timestamps e recomendações."""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote, urlparse

import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
gi.require_version("Pango", "1.0")
from gi.repository import Gdk, Gtk, Pango  # noqa: E402

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec.formatting import format_error_message  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.actions import handle_module_switch, run_ui_task, trigger_module_install  # noqa: E402
from mintsec_ui.animations import ProtectionStatusCanvas  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import format_ui_datetime, localize_text, tr  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    MODULE_ICONS,
    clear_container,
    friendly_module_name,
    friendly_state_text,
    make_empty_state,
    make_icon_chip,
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
    """Painel inicial minimalista com animação verde/vermelha e recomendações acionáveis."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self.set_margin_top(2)
        self.set_margin_bottom(14)
        self._last_recs_sig: tuple[Any, ...] | None = None
        self._last_cards_sig: tuple[Any, ...] | None = None
        self._last_coverage_sig: tuple[Any, ...] | None = None
        self._last_bottom_sig: tuple[Any, ...] | None = None
        self._last_recs_data: list[dict[str, Any]] = []
        self._last_has_scan: bool = False
        self._cta_action: str | None = None
        self._cta_target: str | None = None

        # 1. Hero Card com animação vetorial ultra-light + timestamps + recomendações
        self.status_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.status_card.get_style_context().add_class("mintsec-hero-card")
        self.status_card.get_style_context().add_class("mintsec-hero-ok")
        self.pack_start(self.status_card, False, False, 0)

        self.hero_top_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        self.status_canvas = ProtectionStatusCanvas()
        self.status_canvas.set_size_request(210, 168)
        self.hero_top_row.pack_start(self.status_canvas, False, False, 0)

        right_hero = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        right_hero.set_valign(Gtk.Align.CENTER)

        top_status = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        self.shield_icon = Gtk.Image.new_from_icon_name("security-high-symbolic", Gtk.IconSize.DIALOG)
        self.shield_icon.set_pixel_size(52)
        self.shield_icon.set_no_show_all(True)
        self.shield_icon.hide()
        top_status.pack_start(self.shield_icon, False, False, 0)

        status_text_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.headline_label = Gtk.Label(label="", xalign=0.0)
        self.headline_label.set_line_wrap(True)
        self.headline_label.get_style_context().add_class("mintsec-hero-title")
        self.evidence_label = Gtk.Label(label="", xalign=0.0)
        self.evidence_label.set_line_wrap(True)
        self.evidence_label.get_style_context().add_class("mintsec-muted")
        status_text_box.pack_start(self.headline_label, False, False, 0)
        status_text_box.pack_start(self.evidence_label, False, False, 0)
        top_status.pack_start(status_text_box, True, True, 0)
        right_hero.pack_start(top_status, False, False, 0)

        cta_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.primary_cta_btn = Gtk.Button(label=tr("home.cta_quick_scan"))
        self.primary_cta_btn.get_style_context().add_class("mintsec-primary-cta")
        self.primary_cta_btn.set_valign(Gtk.Align.CENTER)
        self.primary_cta_btn.set_no_show_all(True)
        self.primary_cta_btn.connect("clicked", self._on_primary_cta)
        cta_row.pack_start(self.primary_cta_btn, False, False, 0)

        self.update_db_btn = Gtk.Button(label=tr("home.cta_update_db"))
        self.update_db_btn.set_valign(Gtk.Align.CENTER)
        self.update_db_btn.connect("clicked", lambda *_: self.app_window.trigger_db_update())
        set_accessible(self.update_db_btn, tr("home.cta_update_db"))
        cta_row.pack_start(self.update_db_btn, False, False, 0)
        right_hero.pack_start(cta_row, False, False, 0)

        self.meta_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.last_scan_pill, self.last_scan_val_lbl = self._make_meta_chip("system-search-symbolic")
        self.last_db_pill, self.last_db_val_lbl = self._make_meta_chip("software-update-available-symbolic")
        self.meta_row.pack_start(self.last_scan_pill, False, False, 0)
        self.meta_row.pack_start(self.last_db_pill, False, False, 0)
        right_hero.pack_start(self.meta_row, False, False, 0)

        self.hero_top_row.pack_start(right_hero, True, True, 0)
        self.status_card.pack_start(self.hero_top_row, False, False, 0)

        hero_div = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        hero_div.get_style_context().add_class("mintsec-divider")
        self.status_card.pack_start(hero_div, False, False, 0)

        self.recs_revealer = Gtk.Revealer()
        self.recs_revealer.set_transition_type(Gtk.RevealerTransitionType.SLIDE_DOWN)
        self.recs_revealer.set_transition_duration(180)
        self.recs_revealer.set_reveal_child(True)

        recs_wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        recs_hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.recs_heading_lbl = Gtk.Label(label="", xalign=0.0)
        self.recs_heading_lbl.get_style_context().add_class("mintsec-subtitle")
        recs_hdr.pack_start(self.recs_heading_lbl, True, True, 0)

        self.apply_all_recs_btn = Gtk.Button(label="")
        self.apply_all_recs_btn.get_style_context().add_class("mintsec-primary-cta")
        self.apply_all_recs_btn.set_no_show_all(True)
        self.apply_all_recs_btn.connect("clicked", lambda b: self._on_apply_all_recs(b))
        recs_hdr.pack_start(self.apply_all_recs_btn, False, False, 0)

        self.recs_more_btn = Gtk.Button(label="")
        self.recs_more_btn.get_style_context().add_class("mintsec-ghost-btn")
        self.recs_more_btn.set_no_show_all(True)
        self.recs_more_btn.connect("clicked", lambda b: self._on_show_more_recs(b))
        recs_hdr.pack_start(self.recs_more_btn, False, False, 0)

        self.restore_ignored_btn = Gtk.Button(label=tr("home.recs_restore_btn"))
        self.restore_ignored_btn.get_style_context().add_class("mintsec-ghost-btn")
        self.restore_ignored_btn.set_no_show_all(True)
        set_accessible(self.restore_ignored_btn, tr("home.recs_restore_btn"))
        self.restore_ignored_btn.connect("clicked", self._on_restore_ignored)
        recs_hdr.pack_start(self.restore_ignored_btn, False, False, 0)
        recs_wrap.pack_start(recs_hdr, False, False, 0)

        self.recs_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        recs_wrap.pack_start(self.recs_box, False, False, 0)
        self.recs_feedback_lbl = Gtk.Label(label="", xalign=0.0)
        self.recs_feedback_lbl.set_line_wrap(True)
        self.recs_feedback_lbl.set_no_show_all(True)
        self.recs_feedback_lbl.get_style_context().add_class("mintsec-muted")
        recs_wrap.pack_start(self.recs_feedback_lbl, False, False, 0)
        self.recs_revealer.add(recs_wrap)
        self.status_card.pack_start(self.recs_revealer, False, False, 0)

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

    @property
    def _last_render_sig(self) -> tuple[Any, ...] | None:
        if None in (
            self._last_recs_sig,
            self._last_cards_sig,
            self._last_coverage_sig,
            self._last_bottom_sig,
        ):
            return None
        return (
            self._last_recs_sig,
            self._last_cards_sig,
            self._last_coverage_sig,
            self._last_bottom_sig,
        )

    def invalidate_render_cache(self) -> None:
        self._last_recs_sig = None
        self._last_cards_sig = None
        self._last_coverage_sig = None
        self._last_bottom_sig = None

    @_last_render_sig.setter
    def _last_render_sig(self, value: Any) -> None:
        if value is None:
            self.invalidate_render_cache()

    def _make_meta_chip(self, icon_name: str) -> tuple[Gtk.Box, Gtk.Label]:
        pill = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        pill.get_style_context().add_class("mintsec-meta-pill")
        ic = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.MENU)
        ic.set_pixel_size(14)
        lbl = Gtk.Label(label="", xalign=0.0)
        lbl.set_ellipsize(Pango.EllipsizeMode.END)
        pill.pack_start(ic, False, False, 0)
        pill.pack_start(lbl, False, False, 0)
        return pill, lbl

    def set_animations_active(self, active: bool) -> None:
        self.status_canvas.set_active_page(active)

    def set_high_contrast(self, high_contrast: bool) -> None:
        self.status_canvas.set_high_contrast(high_contrast)

    def apply_language(self) -> None:
        """Reaplica idioma nos textos fixos e invalida assinatura visual."""
        self.update_db_btn.set_label(tr("home.cta_update_db"))
        set_accessible(self.update_db_btn, tr("home.cta_update_db"))
        self.restore_ignored_btn.set_label(tr("home.recs_restore_btn"))
        set_accessible(self.restore_ignored_btn, tr("home.recs_restore_btn"))

        children = self._cov_hdr.get_children()
        if children and isinstance(children[0], Gtk.Label):
            children[0].set_text(tr("home.protections_title"))
        if len(children) > 1 and isinstance(children[1], Gtk.Button):
            children[1].set_label(tr("home.see_all"))
            set_accessible(children[1], tr("home.see_all_a11y"), tr("home.see_all_desc"))
        self._last_render_sig = None

    def set_compact(self, compact: bool) -> None:
        """Adapta escudo, animação e cartões para telas compactas (ex.: 1024x600)."""
        self.shield_icon.set_pixel_size(36 if compact else 52)
        self.status_canvas.set_compact(compact)
        if not compact:
            self.status_canvas.set_size_request(210, 168)
        self.meta_row.set_orientation(
            Gtk.Orientation.VERTICAL if compact else Gtk.Orientation.HORIZONTAL
        )
        self.cards_box.set_orientation(
            Gtk.Orientation.VERTICAL if compact else Gtk.Orientation.HORIZONTAL
        )
        self.bottom_box.set_orientation(
            Gtk.Orientation.VERTICAL if compact else Gtk.Orientation.HORIZONTAL
        )

    def _apply_health_style(self, health: str) -> None:
        ctx = self.status_card.get_style_context()
        ctx.remove_class("mintsec-hero-ok")
        ctx.remove_class("mintsec-hero-alert")
        ctx.add_class("mintsec-hero-ok" if health == "ok" else "mintsec-hero-alert")
        self.status_canvas.set_status(health)

    def _update_shield_icon_name(self, health: str) -> None:
        icon_name = "security-high-symbolic" if health == "ok" else "security-low-symbolic"
        self.shield_icon.set_from_icon_name(icon_name, Gtk.IconSize.DIALOG)

    def _describe_recommendation(self, rec: dict[str, Any], *, has_last_scan: bool) -> tuple[str, str, str, str]:
        rid = rec["rec_id"]
        if rid == "protection_paused":
            return tr("home.rec_paused_title"), tr("home.rec_paused_desc"), tr("home.rec_action_resume"), "crit"
        if rid == "paused_app":
            app = rec.get("app_name") or friendly_module_name("recovery", "Recovery")
            return tr("home.rec_pending_title", count=1), f"{app} — {tr('home.rec_pending_desc')}", tr("home.rec_action_review"), "crit"
        if rid == "pending_alerts":
            cnt = int(rec.get("count", 1))
            return tr("home.rec_pending_title", count=cnt), tr("home.rec_pending_desc"), tr("home.rec_action_review"), "crit"
        if rid == "db_outdated":
            return tr("home.rec_db_stale_title"), tr("home.rec_db_stale_desc"), tr("home.rec_action_update_db"), "warn"
        if rid == "scan_incomplete":
            return tr("home.rec_scan_stale_title"), tr("home.rec_scan_stale_desc"), tr("home.rec_action_scan"), "warn"
        if rid == "enable_antimalware":
            return tr("home.rec_mod_title", name=friendly_module_name("antimalware", "Antimalware")), tr("home.rec_mod_desc"), tr("home.rec_action_enable"), "warn"
        if rid == "enable_firewall":
            return tr("home.rec_mod_title", name=friendly_module_name("firewall", "Firewall")), tr("home.rec_mod_desc"), tr("home.rec_action_enable"), "warn"
        if rid == "enable_browsing":
            return tr("home.rec_browsing_title"), tr("home.rec_browsing_desc"), tr("home.rec_action_enable"), "accent"
        if rid.startswith("allow_fw_app:"):
            app_label = str(rec.get("app_name") or rid.split(":", 1)[1])
            return tr("home.rec_fw_app_title", app=app_label), tr("home.rec_fw_app_desc", app=app_label), tr("home.rec_action_allow_app"), "accent"
        if rid == "enable_auto_scan":
            return tr("home.rec_auto_scan_title"), tr("home.rec_auto_scan_desc"), tr("home.rec_action_enable_auto"), "accent"
        if rid == "run_quick_scan":
            if has_last_scan:
                return tr("home.rec_scan_stale_title"), tr("home.rec_scan_stale_desc"), tr("home.rec_action_scan"), "accent"
            return tr("home.rec_scan_never_title"), tr("home.rec_scan_never_desc"), tr("home.rec_action_scan"), "accent"
        return tr("home.rec_mod_title", name=friendly_module_name("recovery", "Recovery")), tr("home.rec_mod_desc"), tr("home.rec_action_open"), "accent"

    def _make_rec_row(self, rec: dict[str, Any], *, has_last_scan: bool, compact_pop: bool = False) -> Gtk.Box:
        title, desc, btn_lbl, tone = self._describe_recommendation(rec, has_last_scan=has_last_scan)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        row.get_style_context().add_class("mintsec-rec-row")

        ic_name = "dialog-warning-symbolic" if tone in ("crit", "warn") else "security-medium-symbolic"
        row.pack_start(make_icon_chip(ic_name, pixel_size=16, tone=tone), False, False, 0)

        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=1)
        t_lbl = Gtk.Label(label=title, xalign=0.0)
        t_lbl.set_ellipsize(Pango.EllipsizeMode.NONE if compact_pop else Pango.EllipsizeMode.END)
        t_lbl.set_line_wrap(compact_pop)
        t_lbl.get_style_context().add_class("mintsec-subtitle")
        d_lbl = Gtk.Label(label=desc, xalign=0.0)
        d_lbl.set_ellipsize(Pango.EllipsizeMode.NONE if compact_pop else Pango.EllipsizeMode.END)
        d_lbl.set_line_wrap(compact_pop)
        d_lbl.get_style_context().add_class("mintsec-muted")
        info.pack_start(t_lbl, False, False, 0)
        info.pack_start(d_lbl, False, False, 0)
        row.pack_start(info, True, True, 0)

        act_btn = Gtk.Button(label=btn_lbl)
        act_btn.get_style_context().add_class("mintsec-primary-cta")
        act_btn.set_valign(Gtk.Align.CENTER)
        set_accessible(act_btn, f"{btn_lbl}: {title}", desc)
        act_btn.connect("clicked", lambda b, r=rec: self._on_apply_single_rec(r, b))
        row.pack_start(act_btn, False, False, 0)

        if rec.get("ignorable"):
            ign_btn = Gtk.Button(label=tr("home.rec_ignore_btn"))
            ign_btn.get_style_context().add_class("mintsec-ghost-btn")
            ign_btn.set_valign(Gtk.Align.CENTER)
            set_accessible(ign_btn, tr("home.rec_ignore_a11y", title=title))
            ign_btn.connect("clicked", lambda _b, rid=rec["rec_id"]: self._on_ignore_rec(rid))
            row.pack_start(ign_btn, False, False, 0)
        return row

    def _populate_recommendations(self, recs: list[dict[str, Any]], *, has_last_scan: bool, ignored_count: int) -> None:
        self._last_recs_data = list(recs)
        self._last_has_scan = has_last_scan
        self.recs_heading_lbl.set_text(tr("home.recs_heading", count=len(recs)))
        if ignored_count > 0:
            self.restore_ignored_btn.show()
        else:
            self.restore_ignored_btn.hide()

        auto_recs = [r for r in recs if r.get("auto_apply")]
        if auto_recs:
            lbl = tr("home.recs_apply_all_btn", count=len(auto_recs))
            self.apply_all_recs_btn.set_label(lbl)
            set_accessible(
                self.apply_all_recs_btn,
                tr("home.recs_apply_all_a11y"),
                tr("home.recs_apply_all_desc"),
            )
            self.apply_all_recs_btn.show()
        else:
            self.apply_all_recs_btn.hide()

        if len(recs) > 3:
            more_lbl = tr("home.recs_more_btn", count=len(recs) - 3)
            self.recs_more_btn.set_label(more_lbl)
            set_accessible(
                self.recs_more_btn,
                tr("home.recs_more_a11y"),
                tr("home.recs_more_desc"),
            )
            self.recs_more_btn.show()
        else:
            self.recs_more_btn.hide()

        clear_container(self.recs_box)
        if not recs:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            row.get_style_context().add_class("mintsec-rec-row")
            row.pack_start(make_icon_chip("security-high-symbolic", pixel_size=16, tone="ok"), False, False, 0)
            txt = Gtk.Label(
                label=f"{tr('home.recs_none_title')} — {tr('home.recs_none_desc')}",
                xalign=0.0,
            )
            txt.set_ellipsize(Pango.EllipsizeMode.END)
            txt.get_style_context().add_class("mintsec-muted")
            row.pack_start(txt, True, True, 0)
            self.recs_box.pack_start(row, False, False, 0)
            self.recs_box.show_all()
            return

        for rec in recs[:3]:
            self.recs_box.pack_start(self._make_rec_row(rec, has_last_scan=has_last_scan), False, False, 0)
        self.recs_box.show_all()

    def _on_ignore_rec(self, rec_id: str) -> None:
        self.app_window.controller.ignore_recommendation(rec_id)
        self._last_render_sig = None
        self.app_window.refresh_all(force=False)

    def _on_restore_ignored(self, *_args: object) -> None:
        self.app_window.controller.restore_ignored_recommendations()
        self._last_render_sig = None
        self.app_window.refresh_all(force=False)

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
        health = controller.get_overall_health(statuses=statuses, cfg=cfg, open_pending=open_pending)
        recs = controller.get_protection_recommendations(statuses=statuses, cfg=cfg, open_pending=open_pending)

        am_st = statuses.get("antimalware")
        last_scan_info = (am_st.details.get("last_scan") or {}) if am_st is not None else {}
        sig_info = (am_st.details.get("signatures") or {}) if am_st is not None else {}
        last_scan_ts = str(last_scan_info.get("finished_at") or "")
        db_updated_ts = str(sig_info.get("updated_at") or "")

        scan_display = format_ui_datetime(last_scan_ts) if last_scan_ts else tr("home.last_scan_never")
        db_display = format_ui_datetime(db_updated_ts) if db_updated_ts else tr("home.last_db_never")
        self.last_scan_val_lbl.set_text(f"{tr('home.last_scan_label')} {scan_display}")
        self.last_db_val_lbl.set_text(f"{tr('home.last_db_label')} {db_display}")

        self._update_shield_icon_name(health)
        self._apply_health_style(health)

        if health == "paused":
            headline = tr("home.status_paused_title")
            mode = cfg.protection_pause_mode
            until_fmt = format_ui_datetime(cfg.protection_paused_until) if cfg.protection_paused_until else ""
            if mode == "timed" and until_fmt:
                subtitle = tr("home.status_paused_sub_until", until=until_fmt)
            elif mode == "until_restart":
                subtitle = tr("home.status_paused_sub_restart")
            else:
                subtitle = tr("home.status_paused_sub_indef")
            cta_lbl = tr("home.cta_resume")
            self._cta_action = "resume_protection"
            self._cta_target = None
        elif health == "ok":
            headline = tr("home.status_ok_title")
            subtitle = tr("home.status_ok_sub")
            cta_lbl = tr("home.cta_quick_scan")
            self._cta_action = "quick_scan"
            self._cta_target = None
        else:
            headline = tr("home.status_alert_title")
            subtitle = tr("home.status_alert_sub")
            if recs:
                cta_lbl = tr("home.cta_fix_first")
                self._cta_action = recs[0]["action"]
                self._cta_target = recs[0].get("target")
            else:
                cta_lbl = tr("home.cta_quick_scan")
                self._cta_action = "quick_scan"
                self._cta_target = None

        self.headline_label.set_text(headline)
        self.evidence_label.set_text(subtitle)
        self.primary_cta_btn.set_label(cta_lbl)
        set_accessible(self.primary_cta_btn, cta_lbl, f"{headline}. {subtitle}")
        self.primary_cta_btn.show()

        events = controller.history_store.query(limit=3) if cfg.history_enabled else []

        recs_sig = (
            cfg.language,
            tuple(cfg.ignored_recommendations),
            bool(last_scan_ts),
            tuple((r["rec_id"], r.get("count"), r.get("until"), r.get("action")) for r in recs),
        )
        if recs_sig != self._last_recs_sig:
            self._last_recs_sig = recs_sig
            self._populate_recommendations(
                recs,
                has_last_scan=bool(last_scan_ts),
                ignored_count=len(cfg.ignored_recommendations),
            )

        cards_sig = (
            cfg.language,
            cfg.first_run_completed,
            tuple(
                (mid, st.state.value, st.needs_setup)
                for mid, st in statuses.items()
                if mid in ("antimalware", "recovery", "network", "isolation")
            ),
        )
        if cards_sig != self._last_cards_sig:
            self._last_cards_sig = cards_sig
            clear_container(self.cards_box)
            for card in controller.home_cards(statuses=statuses):
                self.cards_box.pack_start(self._make_quick_card_button(card), True, True, 0)

        coverage_sig = (
            cfg.language,
            tuple((mid, st.state.value, st.needs_setup) for mid, st in statuses.items()),
        )
        if coverage_sig != self._last_coverage_sig:
            self._last_coverage_sig = coverage_sig
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

        bottom_sig = (
            cfg.language,
            cfg.history_enabled,
            tuple((mid, st.state.value) for mid, st in statuses.items()),
            tuple((ev.event_id, ev.action) for ev in events),
        )
        if bottom_sig != self._last_bottom_sig:
            self._last_bottom_sig = bottom_sig
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
        self._apply_health_style("ok")
        self.headline_label.set_text(tr("home.loading_headline"))
        self.evidence_label.set_text(tr("home.loading_subtitle"))
        self.last_scan_val_lbl.set_text(f"{tr('home.last_scan_label')} {tr('home.last_scan_never')}")
        self.last_db_val_lbl.set_text(f"{tr('home.last_db_label')} {tr('home.last_db_never')}")
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
                t_lbl = Gtk.Label(label=localize_text(ev.action), xalign=0.0)
                t_lbl.set_ellipsize(Pango.EllipsizeMode.END)
                dt_lbl = Gtk.Label(label=format_ui_datetime(ev.timestamp), xalign=1.0)
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

    def _show_rec_error(self, err: Exception | str, *, operation: str = "") -> None:
        if hasattr(self.app_window, "show_error"):
            self.app_window.show_error(
                err,
                operation=operation or tr("home.rec_apply_err_title"),
                source="NodusGuard",
                title=tr("home.rec_apply_err_title"),
            )
            return
        msg = format_error_message(err) if isinstance(err, Exception) else str(err)
        ask_action_confirmation(
            self.app_window,
            title=tr("home.rec_apply_err_title"),
            summary=msg,
            actor=tr("win.menu"),
            evidence=tr("home.rec_apply_err_evidence"),
            confirm_label=tr("common.close"),
            confirm_effect=tr("common.close_notice"),
        )

    def _on_apply_single_rec(self, rec: dict[str, Any], btn: Any = None) -> None:
        action = str(rec.get("action", ""))
        if action == "update_db":
            self.app_window.trigger_db_update(busy_widget=btn if isinstance(btn, Gtk.Widget) else None)
            return
        if not rec.get("auto_apply") or action == "quick_scan":
            self._run_action(action, rec.get("target"))
            return

        def _done(_res: dict[str, Any]) -> None:
            self.recs_feedback_lbl.set_text(tr("home.recs_applied_ok", count=1))
            self.recs_feedback_lbl.show()
            self.invalidate_render_cache()
            self.app_window.refresh_all(force=True)

        rec_title, _sub, _act, _tone = self._describe_recommendation(rec, has_last_scan=self._last_has_scan)
        run_ui_task(
            self.app_window,
            lambda: self.app_window.controller.apply_recommendation(rec),
            on_success=_done,
            on_error=lambda exc: self._show_rec_error(exc, operation=rec_title),
            busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
            activity_label=tr("win.activity_apply_rec"),
            category="recommendations",
        )

    def _on_show_more_recs(self, anchor_btn: Gtk.Button) -> None:
        extra = self._last_recs_data[3:]
        if not extra:
            return
        popover = Gtk.Popover()
        popover.set_relative_to(anchor_btn)
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        box.set_margin_top(10)
        box.set_margin_bottom(10)
        box.set_margin_start(10)
        box.set_margin_end(10)
        box.set_size_request(460, -1)
        for rec in extra:
            box.pack_start(
                self._make_rec_row(rec, has_last_scan=self._last_has_scan, compact_pop=True),
                False,
                False,
                0,
            )
        box.show_all()
        popover.add(box)
        popover.popup()

    def _on_apply_all_recs(self, btn: Any = None, *, confirm: bool = True) -> None:
        auto_recs = [r for r in self._last_recs_data if r.get("auto_apply")]
        if not auto_recs:
            return
        if confirm:
            bullets = "\n".join(
                f"• {self._describe_recommendation(r, has_last_scan=self._last_has_scan)[0]}"
                for r in auto_recs[:6]
            )
            if len(auto_recs) > 6:
                bullets += f"\n• (+{len(auto_recs) - 6})"
            ok = ask_action_confirmation(
                self.app_window,
                title=tr("home.recs_confirm_title"),
                summary=tr("home.recs_confirm_summary", count=len(auto_recs), items=bullets),
                actor="NodusGuard",
                evidence=tr("home.recs_apply_all_desc"),
                confirm_label=tr("home.recs_confirm_label"),
                confirm_effect=tr("home.recs_confirm_effect"),
            )
            if not ok:
                return
        self.execute_apply_all_recommendations(auto_recs, busy_widget=btn)

    def execute_apply_all_recommendations(
        self,
        recs: list[dict[str, Any]],
        *,
        busy_widget: Any = None,
    ) -> None:
        def _done(res: dict[str, Any]) -> None:
            applied = list(res.get("applied") or [])
            failed = list(res.get("failed") or [])
            if failed:
                err_txt = "; ".join(f"{f['rec_id']}: {f['error']}" for f in failed[:2])
                self.recs_feedback_lbl.set_text(
                    tr("home.recs_applied_partial", ok_cnt=len(applied), err_cnt=len(failed), err=err_txt)
                )
                self.recs_feedback_lbl.show()
            elif applied:
                self.recs_feedback_lbl.set_text(tr("home.recs_applied_ok", count=len(applied)))
                self.recs_feedback_lbl.show()
            self._last_render_sig = None
            self.app_window.refresh_all(force=True)
            if res.get("trigger_scan") == "quick":
                self.app_window.navigate_to("scans", tab="scan")
                self.app_window.scans_page.start_scan("quick")

        run_ui_task(
            self.app_window,
            lambda on_prog=None: self.app_window.controller.apply_all_recommendations(
                recs=recs,
                on_progress=on_prog,
            ),
            on_success=_done,
            on_error=lambda exc: self._show_rec_error(exc, operation=tr("win.activity_apply_all_recs")),
            busy_widget=busy_widget if isinstance(busy_widget, Gtk.Widget) else None,
            activity_label=tr("win.activity_apply_all_recs"),
            category="recommendations",
            pass_progress=True,
        )

    def _run_action(self, action: str | None, target: Any = None) -> None:
        if action == "resume_protection":
            self.app_window.resume_protection()
        elif action == "review_pending" and target:
            self.app_window.open_pending_review(str(target))
        elif action == "open_notifications":
            self.app_window.navigate_to("notifications")
        elif action == "open_pending":
            self.app_window.navigate_to("activity", tab="pending")
        elif action == "open_first_run":
            self.app_window.open_first_run_wizard()
        elif action == "open_scans":
            self.app_window.navigate_to("scans", tab="scan")
        elif action == "quick_scan":
            self.app_window.navigate_to("scans", tab="scan")
            self.app_window.scans_page.start_scan("quick")
        elif action == "update_db":
            self.app_window.trigger_db_update()
        elif action in {
            "auto_enable_antimalware",
            "auto_enable_firewall",
            "auto_enable_browsing",
            "enable_auto_scan",
        } or (action and action.startswith("allow_fw_preset:")):
            self._on_apply_single_rec(
                {"rec_id": action, "action": action, "target": target, "auto_apply": True},
                self.primary_cta_btn,
            )
        elif action == "open_recovery":
            self.app_window.navigate_to("recovery", tab="files")
        elif action == "open_protections":
            self.app_window.navigate_to("protections")
        elif action and (action.startswith("open_module:") or action.startswith("enable_module:")):
            mod_id = action.split(":", 1)[1]
            self.app_window.open_module_detail(mod_id)
        elif action == "open_module" and target:
            self.app_window.open_module_detail(str(target))

    def _on_primary_cta(self, *_args: object) -> None:
        self._run_action(self._cta_action, self._cta_target)

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
