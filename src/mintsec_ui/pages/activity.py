"""Página Atividade em Flat Design: Pendências abertas e Histórico agrupado."""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.formatting import format_local_datetime  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.pages.recovery import populate_incident_cards  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    MODULE_ICONS,
    clear_container,
    confirmation_label,
    friendly_module_name,
    make_empty_state,
    make_icon_chip,
    make_pill,
)

_MODULE_ORDER = ("antimalware", "firewall", "recovery", "network", "browsing", "isolation", "rescue")


class ActivityPage(Gtk.Box):
    """Separa Pendências (sempre ativas) de Histórico local (opcional)."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self._last_pend_sig: tuple[Any, ...] | None = None
        self._last_hist_sig: tuple[Any, ...] | None = None
        self._updating_filters = False

        self.notebook = Gtk.Notebook()
        self.notebook.get_style_context().add_class("mintsec-tabs")
        self.pack_start(self.notebook, True, True, 0)

        self.pending_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.pending_tab.set_margin_top(6)
        self.pending_tab.set_margin_bottom(12)
        self._tab_pending_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.pending_tab, self._tab_pending_lbl)

        self.history_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.history_tab.set_margin_top(6)
        self.history_tab.set_margin_bottom(12)

        filter_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        filter_row.set_margin_top(8)
        self.module_filter = Gtk.ComboBoxText()
        self.module_filter.connect("changed", self._on_filter_changed)

        self.result_filter = Gtk.ComboBoxText()
        self.result_filter.connect("changed", self._on_filter_changed)

        filter_row.pack_start(self.module_filter, False, False, 0)
        filter_row.pack_start(self.result_filter, False, False, 0)

        filter_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=0)
        filter_card.get_style_context().add_class("mintsec-card")
        self.filter_expander = Gtk.Expander(label="")
        self.filter_expander.get_style_context().add_class("mintsec-expander")
        self.filter_expander.add(filter_row)
        filter_card.pack_start(self.filter_expander, False, False, 0)
        self.history_tab.pack_start(filter_card, False, False, 0)

        self.history_list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.history_tab.pack_start(self.history_list_box, False, False, 0)
        self._tab_history_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.history_tab, self._tab_history_lbl)
        self.apply_language()

    def _on_filter_changed(self, *_args: object) -> None:
        if not self._updating_filters:
            self._refresh_history()

    def apply_language(self) -> None:
        self._updating_filters = True
        try:
            self._tab_pending_lbl.set_text(tr("act.tab_pending"))
            self._tab_history_lbl.set_text(tr("act.tab_history"))
            self.filter_expander.set_label(tr("act.filter_expander"))
            set_accessible(
                self.filter_expander,
                tr("act.filter_expander"),
                tr("act.filter_expander_desc"),
            )

            mod_id = self.module_filter.get_active_id() or ""
            self.module_filter.remove_all()
            self.module_filter.append("", tr("act.filter_all_modules"))
            for mid in _MODULE_ORDER:
                self.module_filter.append(mid, friendly_module_name(mid))
            self.module_filter.set_active_id(mod_id)
            set_accessible(
                self.module_filter,
                tr("act.filter_module_a11y"),
                tr("act.filter_module_desc"),
            )

            res_id = self.result_filter.get_active_id() or ""
            self.result_filter.remove_all()
            self.result_filter.append("", tr("act.filter_all_results"))
            self.result_filter.append("confirmed", tr("act.filter_confirmed"))
            self.result_filter.append("incomplete", tr("act.filter_incomplete"))
            self.result_filter.append("failed", tr("act.filter_failed"))
            self.result_filter.set_active_id(res_id)
            set_accessible(
                self.result_filter,
                tr("act.filter_result_a11y"),
                tr("act.filter_result_desc"),
            )
        finally:
            self._updating_filters = False
        self._last_pend_sig = None
        self._last_hist_sig = None

    def select_tab(self, tab_name: str) -> None:
        mapping = {"pending": 0, "history": 1}
        if tab_name in mapping:
            self.notebook.set_current_page(mapping[tab_name])

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        self._refresh_pending()
        self._refresh_history()

    def _refresh_pending(self) -> None:
        controller = self.app_window.controller
        lang = controller.config_store.load().language
        grouped = controller.pending_store.group_by_app()
        reports = controller.incident_manager.list_incidents()
        sig = (
            lang,
            tuple(
                (k, tuple((d.pending_id, d.occurrences, d.evidence) for d in items))
                for k, items in grouped.items()
            ),
            tuple((r.incident_id, r.total_bytes, len(r.items)) for r in reports),
        )
        if sig == self._last_pend_sig:
            return
        self._last_pend_sig = sig

        clear_container(self.pending_tab)
        if not grouped:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "security-high-symbolic",
                    tr("act.pending_empty_title"),
                    tr("act.pending_empty_sub"),
                    illustration="spot_calm.png",
                    illustration_size=96,
                ),
                False,
                False,
                0,
            )
            self.pending_tab.pack_start(empty, False, False, 0)
        else:
            for app_key, items in grouped.items():
                for dec in items:
                    card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                    card.get_style_context().add_class("mintsec-card")

                    tone = "crit" if dec.kind == "paused_app" else "warn"
                    card.pack_start(
                        make_icon_chip(
                            MODULE_ICONS.get(dec.module_id, "security-medium-symbolic"),
                            pixel_size=18,
                            tone=tone,
                        ),
                        False,
                        False,
                        0,
                    )

                    info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
                    title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    t_lbl = Gtk.Label(label=dec.title, xalign=0.0)
                    t_lbl.get_style_context().add_class("mintsec-subtitle")
                    title_row.pack_start(t_lbl, False, False, 0)
                    if dec.occurrences > 1:
                        title_row.pack_start(
                            make_pill(tr("act.grouped_pill", count=dec.occurrences), tone="warn"),
                            False,
                            False,
                            0,
                        )

                    s_lbl = Gtk.Label(
                        label=f"{friendly_module_name(dec.module_id, dec.module_id)} · {app_key} · {dec.evidence} · {format_local_datetime(dec.created_at)}",
                        xalign=0.0,
                    )
                    s_lbl.set_line_wrap(True)
                    s_lbl.get_style_context().add_class("mintsec-muted")
                    info.pack_start(title_row, False, False, 0)
                    info.pack_start(s_lbl, False, False, 0)

                    rev_btn = Gtk.Button(
                        label=tr("cta.review_paused") if dec.kind == "paused_app" else tr("act.review_btn")
                    )
                    rev_btn.get_style_context().add_class("mintsec-primary-cta")
                    rev_btn.set_valign(Gtk.Align.CENTER)
                    set_accessible(
                        rev_btn,
                        tr("act.review_item_a11y", title=dec.title),
                        dec.summary,
                    )
                    rev_btn.connect(
                        "clicked",
                        lambda _b, pid=dec.pending_id: self.app_window.open_pending_review(pid),
                    )
                    card.pack_start(info, True, True, 0)
                    card.pack_start(rev_btn, False, False, 0)
                    self.pending_tab.pack_start(card, False, False, 0)

        inc_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        inc_box.get_style_context().add_class("mintsec-card")
        populate_incident_cards(inc_box, self.app_window, controller)
        self.pending_tab.pack_start(inc_box, False, False, 0)
        self.pending_tab.show_all()

    def _refresh_history(self) -> None:
        cfg = self.app_window.controller.config_store.load()
        mod = self.module_filter.get_active_id() or None
        res = self.result_filter.get_active_id() or None
        groups = (
            self.app_window.controller.history_store.query_grouped(
                module_id=mod,
                confirmation_state=res,
            )
            if cfg.history_enabled
            else []
        )
        sig = (
            cfg.history_enabled,
            cfg.language,
            mod,
            res,
            tuple((g["latest"].event_id, g["count"]) for g in groups[:40]),
        )
        if sig == self._last_hist_sig:
            return
        self._last_hist_sig = sig

        clear_container(self.history_list_box)
        if not cfg.history_enabled:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "view-list-symbolic",
                    tr("act.history_disabled_title"),
                    tr("act.history_disabled_sub"),
                ),
                False,
                False,
                0,
            )
            self.history_list_box.pack_start(empty, False, False, 0)
            self.history_list_box.show_all()
            return

        if not groups:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "view-list-symbolic",
                    tr("act.history_empty_title"),
                    tr("act.history_empty_sub"),
                ),
                False,
                False,
                0,
            )
            self.history_list_box.pack_start(empty, False, False, 0)
        else:
            for grp in groups[:40]:
                ev = grp["latest"]
                cnt = grp["count"]
                card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                card.get_style_context().add_class("mintsec-card")

                state_tone = "ok" if ev.confirmation_state == "confirmed" else (
                    "crit" if ev.confirmation_state == "failed" else "warn"
                )
                card.pack_start(
                    make_icon_chip(MODULE_ICONS.get(ev.module_id, "view-list-symbolic"), pixel_size=18, tone=state_tone),
                    False,
                    False,
                    0,
                )

                info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
                top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                t_lbl = Gtk.Label(label=ev.action, xalign=0.0)
                t_lbl.get_style_context().add_class("mintsec-subtitle")
                top.pack_start(t_lbl, False, False, 0)
                top.pack_start(
                    make_pill(confirmation_label(ev.confirmation_state), tone=state_tone),
                    False,
                    False,
                    0,
                )
                if cnt > 1:
                    top.pack_start(make_pill(f"{cnt}x", tone="neutral"), False, False, 0)

                mod_label = friendly_module_name(ev.module_id, ev.module_id)
                d_lbl = Gtk.Label(
                    label=f"{mod_label} · {ev.reason} · {format_local_datetime(ev.timestamp)}",
                    xalign=0.0,
                )
                d_lbl.set_line_wrap(True)
                d_lbl.get_style_context().add_class("mintsec-muted")
                info.pack_start(top, False, False, 0)
                info.pack_start(d_lbl, False, False, 0)
                card.pack_start(info, True, True, 0)

                if ev.reversible and ev.revert_action and ev.revert_action.startswith("revoke_rule:"):
                    rule_id = ev.revert_action.split(":", 1)[1]
                    rev_btn = Gtk.Button(label=tr("act.revoke_btn"))
                    rev_btn.set_valign(Gtk.Align.CENTER)
                    set_accessible(rev_btn, tr("act.revoke_btn"), tr("act.revoke_desc"))
                    rev_btn.connect("clicked", lambda _b, rid=rule_id: self._on_revoke_rule(rid))
                    card.pack_start(rev_btn, False, False, 0)

                self.history_list_box.pack_start(card, False, False, 0)

        self.history_list_box.show_all()

    def _on_revoke_rule(self, rule_id: str) -> None:
        self.app_window.controller.firewall.revoke_rule(rule_id)
        self.app_window.controller.invalidate_cache("firewall")
        self.app_window.refresh_all(force=True)
