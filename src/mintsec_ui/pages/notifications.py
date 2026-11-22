"""Central de Notificações: alertas pendentes, modos de silêncio e eventos recentes."""

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


class NotificationsPage(Gtk.Box):
    """Página de notificações acessível pelo ícone de sino ao lado das configurações."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self._last_sig: tuple[Any, ...] | None = None

        hero = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        hero.get_style_context().add_class("mintsec-hero-card")
        hero.pack_start(
            make_icon_chip("preferences-system-notifications-symbolic", pixel_size=24, tone="accent"),
            False,
            False,
            0,
        )

        hero_text = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.hero_title_lbl = Gtk.Label(label="", xalign=0.0)
        self.hero_title_lbl.get_style_context().add_class("mintsec-title")
        self.hero_sub_lbl = Gtk.Label(label="", xalign=0.0)
        self.hero_sub_lbl.set_line_wrap(True)
        self.hero_sub_lbl.get_style_context().add_class("mintsec-muted")
        hero_text.pack_start(self.hero_title_lbl, False, False, 0)
        hero_text.pack_start(self.hero_sub_lbl, False, False, 0)
        hero.pack_start(hero_text, True, True, 0)

        self.refresh_btn = Gtk.Button(label="")
        self.refresh_btn.set_valign(Gtk.Align.CENTER)
        self.refresh_btn.connect("clicked", lambda *_: self.app_window.refresh_all(force=True))
        hero.pack_start(self.refresh_btn, False, False, 0)
        self.pack_start(hero, False, False, 0)

        self.banners_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.pack_start(self.banners_box, False, False, 0)

        self.pending_heading = Gtk.Label(label="", xalign=0.0)
        self.pending_heading.get_style_context().add_class("mintsec-section-title")
        self.pack_start(self.pending_heading, False, False, 0)

        self.pending_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.pack_start(self.pending_box, False, False, 0)

        self.incidents_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.pack_start(self.incidents_box, False, False, 0)

        self.history_heading = Gtk.Label(label="", xalign=0.0)
        self.history_heading.get_style_context().add_class("mintsec-section-title")
        self.pack_start(self.history_heading, False, False, 0)

        self.history_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.pack_start(self.history_box, False, False, 0)

        self.apply_language()

    def apply_language(self) -> None:
        self.hero_title_lbl.set_text(tr("notif_page.hero_title"))
        self.refresh_btn.set_label(tr("notif_page.btn_refresh"))
        set_accessible(self.refresh_btn, tr("notif_page.btn_refresh"))
        self.history_heading.set_text(tr("notif_page.history_title"))
        self._last_sig = None
        if self.get_mapped():
            self.refresh()

    def _add_mode_banner(
        self,
        *,
        icon_name: str,
        tone: str,
        text: str,
        btn_label: str,
        on_click: Any,
    ) -> None:
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        row.get_style_context().add_class("mintsec-card")
        row.pack_start(make_icon_chip(icon_name, pixel_size=18, tone=tone), False, False, 0)
        lbl = Gtk.Label(label=text, xalign=0.0)
        lbl.set_line_wrap(True)
        lbl.get_style_context().add_class("mintsec-subtitle")
        row.pack_start(lbl, True, True, 0)

        btn = Gtk.Button(label=btn_label)
        btn.set_valign(Gtk.Align.CENTER)
        set_accessible(btn, btn_label)
        btn.connect("clicked", lambda *_: on_click())
        row.pack_start(btn, False, False, 0)
        self.banners_box.pack_start(row, False, False, 0)

    def refresh(self) -> None:
        controller = self.app_window.controller
        cfg = controller.config_store.load()
        paused = cfg.is_protection_paused_now()
        open_pending = controller.pending_store.list_open()
        grouped = controller.pending_store.group_by_app()
        reports = controller.incident_manager.list_incidents()
        events = controller.history_store.query(limit=15) if cfg.history_enabled else []

        sig = (
            cfg.language,
            cfg.do_not_disturb,
            cfg.game_mode,
            paused,
            cfg.history_enabled,
            tuple((d.pending_id, d.occurrences, d.evidence) for d in open_pending),
            tuple((r.incident_id, len(r.items)) for r in reports),
            tuple((e.event_id, e.timestamp, e.confirmation_state) for e in events),
        )
        if sig == self._last_sig:
            return
        self._last_sig = sig

        count = len(open_pending)
        if count > 0:
            self.hero_sub_lbl.set_text(tr("notif_page.hero_sub_pending", count=count))
        else:
            self.hero_sub_lbl.set_text(tr("notif_page.hero_sub_clear"))
        self.pending_heading.set_text(tr("notif_page.pending_title", count=count))

        clear_container(self.banners_box)
        if paused:
            self._add_mode_banner(
                icon_name="media-playback-pause-symbolic",
                tone="crit",
                text=tr("notif_page.banner_paused"),
                btn_label=tr("home.cta_resume"),
                on_click=self.app_window.resume_protection,
            )
        if cfg.do_not_disturb:
            self._add_mode_banner(
                icon_name="notifications-disabled-symbolic",
                tone="warn",
                text=tr("notif_page.banner_dnd"),
                btn_label=tr("notif_page.btn_disable_dnd"),
                on_click=lambda: self.app_window.set_do_not_disturb(False),
            )
        if cfg.game_mode:
            self._add_mode_banner(
                icon_name="input-gaming-symbolic",
                tone="accent",
                text=tr("notif_page.banner_game"),
                btn_label=tr("notif_page.btn_disable_game"),
                on_click=lambda: self.app_window.set_game_mode(False),
            )
        self.banners_box.show_all()

        clear_container(self.pending_box)
        if not grouped:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "security-high-symbolic",
                    tr("notif_page.pending_empty"),
                    tr("act.pending_empty_sub"),
                    illustration="spot_calm.png",
                    illustration_size=84,
                ),
                False,
                False,
                0,
            )
            self.pending_box.pack_start(empty, False, False, 0)
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
                    info.pack_start(title_row, False, False, 0)

                    sub_lbl = Gtk.Label(
                        label=f"{friendly_module_name(dec.module_id, dec.module_id)} · {app_key} · {dec.evidence} · {format_local_datetime(dec.created_at)}",
                        xalign=0.0,
                    )
                    sub_lbl.set_line_wrap(True)
                    sub_lbl.get_style_context().add_class("mintsec-muted")
                    info.pack_start(sub_lbl, False, False, 0)
                    card.pack_start(info, True, True, 0)

                    rev_btn = Gtk.Button(
                        label=tr("cta.review_paused") if dec.kind == "paused_app" else tr("act.review_btn")
                    )
                    rev_btn.get_style_context().add_class("mintsec-primary-cta")
                    rev_btn.set_valign(Gtk.Align.CENTER)
                    set_accessible(rev_btn, tr("act.review_item_a11y", title=dec.title), dec.summary)
                    rev_btn.connect(
                        "clicked",
                        lambda _b, pid=dec.pending_id: self.app_window.open_pending_review(pid),
                    )
                    card.pack_start(rev_btn, False, False, 0)
                    self.pending_box.pack_start(card, False, False, 0)
        self.pending_box.show_all()

        clear_container(self.incidents_box)
        if reports:
            inc_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            inc_card.get_style_context().add_class("mintsec-card")
            populate_incident_cards(inc_card, self.app_window, controller)
            self.incidents_box.pack_start(inc_card, False, False, 0)
        self.incidents_box.show_all()

        clear_container(self.history_box)
        if not cfg.history_enabled:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            card.get_style_context().add_class("mintsec-card")
            card.pack_start(
                make_empty_state(
                    "view-list-symbolic",
                    tr("act.history_disabled_title"),
                    tr("act.history_disabled_sub"),
                ),
                False,
                False,
                0,
            )
            self.history_box.pack_start(card, False, False, 0)
        elif not events:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            card.get_style_context().add_class("mintsec-card")
            card.pack_start(
                make_empty_state(
                    "view-list-symbolic",
                    tr("act.history_empty_title"),
                    tr("act.history_empty_sub"),
                ),
                False,
                False,
                0,
            )
            self.history_box.pack_start(card, False, False, 0)
        else:
            for ev in events:
                card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
                card.get_style_context().add_class("mintsec-card")
                state_tone = "ok" if ev.confirmation_state == "confirmed" else (
                    "crit" if ev.confirmation_state == "failed" else "warn"
                )
                card.pack_start(
                    make_icon_chip(
                        MODULE_ICONS.get(ev.module_id, "view-list-symbolic"),
                        pixel_size=18,
                        tone=state_tone,
                    ),
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
                info.pack_start(top, False, False, 0)

                meta = f"{friendly_module_name(ev.module_id, ev.module_id)} · {ev.reason} · {format_local_datetime(ev.timestamp)}"
                m_lbl = Gtk.Label(label=meta, xalign=0.0)
                m_lbl.set_line_wrap(True)
                m_lbl.get_style_context().add_class("mintsec-muted")
                info.pack_start(m_lbl, False, False, 0)
                card.pack_start(info, True, True, 0)
                self.history_box.pack_start(card, False, False, 0)
        self.history_box.show_all()
