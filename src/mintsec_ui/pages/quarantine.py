"""Página dedicada de Quarentena: arquivos isolados, restauração e exclusão segura."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.dialogs.quarantine_restore import restore_quarantine_interactive  # noqa: E402
from mintsec_ui.i18n import format_ui_bytes, format_ui_datetime, tr  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    clear_container,
    make_empty_state,
    make_icon_chip,
    make_pill,
)


class QuarantinePage(Gtk.Box):
    """Gerencia arquivos movidos para a quarentena com restauração e remoção explícita."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self._last_sig: tuple[Any, ...] | None = None

        hero = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        hero.get_style_context().add_class("mintsec-hero-card")
        hero.pack_start(
            make_icon_chip("folder-locked-symbolic", pixel_size=24, tone="warn"),
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

        self.scans_btn = Gtk.Button(label="")
        self.scans_btn.set_valign(Gtk.Align.CENTER)
        self.scans_btn.connect("clicked", lambda *_: self.app_window.navigate_to("scans"))
        hero.pack_start(self.scans_btn, False, False, 0)
        self.pack_start(hero, False, False, 0)

        self.status_lbl = Gtk.Label(label="", xalign=0.0)
        self.status_lbl.set_line_wrap(True)
        self.status_lbl.get_style_context().add_class("mintsec-muted")
        self.pack_start(self.status_lbl, False, False, 0)

        self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.pack_start(self.list_box, False, False, 0)
        self.apply_language()

    def apply_language(self) -> None:
        self.hero_title_lbl.set_text(tr("quar_page.hero_title"))
        self.scans_btn.set_label(tr("quar_page.btn_open_scans"))
        set_accessible(self.scans_btn, tr("quar_page.btn_open_scans"))
        self._last_sig = None
        if self.get_mapped():
            self.refresh()

    def _build_item_card(self, item: Any) -> Gtk.Box:
        name = Path(item.original_path).name
        card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
        card.get_style_context().add_class("mintsec-card")
        card.pack_start(
            make_icon_chip("security-low-symbolic", pixel_size=18, tone="warn"),
            False,
            False,
            0,
        )

        info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        top = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        title_lbl = Gtk.Label(label=name, xalign=0.0)
        title_lbl.get_style_context().add_class("mintsec-subtitle")
        top.pack_start(title_lbl, False, False, 0)
        if item.detection_name:
            top.pack_start(make_pill(item.detection_name, tone="crit"), False, False, 0)
        info.pack_start(top, False, False, 0)

        meta_lbl = Gtk.Label(
            label=tr(
                "scans.quar_meta",
                path=item.original_path,
                date=format_ui_datetime(item.quarantined_at),
                size=format_ui_bytes(item.size_bytes),
            ),
            xalign=0.0,
        )
        meta_lbl.set_line_wrap(True)
        meta_lbl.get_style_context().add_class("mintsec-muted")
        info.pack_start(meta_lbl, False, False, 0)
        card.pack_start(info, True, True, 0)

        actions = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        actions.set_valign(Gtk.Align.CENTER)

        restore_btn = Gtk.Button(label=tr("scans.quar_restore_btn"))
        set_accessible(
            restore_btn,
            tr("scans.quar_restore_a11y", name=name),
            tr("scans.quar_restore_desc"),
        )
        restore_btn.connect("clicked", lambda _b, it=item: self._on_restore(it))
        actions.pack_start(restore_btn, False, False, 0)

        del_btn = Gtk.Button(label=tr("quar_page.del_btn"))
        del_btn.get_style_context().add_class("destructive-action")
        set_accessible(
            del_btn,
            tr("quar_page.del_a11y", name=name),
            tr("quar_page.del_desc"),
        )
        del_btn.connect("clicked", lambda _b, it=item: self._on_delete(it))
        actions.pack_start(del_btn, False, False, 0)

        card.pack_start(actions, False, False, 0)
        return card

    def _on_restore(self, item: Any) -> None:
        restored = restore_quarantine_interactive(
            self.app_window,
            service=self.app_window.controller.antimalware,
            item=item,
        )
        if restored is not None:
            self.status_lbl.set_text(tr("scans.restored_status", path=restored))
            self._last_sig = None
            self.app_window.refresh_all(force=False)

    def _on_delete(self, item: Any) -> None:
        name = Path(item.original_path).name
        if not ask_action_confirmation(
            self.app_window,
            title=tr("quar_page.del_title"),
            summary=tr("quar_page.del_summary", name=name),
            actor=tr("quar.confirm_actor"),
            evidence=tr(
                "quar.confirm_evidence",
                det=item.detection_name or tr("quar_page.col_threat"),
                path=item.original_path,
            ),
            confirm_label=tr("quar_page.del_btn"),
            confirm_effect=tr("quar_page.del_effect"),
            destructive=True,
        ):
            return
        try:
            self.app_window.controller.antimalware.delete_quarantined(
                item.item_id,
                confirmed=True,
            )
        except Exception as exc:  # noqa: BLE001 - falha explícita na interface
            self.status_lbl.set_text(str(exc))
            return
        self.status_lbl.set_text(tr("quar_page.deleted_status", name=name))
        self._last_sig = None
        self.app_window.refresh_all(force=False)

    def refresh(self) -> None:
        lang = self.app_window.controller.config_store.load().language
        items = self.app_window.controller.antimalware.list_quarantine()
        sig = (lang, tuple((it.item_id, it.quarantined_at, it.size_bytes) for it in items))
        if sig == self._last_sig:
            return
        self._last_sig = sig

        if items:
            self.hero_sub_lbl.set_text(tr("quar_page.hero_subtitle_items", count=len(items)))
        else:
            self.hero_sub_lbl.set_text(tr("quar_page.hero_subtitle_empty"))

        clear_container(self.list_box)
        if not items:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "security-high-symbolic",
                    tr("quar_page.empty_title"),
                    tr("quar_page.empty_desc"),
                    illustration="spot_calm.png",
                    illustration_size=92,
                ),
                False,
                False,
                0,
            )
            self.list_box.pack_start(empty, False, False, 0)
        else:
            for item in items:
                self.list_box.pack_start(self._build_item_card(item), False, False, 0)
        self.list_box.show_all()
