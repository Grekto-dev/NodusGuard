"""Página Proteções do NodusGuard: ativação direta por interruptor e ajustes em submenu."""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.actions import handle_module_switch, trigger_module_install  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    MODULE_ICONS,
    clear_container,
    friendly_module_name,
    friendly_module_tagline,
    friendly_state_text,
    make_empty_state,
    make_icon_chip,
    make_pill,
    status_tone,
)


class ProtectionsPage(Gtk.Box):
    """Catálogo limpo dos 7 recursos com ativação em 1 toque e ajustes detalhados sob demanda."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=14)
        self.app_window = app_window
        self._filter_mode = "all"
        self._updating_filter = False
        self._last_render_sig: tuple[Any, ...] | None = None

        top_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        seg_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=2)
        seg_box.get_style_context().add_class("mintsec-segmented")

        self._filter_buttons: dict[str, Gtk.ToggleButton] = {}
        for key in ("all", "installed", "available"):
            btn = Gtk.ToggleButton(label="")
            btn.get_style_context().add_class("mintsec-seg-btn")
            btn.set_active(key == "all")
            btn.connect("clicked", self._on_filter_clicked, key)
            seg_box.pack_start(btn, False, False, 0)
            self._filter_buttons[key] = btn

        top_bar.pack_start(seg_box, False, False, 0)
        self.pack_start(top_bar, False, False, 0)

        self.list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self.pack_start(self.list_box, False, False, 0)
        self.apply_language()

    def apply_language(self) -> None:
        """Atualiza os filtros e invalida o cache de renderização no idioma ativo."""
        key_map = {
            "all": "prot.filter_all",
            "installed": "prot.filter_installed",
            "available": "prot.filter_available",
        }
        self._updating_filter = True
        try:
            for key, btn in self._filter_buttons.items():
                label = tr(key_map[key])
                btn.set_label(label)
                set_accessible(
                    btn,
                    tr("prot.filter_a11y", label=label),
                    tr("prot.filter_desc", label=label),
                )
        finally:
            self._updating_filter = False
        self._last_render_sig = None

    def _on_filter_clicked(self, clicked: Gtk.ToggleButton, key: str) -> None:
        if self._updating_filter:
            return
        if not clicked.get_active() and self._filter_mode == key:
            self._updating_filter = True
            try:
                clicked.set_active(True)
            finally:
                self._updating_filter = False
            return
        self._filter_mode = key
        self._updating_filter = True
        try:
            for k, btn in self._filter_buttons.items():
                btn.set_active(k == key)
        finally:
            self._updating_filter = False
        cached = getattr(self.app_window, "_cached_statuses", None)
        self.refresh(statuses=cached)

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        controller = self.app_window.controller
        cfg = controller.config_store.load()

        if statuses is None:
            if controller.is_live_host_runner:
                cached = controller.get_cached_statuses()
                if cached is None:
                    self._render_loading()
                    return
                statuses = cached
            else:
                statuses = controller.all_statuses()

        render_sig = (
            self._filter_mode,
            cfg.density,
            cfg.language,
            tuple(
                (mid, st.state.value, st.package_origin, st.installed_version, st.mode_summary, st.needs_setup)
                for mid, st in statuses.items()
            ),
        )
        if render_sig == self._last_render_sig:
            return
        self._last_render_sig = render_sig

        clear_container(self.list_box)
        shown = 0
        for mod_id, st in statuses.items():
            is_installed = st.state != ModuleState.AUSENTE
            if self._filter_mode == "installed" and not is_installed:
                continue
            if self._filter_mode == "available" and is_installed:
                continue
            shown += 1

            manifest = controller.manifests[mod_id]
            friendly_name = friendly_module_name(mod_id, st.display_name)
            tagline = friendly_module_tagline(mod_id, manifest.short_description)

            card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
            card.get_style_context().add_class("mintsec-card")

            tone = status_tone(st.state)
            chip_tone = "ok" if st.state == ModuleState.ATIVO else ("warn" if tone == "warn" else "neutral")
            card.pack_start(
                make_icon_chip(MODULE_ICONS.get(mod_id, "security-high-symbolic"), pixel_size=20, tone=chip_tone),
                False,
                False,
                0,
            )

            text_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=3)
            title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            name_lbl = Gtk.Label(label=friendly_name, xalign=0.0)
            name_lbl.get_style_context().add_class("mintsec-section-title")
            title_row.pack_start(name_lbl, False, False, 0)
            if st.experimental:
                title_row.pack_start(make_pill(tr("common.experimental"), tone="warn"), False, False, 0)

            desc_lbl = Gtk.Label(label=tagline, xalign=0.0)
            desc_lbl.set_line_wrap(True)

            state_txt = friendly_state_text(mod_id, st)
            if cfg.density == "detailed":
                sub_text = tr(
                    "prot.detail_sub",
                    state=state_txt,
                    engine=manifest.engine.get("name"),
                    origin=st.package_origin,
                ) + (f" ({st.installed_version})" if st.installed_version else "")
            else:
                sub_text = state_txt
            meta_lbl = Gtk.Label(label=sub_text, xalign=0.0)
            meta_lbl.set_line_wrap(True)
            meta_lbl.get_style_context().add_class("mintsec-muted")

            text_col.pack_start(title_row, False, False, 0)
            text_col.pack_start(desc_lbl, False, False, 0)
            text_col.pack_start(meta_lbl, False, False, 0)
            card.pack_start(text_col, True, True, 0)

            actions_col = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            actions_col.set_valign(Gtk.Align.CENTER)

            if not is_installed:
                inst_btn = Gtk.Button(label=tr("common.install"))
                inst_btn.get_style_context().add_class("mintsec-primary-cta")
                set_accessible(inst_btn, tr("home.install_a11y", name=friendly_name), tagline)
                inst_btn.connect("clicked", lambda _b, mid=mod_id: trigger_module_install(self.app_window, mid))
                actions_col.pack_start(inst_btn, False, False, 0)
            else:
                adj_btn = Gtk.Button(label=tr("common.adjustments"))
                adj_btn.get_style_context().add_class("mintsec-ghost-btn")
                set_accessible(
                    adj_btn,
                    tr("prot.adjust_a11y", name=friendly_name),
                    tr("prot.adjust_desc", name=friendly_name),
                )
                adj_btn.connect("clicked", lambda _b, mid=mod_id: self.app_window.open_module_detail(mid))
                actions_col.pack_start(adj_btn, False, False, 0)

                if mod_id == "recovery" and st.needs_setup:
                    cfg_btn = Gtk.Button(label=tr("common.configure"))
                    set_accessible(
                        cfg_btn,
                        tr("home.configure_a11y", name=friendly_name),
                        tr("home.configure_desc"),
                    )
                    cfg_btn.connect("clicked", lambda _b: self.app_window.navigate_to("recovery", tab="files"))
                    actions_col.pack_start(cfg_btn, False, False, 0)
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
                    actions_col.pack_start(sw, False, False, 0)

            card.pack_start(actions_col, False, False, 0)
            self.list_box.pack_start(card, False, False, 0)

        if shown == 0:
            empty = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            empty.get_style_context().add_class("mintsec-card")
            empty.pack_start(
                make_empty_state(
                    "security-high-symbolic",
                    tr("prot.empty_title"),
                    tr("prot.empty_sub"),
                ),
                False,
                False,
                0,
            )
            self.list_box.pack_start(empty, False, False, 0)

        self.list_box.show_all()

    def _render_loading(self) -> None:
        if self.list_box.get_children():
            return
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        card.get_style_context().add_class("mintsec-card")
        card.pack_start(
            make_empty_state(
                "security-medium-symbolic",
                tr("prot.loading_title"),
                tr("prot.loading_sub"),
            ),
            False,
            False,
            0,
        )
        self.list_box.pack_start(card, False, False, 0)
        self.list_box.show_all()
