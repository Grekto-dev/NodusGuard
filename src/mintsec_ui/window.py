"""Janela principal GTK 3 do NodusGuard em estilo minimalista Flat Design."""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gdk", "3.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gdk, GLib, Gtk  # noqa: E402

from mintsec import APP_NAME  # noqa: E402
from mintsec.services.catalog import SuiteController  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.dialogs.first_run import FirstRunDialog  # noqa: E402
from mintsec_ui.dialogs.paused_app import PausedAppDialog  # noqa: E402
from mintsec_ui.i18n import set_language, tr  # noqa: E402
from mintsec_ui.pages.activity import ActivityPage  # noqa: E402
from mintsec_ui.pages.home import HomePage  # noqa: E402
from mintsec_ui.pages.module_detail import ModuleDetailPage  # noqa: E402
from mintsec_ui.pages.protections import ProtectionsPage  # noqa: E402
from mintsec_ui.pages.recovery import RecoveryPage  # noqa: E402
from mintsec_ui.pages.scans import ScansPage  # noqa: E402
from mintsec_ui.pages.settings import SettingsPage  # noqa: E402
from mintsec_ui.theme import ThemeManager  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    ASSETS_DIR,
    friendly_module_name,
    install_app_icon,
    make_illustration,
)

NAV_ITEMS = (
    ("home", "nav.home", "go-home-symbolic"),
    ("scans", "nav.scans", "system-search-symbolic"),
    ("protections", "nav.protections", "security-high-symbolic"),
    ("recovery", "nav.recovery", "document-revert-symbolic"),
    ("activity", "nav.activity", "view-list-symbolic"),
)

_ALL_NAV_ITEMS = (*NAV_ITEMS, ("settings", "nav.settings", "emblem-system-symbolic"))


class SuiteWindow(Gtk.ApplicationWindow):
    """Janela principal do NodusGuard com decoração nativa (SSD) e navegação instantânea."""

    def __init__(
        self,
        application: Gtk.Application | None,
        *,
        controller: SuiteController,
        theme_manager: ThemeManager | None = None,
        initial_width: int = 1180,
        initial_height: int = 740,
    ) -> None:
        super().__init__(application=application, title=APP_NAME)
        self.controller = controller
        set_language(self.controller.config_store.load().language)
        install_app_icon()

        self.theme_manager = theme_manager or ThemeManager()
        self.current_page = "home"
        self._is_compact = False
        self._destroyed = False
        self._cached_statuses: dict[str, Any] | None = None
        self._sidebar_buttons: dict[str, Gtk.Button] = {}
        self._sidebar_labels: dict[str, Gtk.Label] = {}
        self._nav_keys: dict[str, str] = {pid: key for pid, key, _icon in _ALL_NAV_ITEMS}

        logo_file = ASSETS_DIR / "nodusguard_logo.png"
        if logo_file.is_file():
            try:
                self.set_icon_from_file(str(logo_file))
            except Exception:
                pass

        # SSD nativo: não usamos set_titlebar()
        self.set_default_size(initial_width, initial_height)
        self.set_size_request(360, 420)
        self.get_style_context().add_class("mintsec-window")

        root = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=0)
        self.add(root)

        # Barra lateral minimalista com marca NodusGuard
        self.sidebar = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        self.sidebar.get_style_context().add_class("mintsec-sidebar")
        self.sidebar.set_size_request(220, -1)

        brand_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        brand_row.get_style_context().add_class("mintsec-brand-row")
        brand_logo = make_illustration(
            "nodusguard_logo.png",
            28,
            fallback_icon="security-high-symbolic",
        )
        brand_logo.set_valign(Gtk.Align.CENTER)
        b_title = Gtk.Label(label=APP_NAME, xalign=0.0)
        b_title.set_valign(Gtk.Align.CENTER)
        b_title.get_style_context().add_class("mintsec-brand-title")
        brand_row.pack_start(brand_logo, False, False, 0)
        brand_row.pack_start(b_title, True, True, 0)
        self.sidebar.pack_start(brand_row, False, False, 0)

        top_sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        top_sep.get_style_context().add_class("mintsec-divider")
        self.sidebar.pack_start(top_sep, False, False, 6)

        for page_id, key, icon_name in NAV_ITEMS:
            btn, lbl = self._make_nav_button(page_id, tr(key), icon_name)
            self.sidebar.pack_start(btn, False, False, 0)
            self._sidebar_buttons[page_id] = btn
            self._sidebar_labels[page_id] = lbl

        settings_btn, settings_lbl = self._make_nav_button(
            "settings", tr("nav.settings"), "emblem-system-symbolic"
        )
        self.sidebar.pack_end(settings_btn, False, False, 0)
        self._sidebar_buttons["settings"] = settings_btn
        self._sidebar_labels["settings"] = settings_lbl

        bot_sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
        bot_sep.get_style_context().add_class("mintsec-divider")
        self.sidebar.pack_end(bot_sep, False, False, 6)

        root.pack_start(self.sidebar, False, False, 0)

        # Área principal serena
        self.content_wrap = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.content_wrap.get_style_context().add_class("mintsec-content")
        self.content_wrap.set_margin_top(16)
        self.content_wrap.set_margin_bottom(14)
        self.content_wrap.set_margin_start(22)
        self.content_wrap.set_margin_end(22)
        root.pack_start(self.content_wrap, True, True, 0)

        # Cabeçalho limpo: Menu (compacto) + Título + Sino + Menu discreto (⋯)
        header_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        header_row.get_style_context().add_class("mintsec-header")

        self.menu_btn = Gtk.MenuButton()
        menu_inner = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        menu_inner.pack_start(
            Gtk.Image.new_from_icon_name("open-menu-symbolic", Gtk.IconSize.MENU),
            False,
            False,
            0,
        )
        self._menu_btn_lbl = Gtk.Label(label=tr("win.menu"))
        menu_inner.pack_start(self._menu_btn_lbl, False, False, 0)
        menu_inner.show_all()
        self.menu_btn.add(menu_inner)
        self.menu_btn.set_no_show_all(True)
        set_accessible(self.menu_btn, tr("win.menu_a11y"), tr("win.menu_desc"))
        self._build_compact_menu_popover()
        header_row.pack_start(self.menu_btn, False, False, 0)

        self.page_title_lbl = Gtk.Label(label=tr("page.home"), xalign=0.0)
        self.page_title_lbl.get_style_context().add_class("mintsec-page-title")
        header_row.pack_start(self.page_title_lbl, True, True, 0)

        self.bell_btn = Gtk.Button()
        self.bell_btn.get_style_context().add_class("mintsec-bell-btn")
        bell_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
        bell_icon = Gtk.Image.new_from_icon_name("preferences-system-notifications-symbolic", Gtk.IconSize.MENU)
        self.bell_count_lbl = Gtk.Label(label="0")
        bell_box.pack_start(bell_icon, False, False, 0)
        bell_box.pack_start(self.bell_count_lbl, False, False, 0)
        self.bell_btn.add(bell_box)
        self.bell_btn.connect("clicked", lambda *_: self.navigate_to("activity", tab="pending"))
        header_row.pack_start(self.bell_btn, False, False, 0)

        self.more_btn = Gtk.MenuButton()
        self.more_btn.get_style_context().add_class("mintsec-icon-btn")
        self.more_btn.set_image(
            Gtk.Image.new_from_icon_name("view-more-symbolic", Gtk.IconSize.MENU)
        )
        set_accessible(self.more_btn, tr("win.more_a11y"), tr("win.more_desc"))
        self._build_more_popover()
        header_row.pack_start(self.more_btn, False, False, 0)

        self.content_wrap.pack_start(header_row, False, False, 0)

        # Faixa discreta durante verificação em andamento
        self.active_scan_btn = Gtk.Button()
        self.active_scan_btn.get_style_context().add_class("mintsec-banner-active")
        self.active_scan_btn.set_no_show_all(True)
        self.active_scan_lbl = Gtk.Label(label="", xalign=0.0)
        self.active_scan_btn.add(self.active_scan_lbl)
        self.active_scan_btn.connect("clicked", lambda *_: self.navigate_to("scans", tab="scan"))
        set_accessible(
            self.active_scan_btn,
            tr("win.active_scan_a11y"),
            tr("win.active_scan_desc"),
        )
        self.content_wrap.pack_start(self.active_scan_btn, False, False, 0)

        # Área rolável plana + Stack sem transição custosa nem animação de overlay scrollbar
        self.scroller = Gtk.ScrolledWindow()
        self.scroller.set_policy(Gtk.PolicyType.NEVER, Gtk.PolicyType.AUTOMATIC)
        self.scroller.set_shadow_type(Gtk.ShadowType.NONE)
        self.scroller.set_overlay_scrolling(False)
        self.stack = Gtk.Stack()
        self.stack.set_transition_type(Gtk.StackTransitionType.NONE)
        self.stack.set_vhomogeneous(False)
        self.stack.set_hhomogeneous(False)
        self.scroller.add(self.stack)
        self.content_wrap.pack_start(self.scroller, True, True, 0)

        self.home_page = HomePage(self)
        self.scans_page = ScansPage(self)
        self.protections_page = ProtectionsPage(self)
        self.module_detail_page = ModuleDetailPage(self)
        self.recovery_page = RecoveryPage(self)
        self.activity_page = ActivityPage(self)
        self.settings_page = SettingsPage(self)

        self.pages: dict[str, Any] = {
            "home": self.home_page,
            "scans": self.scans_page,
            "protections": self.protections_page,
            "module_detail": self.module_detail_page,
            "recovery": self.recovery_page,
            "activity": self.activity_page,
            "settings": self.settings_page,
        }
        for page_id, widget in self.pages.items():
            self.stack.add_named(widget, page_id)

        self.connect("size-allocate", self._on_size_allocate)
        self.connect("destroy", self._on_destroy)
        self.show_all()
        self.apply_theme()
        self._update_nav_highlight("home")
        self._update_compact_mode(initial_width)

        if self.controller.is_live_host_runner:
            self._refresh_bell()
            self.home_page.refresh(statuses=None)
            self._schedule_async_refresh(force=True)
        else:
            self.refresh_all()

    def _on_destroy(self, *_args: object) -> None:
        self._destroyed = True
        self.scans_page.cancel_scan()
        self.theme_manager.cleanup()

    def _make_nav_button(self, page_id: str, label: str, icon_name: str) -> tuple[Gtk.Button, Gtk.Label]:
        btn = Gtk.Button()
        btn.get_style_context().add_class("mintsec-sidebar-btn")
        box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        icon = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.MENU)
        icon.set_pixel_size(16)
        lbl = Gtk.Label(label=label, xalign=0.0)
        box.pack_start(icon, False, False, 0)
        box.pack_start(lbl, True, True, 0)
        btn.add(box)
        set_accessible(btn, label, tr("win.nav_open_desc", label=label))
        btn.connect("clicked", lambda *_: self.navigate_to(page_id))
        return btn, lbl

    def _build_compact_menu_popover(self) -> None:
        popover = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(8)
        box.set_margin_end(8)
        for page_id, key, icon_name in _ALL_NAV_ITEMS:
            btn, _lbl = self._make_nav_button(page_id, tr(key), icon_name)
            btn.connect("clicked", lambda *_: popover.popdown())
            box.pack_start(btn, False, False, 0)
        box.show_all()
        popover.add(box)
        self.menu_btn.set_popover(popover)

    def _build_more_popover(self) -> None:
        popover = Gtk.Popover()
        box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
        box.set_margin_top(8)
        box.set_margin_bottom(8)
        box.set_margin_start(8)
        box.set_margin_end(8)

        actions = (
            (tr("win.refresh_now"), "view-refresh-symbolic", lambda: self.refresh_all(force=True)),
            (tr("win.initial_setup"), "security-high-symbolic", self.open_first_run_wizard),
            (tr("nav.settings"), "emblem-system-symbolic", lambda: self.navigate_to("settings")),
        )
        for label, icon_name, callback in actions:
            btn = Gtk.Button()
            btn.get_style_context().add_class("mintsec-ghost-btn")
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            ic = Gtk.Image.new_from_icon_name(icon_name, Gtk.IconSize.MENU)
            row.pack_start(ic, False, False, 0)
            row.pack_start(Gtk.Label(label=label, xalign=0.0), True, True, 0)
            btn.add(row)
            set_accessible(btn, label, label)
            btn.connect(
                "clicked",
                lambda _b, cb=callback: (popover.popdown(), cb()),
            )
            box.pack_start(btn, False, False, 0)
        box.show_all()
        popover.add(box)
        self.more_btn.set_popover(popover)

    def apply_language(self) -> None:
        """Atualiza idioma ao vivo em toda a janela e em todas as páginas."""
        cfg = self.controller.config_store.load()
        set_language(cfg.language)

        for page_id, btn in self._sidebar_buttons.items():
            label = tr(self._nav_keys[page_id])
            self._sidebar_labels[page_id].set_text(label)
            set_accessible(btn, label, tr("win.nav_open_desc", label=label))

        self._menu_btn_lbl.set_text(tr("win.menu"))
        set_accessible(self.menu_btn, tr("win.menu_a11y"), tr("win.menu_desc"))
        set_accessible(self.more_btn, tr("win.more_a11y"), tr("win.more_desc"))
        set_accessible(self.active_scan_btn, tr("win.active_scan_a11y"), tr("win.active_scan_desc"))

        self._build_compact_menu_popover()
        self._build_more_popover()
        self._update_current_page_title()

        for page in self.pages.values():
            if hasattr(page, "apply_language"):
                page.apply_language()

        self.refresh_all(force=False)

    def _update_current_page_title(self) -> None:
        if self.current_page == "module_detail":
            mod_id = self.module_detail_page.current_module_id
            title = friendly_module_name(mod_id, self.controller.manifests[mod_id].display_name)
        else:
            title = tr(f"page.{self.current_page}")
        self.page_title_lbl.set_text(title)

    def _update_nav_highlight(self, page_id: str) -> None:
        active_nav = "protections" if page_id == "module_detail" else page_id
        for nav_id, btn in self._sidebar_buttons.items():
            ctx = btn.get_style_context()
            if nav_id == active_nav:
                ctx.add_class("mintsec-active-nav")
            else:
                ctx.remove_class("mintsec-active-nav")

    def apply_theme(self) -> None:
        cfg = self.controller.config_store.load()
        self.theme_manager.apply(
            theme_mode=cfg.theme_mode,
            theme_preset=cfg.theme_preset,
            probe_widget=self,
            screen=self.get_screen(),
        )

    def set_active_scan_banner(self, visible: bool, text: str) -> None:
        if visible:
            self.active_scan_lbl.set_text(text)
            self.active_scan_lbl.show()
            self.active_scan_btn.show()
        else:
            self.active_scan_btn.hide()

    def _schedule_async_refresh(self, *, force: bool = False) -> None:
        if self._destroyed:
            return
        if not self.controller.is_live_host_runner:
            statuses = self.controller.all_statuses(use_cache=not force)
            self._apply_async_statuses(statuses)
            return

        def _bg_done(statuses: dict[str, Any]) -> None:
            if not self._destroyed and statuses:
                GLib.idle_add(self._on_async_statuses_ready, statuses)

        self.controller.refresh_statuses_async(_bg_done, force=force)

    def _on_async_statuses_ready(self, statuses: dict[str, Any]) -> bool:
        if self._destroyed:
            return False
        self._apply_async_statuses(statuses)
        return False

    def _apply_async_statuses(self, statuses: dict[str, Any]) -> None:
        self._cached_statuses = statuses
        self._refresh_bell()
        page_widget = self.pages.get(self.current_page)
        if page_widget is not None:
            self._invoke_page_refresh(page_widget, statuses=statuses)

    @staticmethod
    def _invoke_page_refresh(page_widget: Any, statuses: dict[str, Any] | None) -> None:
        if statuses is None:
            try:
                page_widget.refresh(statuses=None)
            except TypeError:
                page_widget.refresh()
        else:
            try:
                page_widget.refresh(statuses=statuses)
            except TypeError:
                page_widget.refresh()

    def navigate_to(self, page_id: str, *, tab: str | None = None, path: str | None = None) -> None:
        if page_id not in self.pages:
            return
        self.current_page = page_id
        self.stack.set_visible_child_name(page_id)
        self._update_current_page_title()
        self._update_nav_highlight(page_id)

        vadj = self.scroller.get_vadjustment()
        if vadj is not None and vadj.get_value() != 0.0:
            vadj.set_value(0.0)

        if page_id == "scans" and tab:
            self.scans_page.select_tab(tab)
        elif page_id == "recovery":
            self.recovery_page.select_tab(tab or "files", path=path)
        elif page_id == "activity" and tab:
            self.activity_page.select_tab(tab)

        if self.controller.is_live_host_runner:
            cached = self._cached_statuses or self.controller.get_cached_statuses()
            self._invoke_page_refresh(self.pages[page_id], statuses=cached)
            if self.controller.get_cached_statuses(max_age_secs=15.0) is None:
                self._schedule_async_refresh(force=False)
        else:
            self.pages[page_id].refresh()
        self._refresh_bell()

    def open_module_detail(self, module_id: str) -> None:
        cached = (
            (self._cached_statuses or self.controller.get_cached_statuses())
            if self.controller.is_live_host_runner
            else None
        )
        self.module_detail_page.load_module(module_id, statuses=cached)
        self.current_page = "module_detail"
        self.stack.set_visible_child_name("module_detail")
        self._update_current_page_title()
        self._update_nav_highlight("module_detail")
        vadj = self.scroller.get_vadjustment()
        if vadj is not None and vadj.get_value() != 0.0:
            vadj.set_value(0.0)
        self._refresh_bell()
        if self.controller.is_live_host_runner and self.controller.get_cached_statuses(max_age_secs=15.0) is None:
            self._schedule_async_refresh(force=False)

    def apply_module_status(self, module_id: str, new_status: Any) -> None:
        """Reflete imediatamente o estado retornado por enable/disable sem snap-back do Switch."""
        if self.controller.is_live_host_runner:
            base = dict(self._cached_statuses or self.controller.get_cached_statuses() or {})
            base[module_id] = new_status
            self._cached_statuses = base
        for page in (self.home_page, self.protections_page):
            page._last_render_sig = None
        self._refresh_bell()
        page_widget = self.pages.get(self.current_page)
        if page_widget is not None:
            self._invoke_page_refresh(
                page_widget,
                statuses=self._cached_statuses if self.controller.is_live_host_runner else None,
            )
        if self.controller.is_live_host_runner:
            self.controller.invalidate_cache(module_id)
            self._schedule_async_refresh(force=True)

    def refresh_all(self, *, force: bool = True) -> None:
        self._refresh_bell()
        if self.controller.is_live_host_runner:
            page_widget = self.pages.get(self.current_page)
            if page_widget is not None:
                self._invoke_page_refresh(page_widget, statuses=self._cached_statuses)
            if force:
                self.controller.invalidate_cache()
                self._schedule_async_refresh(force=True)
            return

        page_widget = self.pages.get(self.current_page)
        if page_widget is not None:
            page_widget.refresh()

    def _refresh_bell(self) -> None:
        count = self.controller.pending_store.count_open()
        self.bell_count_lbl.set_text(str(count))
        ctx = self.bell_btn.get_style_context()
        if count > 0:
            ctx.add_class("mintsec-bell-alert")
        else:
            ctx.remove_class("mintsec-bell-alert")
        set_accessible(
            self.bell_btn,
            tr("win.bell_a11y", count=count),
            tr("win.bell_desc"),
        )

    def open_first_run_wizard(self) -> None:
        dlg = FirstRunDialog(self, self.controller)
        resp = dlg.run()
        pause_pol = dlg.selected_pause_policy()
        en_am = dlg.chk_antimalware.get_active()
        en_fw = dlg.chk_firewall.get_active()
        dlg.destroy()

        if resp == Gtk.ResponseType.HELP:
            self.navigate_to("protections")
        elif resp == Gtk.ResponseType.OK:
            self.controller.complete_first_run(
                pause_policy=pause_pol,
                enable_antimalware=en_am,
                enable_firewall=en_fw,
                deferred=False,
            )
            self.refresh_all(force=True)
        elif resp == Gtk.ResponseType.CANCEL:
            self.controller.complete_first_run(deferred=True)
            self.refresh_all(force=False)

    def open_pending_review(self, pending_id: str) -> None:
        decision = self.controller.pending_store.get(pending_id)
        if decision is None:
            self.refresh_all(force=False)
            return
        if decision.kind == "paused_app":
            dlg = PausedAppDialog(
                self,
                controller=self.controller,
                decision=decision,
                on_open_recovery=self._on_open_incident_recovery,
                on_state_changed=lambda: self.refresh_all(force=False),
            )
            dlg.run()
            dlg.destroy()
            self.refresh_all(force=False)
            return

        approved = ask_action_confirmation(
            self,
            title=decision.title,
            summary=decision.summary,
            actor=decision.module_id,
            evidence=decision.evidence,
            confirm_label=tr("win.pending_resolve_confirm"),
            confirm_effect=tr("win.pending_resolve_effect"),
            cancel_label=tr("win.pending_keep_label"),
            cancel_effect=tr("win.pending_keep_effect"),
        )
        if approved:
            self.controller.pending_store.resolve(decision.pending_id, resolution="reviewed")
            self.refresh_all(force=False)

    def _on_open_incident_recovery(self, decision: Any, _full_backup: bool) -> None:
        target = decision.affected_paths[0] if decision.affected_paths else None
        self.navigate_to("recovery", tab="files", path=target)

    def _on_size_allocate(self, _widget: Gtk.Widget, allocation: Gdk.Rectangle) -> None:
        self._update_compact_mode(int(allocation.width))

    def _update_compact_mode(self, width: int) -> None:
        # Considera escala de fonte para entrar em modo compacto se necessário
        pango_ctx = self.get_pango_context()
        font_desc = pango_ctx.get_font_description()
        font_pt = font_desc.get_size() / 1024.0 if font_desc else 10.0
        threshold = 1080 if font_pt <= 11.5 else 1240
        compact = width <= threshold
        if compact == self._is_compact:
            return
        self._is_compact = compact
        if compact:
            self.sidebar.hide()
            self.menu_btn.show()
            self.content_wrap.set_margin_start(12)
            self.content_wrap.set_margin_end(12)
            self.content_wrap.set_margin_top(12)
        else:
            self.menu_btn.hide()
            self.sidebar.show()
            self.content_wrap.set_margin_start(22)
            self.content_wrap.set_margin_end(22)
            self.content_wrap.set_margin_top(16)
        self.home_page.set_compact(compact)
