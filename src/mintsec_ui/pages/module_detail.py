"""Tela única de detalhe de proteção em Flat Design (aberta por Início e Proteções)."""

from __future__ import annotations

from typing import Any

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.contracts import ModuleState  # noqa: E402
from mintsec.formatting import format_error_message, format_local_datetime  # noqa: E402
from mintsec_ui.a11y import relate_label, set_accessible  # noqa: E402
from mintsec_ui.actions import run_ui_task  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import get_language, tr  # noqa: E402
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


class ModuleDetailPage(Gtk.Box):
    """Exibe controles específicos, exceções e desativação do módulo selecionado."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self.current_module_id: str = "antimalware"
        self._fw_active_tab: int | None = None
        self._fw_search_text: str = ""
        self._fw_lan_only: bool = True
        self._fw_auto_allow_on_enable: bool = True
        self.fw_search_entry: Gtk.SearchEntry | None = None
        self.fw_presets_list_box: Gtk.Box | None = None
        self.fw_custom_name_entry: Gtk.Entry | None = None
        self.fw_custom_ports_entry: Gtk.Entry | None = None
        self.fw_notebook: Gtk.Notebook | None = None

        top_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._back_btn = Gtk.Button(label="")
        self._back_btn.get_style_context().add_class("mintsec-ghost-btn")
        self._back_btn.connect("clicked", lambda *_: self.app_window.navigate_to("protections"))
        top_bar.pack_start(self._back_btn, False, False, 0)
        self.pack_start(top_bar, False, False, 0)

        self.body_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.pack_start(self.body_box, False, False, 0)
        self.apply_language()

    def apply_language(self) -> None:
        self._back_btn.set_label(tr("detail.back_btn"))
        set_accessible(self._back_btn, tr("detail.back_a11y"), tr("detail.back_desc"))

    def load_module(self, module_id: str, statuses: dict[str, Any] | None = None) -> None:
        self.current_module_id = module_id
        self._fw_active_tab = None
        self.refresh(statuses=statuses)

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        clear_container(self.body_box)

        controller = self.app_window.controller
        mod_id = self.current_module_id
        manifest = controller.manifests[mod_id]

        if statuses is not None and mod_id in statuses:
            st = statuses[mod_id]
        elif controller.is_live_host_runner:
            cached = controller.get_cached_statuses()
            if cached is not None and mod_id in cached:
                st = cached[mod_id]
            else:
                st = None
        else:
            st = controller.get_module_status(mod_id)

        if st is None:
            card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            card.get_style_context().add_class("mintsec-card")
            card.pack_start(
                make_empty_state(
                    MODULE_ICONS.get(mod_id, "security-high-symbolic"),
                    friendly_module_name(mod_id, manifest.display_name),
                    tr("detail.loading_sub"),
                ),
                False,
                False,
                0,
            )
            self.body_box.pack_start(card, False, False, 0)
            self.body_box.show_all()
            return

        # Cabeçalho do módulo
        header_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=14)
        header_card.get_style_context().add_class("mintsec-card")
        tone = status_tone(st.state)
        chip_tone = "ok" if st.state == ModuleState.ATIVO else ("warn" if tone == "warn" else "accent")
        header_card.pack_start(
            make_icon_chip(MODULE_ICONS.get(mod_id, "security-high-symbolic"), pixel_size=22, tone=chip_tone),
            False,
            False,
            0,
        )

        hdr_col = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
        title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        display_title = friendly_module_name(mod_id, st.display_name)
        t_lbl = Gtk.Label(label=display_title, xalign=0.0)
        t_lbl.get_style_context().add_class("mintsec-hero-title")
        title_row.pack_start(t_lbl, False, False, 0)
        title_row.pack_start(make_pill(friendly_state_text(mod_id, st), tone=tone), False, False, 0)
        if st.experimental:
            title_row.pack_start(make_pill(tr("common.experimental"), tone="warn"), False, False, 0)
        hdr_col.pack_start(title_row, False, False, 0)

        tagline = friendly_module_tagline(mod_id, manifest.short_description)
        tagline_lbl = Gtk.Label(label=tagline, xalign=0.0)
        tagline_lbl.set_line_wrap(True)
        tagline_lbl.get_style_context().add_class("mintsec-muted")
        hdr_col.pack_start(tagline_lbl, False, False, 0)

        tech_exp = Gtk.Expander(label=tr("detail.tech_expander"))
        tech_exp.get_style_context().add_class("mintsec-expander")
        set_accessible(tech_exp, tr("detail.tech_expander"), tr("detail.tech_desc"))
        ver_str = f" ({st.installed_version})" if st.installed_version else ""
        meta = Gtk.Label(
            label=tr(
                "detail.tech_body",
                desc=manifest.short_description,
                engine=manifest.engine.get("name"),
                origin=st.package_origin,
                ver=ver_str,
                evidence=st.evidence,
            ),
            xalign=0.0,
        )
        meta.set_line_wrap(True)
        meta.set_margin_top(6)
        meta.get_style_context().add_class("mintsec-muted")
        tech_exp.add(meta)
        hdr_col.pack_start(tech_exp, False, False, 0)
        header_card.pack_start(hdr_col, True, True, 0)
        self.body_box.pack_start(header_card, False, False, 0)

        # Seção específica por módulo
        if mod_id == "antimalware":
            self._build_antimalware_section(st)
        elif mod_id == "firewall":
            self._build_firewall_section(st)
        elif mod_id == "recovery":
            self._build_recovery_section(st)
        elif mod_id == "network":
            self._build_network_section(st)
        elif mod_id == "browsing":
            self._build_browsing_section(st)
        elif mod_id == "isolation":
            self._build_isolation_section(st)
        elif mod_id == "rescue":
            self._build_rescue_section(st)

        # Desativação e reversão (comum a módulos ativos ou configurados)
        if st.state != ModuleState.AUSENTE:
            ctrl_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=12)
            ctrl_card.get_style_context().add_class("mintsec-card")

            c_txt = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
            c_title = Gtk.Label(label=tr("detail.disable_title"), xalign=0.0)
            c_title.get_style_context().add_class("mintsec-subtitle")
            c_sub = Gtk.Label(label=tr("detail.disable_sub"), xalign=0.0)
            c_sub.set_line_wrap(True)
            c_sub.get_style_context().add_class("mintsec-muted")
            c_txt.pack_start(c_title, False, False, 0)
            c_txt.pack_start(c_sub, False, False, 0)

            disable_btn = Gtk.Button(label=tr("detail.disable_btn"))
            disable_btn.get_style_context().add_class("destructive-action")
            disable_btn.set_valign(Gtk.Align.CENTER)
            set_accessible(
                disable_btn,
                tr("detail.disable_a11y", name=display_title),
                tr("detail.disable_desc"),
            )
            disable_btn.connect("clicked", lambda b: self._on_disable_module(mod_id, b))
            ctrl_card.pack_start(c_txt, True, True, 0)
            ctrl_card.pack_start(disable_btn, False, False, 0)
            self.body_box.pack_start(ctrl_card, False, False, 0)

        self.body_box.show_all()

    def _build_antimalware_section(self, st: Any) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        card.get_style_context().add_class("mintsec-card")
        sig = st.details.get("signatures", {})
        sig_text = (
            tr("detail.am_sigs_ok", ts=format_local_datetime(sig.get("updated_at")))
            if sig.get("available")
            else tr("detail.am_sigs_missing")
        )
        sig_lbl = Gtk.Label(label=sig_text, xalign=0.0)
        sig_lbl.get_style_context().add_class("mintsec-subtitle")
        card.pack_start(sig_lbl, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        upd_lbl = tr("detail.am_update_btn")
        upd_btn = Gtk.Button(label=upd_lbl)
        upd_btn.get_style_context().add_class("mintsec-primary-cta")
        set_accessible(upd_btn, upd_lbl, tr("detail.am_update_desc"))
        upd_btn.set_sensitive(st.state != ModuleState.AUSENTE)
        upd_btn.connect("clicked", lambda b: self._on_update_clamav(b))

        scans_lbl = tr("detail.am_open_scans")
        scans_btn = Gtk.Button(label=scans_lbl)
        set_accessible(scans_btn, scans_lbl, tr("detail.am_open_scans_desc"))
        scans_btn.connect("clicked", lambda *_: self.app_window.navigate_to("scans"))

        row.pack_start(upd_btn, False, False, 0)
        row.pack_start(scans_btn, False, False, 0)
        card.pack_start(row, False, False, 0)

        exc_lbl = Gtk.Label(label=tr("detail.am_excl_label"), xalign=0.0)
        exc_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        exc_entry = Gtk.Entry()
        exc_entry.set_text(", ".join(st.details.get("exclusions", [])))
        relate_label(exc_lbl, exc_entry)
        set_accessible(exc_entry, tr("detail.am_excl_a11y"), tr("detail.am_excl_desc"))
        save_lbl = tr("detail.am_excl_save")
        save_exc = Gtk.Button(label=save_lbl)
        set_accessible(save_exc, save_lbl, tr("detail.am_excl_save_desc"))
        save_exc.connect(
            "clicked",
            lambda *_: self._save_am_exclusions(exc_entry.get_text()),
        )
        exc_row.pack_start(exc_entry, True, True, 0)
        exc_row.pack_start(save_exc, False, False, 0)
        card.pack_start(exc_lbl, False, False, 0)
        card.pack_start(exc_row, False, False, 0)
        self.body_box.pack_start(card, False, False, 0)

    def _build_firewall_section(self, st: Any) -> None:
        nb = Gtk.Notebook()
        nb.get_style_context().add_class("mintsec-tabs")
        self.fw_notebook = nb
        lan_cidr = str(st.details.get("lan_cidr") or "192.168.0.0/16")

        # Aba 1: Entrada
        in_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        in_box.set_margin_top(6)
        in_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        in_card.get_style_context().add_class("mintsec-card")

        preview_hdr = Gtk.Label(label=tr("detail.fw_preview_hdr"), xalign=0.0)
        preview_hdr.get_style_context().add_class("mintsec-subtitle")
        preview_hdr.set_line_wrap(True)
        in_card.pack_start(preview_hdr, False, False, 0)
        for rule in st.details.get("essential_rules", []):
            rl = Gtk.Label(
                label=f"{rule['title']} ({rule['port_proto']}) — {rule['reason']}",
                xalign=0.0,
            )
            rl.set_line_wrap(True)
            rl.get_style_context().add_class("mintsec-muted")
            in_card.pack_start(rl, False, False, 0)

        auto_allow_chk = Gtk.CheckButton(label=tr("detail.fw_auto_allow_chk"))
        auto_allow_chk.set_active(self._fw_auto_allow_on_enable)
        set_accessible(auto_allow_chk, tr("detail.fw_auto_allow_chk"), tr("detail.fw_auto_allow_desc"))
        auto_allow_chk.connect(
            "toggled",
            lambda chk: setattr(self, "_fw_auto_allow_on_enable", bool(chk.get_active())),
        )
        in_card.pack_start(auto_allow_chk, False, False, 0)

        act_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        act_lbl = tr("detail.fw_enable_btn")
        act_btn = Gtk.Button(label=act_lbl)
        act_btn.get_style_context().add_class("mintsec-primary-cta")
        set_accessible(act_btn, act_lbl, tr("detail.fw_enable_desc"))
        act_btn.connect("clicked", lambda b: self._on_enable_firewall(b))
        act_row.pack_start(act_btn, False, False, 0)
        in_card.pack_start(act_row, False, False, 0)
        in_box.pack_start(in_card, False, False, 0)
        nb.append_page(in_box, Gtk.Label(label=tr("detail.fw_tab_in")))

        # Aba 2: Permitir aplicativos (KDE Connect, AudioRelay, perfis e portas personalizadas)
        apps_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        apps_box.set_margin_top(6)

        presets_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        presets_card.get_style_context().add_class("mintsec-card")

        p_title = Gtk.Label(label=tr("detail.fw_presets_title"), xalign=0.0)
        p_title.get_style_context().add_class("mintsec-section-title")
        p_sub = Gtk.Label(label=tr("detail.fw_presets_sub"), xalign=0.0)
        p_sub.set_line_wrap(True)
        p_sub.get_style_context().add_class("mintsec-muted")
        presets_card.pack_start(p_title, False, False, 0)
        presets_card.pack_start(p_sub, False, False, 0)

        ctrl_bar = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        search_entry = Gtk.SearchEntry()
        search_entry.set_placeholder_text(tr("detail.fw_apps_search_ph"))
        search_entry.set_text(self._fw_search_text)
        set_accessible(
            search_entry,
            tr("detail.fw_apps_search_a11y"),
            tr("detail.fw_apps_search_desc"),
        )
        self.fw_search_entry = search_entry

        lan_chk = Gtk.CheckButton(label=tr("detail.fw_lan_chk", cidr=lan_cidr))
        lan_chk.set_active(self._fw_lan_only)
        set_accessible(lan_chk, tr("detail.fw_lan_chk", cidr=lan_cidr), tr("detail.fw_lan_chk_desc"))
        lan_chk.connect(
            "toggled",
            lambda chk: setattr(self, "_fw_lan_only", bool(chk.get_active())),
        )
        ctrl_bar.pack_start(search_entry, True, True, 0)
        ctrl_bar.pack_start(lan_chk, False, False, 0)
        presets_card.pack_start(ctrl_bar, False, False, 0)

        presets_list = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.fw_presets_list_box = presets_list
        presets_data = list(st.details.get("app_presets") or [])

        def _populate_presets(query_txt: str) -> None:
            clear_container(presets_list)
            q = query_txt.strip().lower()
            is_pt = get_language() == "pt_BR"
            matched = []
            for p in presets_data:
                summary = p.get("summary_pt") if is_pt else p.get("summary_en")
                hay = f"{p.get('name', '')} {summary or ''} {' '.join(p.get('ports') or [])}".lower()
                if not q or q in hay:
                    matched.append(p)
            if not matched:
                empty_lbl = Gtk.Label(label=tr("detail.fw_apps_no_match"), xalign=0.0)
                empty_lbl.set_line_wrap(True)
                empty_lbl.get_style_context().add_class("mintsec-muted")
                presets_list.pack_start(empty_lbl, False, False, 0)
                presets_list.show_all()
                return

            for idx, preset in enumerate(matched):
                if idx > 0:
                    sep = Gtk.Separator(orientation=Gtk.Orientation.HORIZONTAL)
                    sep.get_style_context().add_class("mintsec-divider")
                    presets_list.pack_start(sep, False, False, 0)
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                row.set_margin_top(4)
                row.set_margin_bottom(4)

                info = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
                title_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=6)
                n_lbl = Gtk.Label(label=str(preset.get("name", "")), xalign=0.0)
                n_lbl.get_style_context().add_class("mintsec-subtitle")
                title_row.pack_start(n_lbl, False, False, 0)
                if preset.get("running"):
                    title_row.pack_start(make_pill(tr("detail.fw_badge_running"), tone="accent"), False, False, 0)
                elif preset.get("installed"):
                    title_row.pack_start(make_pill(tr("detail.fw_badge_installed"), tone="neutral"), False, False, 0)
                if preset.get("allowed"):
                    title_row.pack_start(make_pill(tr("detail.fw_badge_allowed"), tone="ok"), False, False, 0)
                info.pack_start(title_row, False, False, 0)

                summary_txt = str((preset.get("summary_pt") if is_pt else preset.get("summary_en")) or "")
                s_lbl = Gtk.Label(label=summary_txt, xalign=0.0)
                s_lbl.set_line_wrap(True)
                s_lbl.get_style_context().add_class("mintsec-muted")
                info.pack_start(s_lbl, False, False, 0)

                ports_txt = tr("detail.fw_ports_line", ports=", ".join(preset.get("ports") or []))
                pt_lbl = Gtk.Label(label=ports_txt, xalign=0.0)
                pt_lbl.get_style_context().add_class("mintsec-muted")
                info.pack_start(pt_lbl, False, False, 0)
                row.pack_start(info, True, True, 0)

                pid = str(preset["preset_id"])
                pname = str(preset.get("name", pid))
                if preset.get("allowed"):
                    btn = Gtk.Button(label=tr("detail.fw_remove_app_btn"))
                    btn.set_valign(Gtk.Align.CENTER)
                    set_accessible(
                        btn,
                        tr("detail.fw_remove_app_a11y", name=pname),
                        tr("detail.fw_remove_app_desc", name=pname),
                    )
                    btn.connect("clicked", lambda b, p_id=pid: self._on_revoke_fw_preset(p_id, b))
                else:
                    btn = Gtk.Button(label=tr("detail.fw_allow_btn"))
                    btn.set_valign(Gtk.Align.CENTER)
                    if preset.get("detected"):
                        btn.get_style_context().add_class("mintsec-primary-cta")
                    set_accessible(
                        btn,
                        tr("detail.fw_allow_a11y", name=pname),
                        tr("detail.fw_allow_desc", name=pname),
                    )
                    btn.connect(
                        "clicked",
                        lambda b, p_id=pid: self._on_allow_fw_preset(
                            p_id,
                            lan_chk.get_active(),
                            b,
                        ),
                    )
                row.pack_start(btn, False, False, 0)
                presets_list.pack_start(row, False, False, 0)
            presets_list.show_all()

        _populate_presets(self._fw_search_text)

        def _on_search_changed(entry: Gtk.SearchEntry) -> None:
            self._fw_search_text = entry.get_text()
            _populate_presets(self._fw_search_text)

        search_entry.connect("changed", _on_search_changed)
        presets_card.pack_start(presets_list, False, False, 0)
        apps_box.pack_start(presets_card, False, False, 0)

        # Processos ativos detectados fora de presets conhecidos
        unmatched_listening = [
            item
            for item in (st.details.get("listening_apps") or [])
            if not item.get("preset_id") and item.get("ports")
        ]
        if unmatched_listening:
            listen_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            listen_card.get_style_context().add_class("mintsec-card")
            lt = Gtk.Label(label=tr("detail.fw_listening_title"), xalign=0.0)
            lt.get_style_context().add_class("mintsec-section-title")
            ls = Gtk.Label(label=tr("detail.fw_listening_sub"), xalign=0.0)
            ls.set_line_wrap(True)
            ls.get_style_context().add_class("mintsec-muted")
            listen_card.pack_start(lt, False, False, 0)
            listen_card.pack_start(ls, False, False, 0)
            for item in unmatched_listening[:8]:
                proc_name = str(item.get("process", ""))
                ports_list = list(item.get("ports") or [])
                lrow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                ll = Gtk.Label(
                    label=f"{proc_name} — {', '.join(ports_list)}",
                    xalign=0.0,
                )
                ll.set_line_wrap(True)
                lbtn = Gtk.Button(label=tr("detail.fw_allow_lan_btn"))
                set_accessible(
                    lbtn,
                    tr("detail.fw_allow_a11y", name=proc_name),
                    tr("detail.fw_allow_desc", name=proc_name),
                )
                lbtn.connect(
                    "clicked",
                    lambda b, nm=proc_name, pts=ports_list: self._on_allow_custom_ports(
                        nm,
                        ", ".join(pts),
                        "both",
                        "in",
                        True,
                        b,
                    ),
                )
                lrow.pack_start(ll, True, True, 0)
                lrow.pack_start(lbtn, False, False, 0)
                listen_card.pack_start(lrow, False, False, 0)
            apps_box.pack_start(listen_card, False, False, 0)

        # Formulário para liberar outro app ou porta personalizada
        custom_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        custom_card.get_style_context().add_class("mintsec-card")
        c_title = Gtk.Label(label=tr("detail.fw_custom_title"), xalign=0.0)
        c_title.get_style_context().add_class("mintsec-section-title")
        custom_card.pack_start(c_title, False, False, 0)

        grid_row1 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        name_lbl = Gtk.Label(label=tr("detail.fw_custom_name_lbl"), xalign=0.0)
        custom_name = Gtk.Entry()
        custom_name.set_placeholder_text(tr("detail.fw_custom_name_ph"))
        relate_label(name_lbl, custom_name)
        set_accessible(custom_name, tr("detail.fw_custom_name_lbl"), tr("detail.fw_custom_name_ph"))
        self.fw_custom_name_entry = custom_name

        ports_lbl = Gtk.Label(label=tr("detail.fw_custom_ports_lbl"), xalign=0.0)
        custom_ports = Gtk.Entry()
        custom_ports.set_placeholder_text(tr("detail.fw_custom_ports_ph"))
        relate_label(ports_lbl, custom_ports)
        set_accessible(custom_ports, tr("detail.fw_custom_ports_lbl"), tr("detail.fw_custom_ports_ph"))
        self.fw_custom_ports_entry = custom_ports

        grid_row1.pack_start(name_lbl, False, False, 0)
        grid_row1.pack_start(custom_name, True, True, 0)
        grid_row1.pack_start(ports_lbl, False, False, 0)
        grid_row1.pack_start(custom_ports, True, True, 0)
        custom_card.pack_start(grid_row1, False, False, 0)

        grid_row2 = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        proto_lbl = Gtk.Label(label=tr("detail.fw_custom_proto_lbl"), xalign=0.0)
        custom_proto = Gtk.ComboBoxText()
        custom_proto.append("both", tr("detail.fw_custom_proto_both"))
        custom_proto.append("tcp", tr("detail.fw_custom_proto_tcp"))
        custom_proto.append("udp", tr("detail.fw_custom_proto_udp"))
        custom_proto.set_active_id("both")
        relate_label(proto_lbl, custom_proto)
        set_accessible(custom_proto, tr("detail.fw_custom_proto_lbl"))

        dir_lbl = Gtk.Label(label=tr("detail.fw_custom_dir_lbl"), xalign=0.0)
        custom_dir = Gtk.ComboBoxText()
        custom_dir.append("in", tr("detail.fw_custom_dir_in"))
        custom_dir.append("out", tr("detail.fw_custom_dir_out"))
        custom_dir.set_active_id("in")
        relate_label(dir_lbl, custom_dir)
        set_accessible(custom_dir, tr("detail.fw_custom_dir_lbl"))

        custom_lan = Gtk.CheckButton(label=tr("detail.fw_lan_chk", cidr=lan_cidr))
        custom_lan.set_active(True)
        set_accessible(custom_lan, tr("detail.fw_lan_chk", cidr=lan_cidr), tr("detail.fw_lan_chk_desc"))

        custom_btn = Gtk.Button(label=tr("detail.fw_custom_btn"))
        custom_btn.get_style_context().add_class("mintsec-primary-cta")
        set_accessible(custom_btn, tr("detail.fw_custom_btn"), tr("detail.fw_custom_btn_desc"))
        custom_btn.connect(
            "clicked",
            lambda b: self._on_allow_custom_ports(
                custom_name.get_text(),
                custom_ports.get_text(),
                custom_proto.get_active_id() or "both",
                custom_dir.get_active_id() or "in",
                custom_lan.get_active(),
                b,
            ),
        )
        grid_row2.pack_start(proto_lbl, False, False, 0)
        grid_row2.pack_start(custom_proto, False, False, 0)
        grid_row2.pack_start(dir_lbl, False, False, 0)
        grid_row2.pack_start(custom_dir, False, False, 0)
        grid_row2.pack_start(custom_lan, True, True, 0)
        grid_row2.pack_start(custom_btn, False, False, 0)
        custom_card.pack_start(grid_row2, False, False, 0)
        apps_box.pack_start(custom_card, False, False, 0)

        # Perfis UFW do sistema (/etc/ufw/applications.d)
        ufw_profiles = list(st.details.get("ufw_profiles") or [])
        if ufw_profiles:
            prof_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
            prof_card.get_style_context().add_class("mintsec-card")
            pr_title = Gtk.Label(label=tr("detail.fw_profiles_title"), xalign=0.0)
            pr_title.get_style_context().add_class("mintsec-section-title")
            prof_card.pack_start(pr_title, False, False, 0)
            for prof in ufw_profiles[:12]:
                p_name = str(prof["name"])
                prow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                plbl = Gtk.Label(
                    label=f"{prof.get('title', p_name)} ({prof.get('ports', '')})",
                    xalign=0.0,
                )
                plbl.set_line_wrap(True)
                pbtn = Gtk.Button(label=tr("detail.fw_profile_allow_btn"))
                set_accessible(
                    pbtn,
                    f"{tr('detail.fw_profile_allow_btn')}: {p_name}",
                    tr("detail.fw_profile_allow_desc", name=p_name),
                )
                pbtn.connect("clicked", lambda b, nm=p_name: self._on_allow_ufw_profile(nm, b))
                prow.pack_start(plbl, True, True, 0)
                prow.pack_start(pbtn, False, False, 0)
                prof_card.pack_start(prow, False, False, 0)
            apps_box.pack_start(prof_card, False, False, 0)

        nb.append_page(apps_box, Gtk.Label(label=tr("detail.fw_tab_apps")))

        # Aba 3: Saída
        out_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        out_box.set_margin_top(6)
        out_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        out_card.get_style_context().add_class("mintsec-card")
        os_installed = st.details.get("opensnitch_installed", False)
        out_info = Gtk.Label(
            label=tr("detail.fw_os_present") if os_installed else tr("detail.fw_os_missing"),
            xalign=0.0,
        )
        out_info.set_line_wrap(True)
        out_info.get_style_context().add_class("mintsec-subtitle")
        out_card.pack_start(out_info, False, False, 0)

        current_outbound = st.details.get("outbound_mode", "monitor_only")
        mode_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        mon_lbl = tr("detail.fw_mon_btn")
        blk_lbl = tr("detail.fw_blk_btn")
        btn_mon = Gtk.Button(label=mon_lbl)
        btn_blk = Gtk.Button(label=blk_lbl)
        if current_outbound == "monitor_only":
            btn_mon.get_style_context().add_class("mintsec-primary-cta")
        else:
            btn_blk.get_style_context().add_class("mintsec-primary-cta")
        set_accessible(btn_mon, mon_lbl, tr("detail.fw_mon_desc"))
        set_accessible(btn_blk, blk_lbl, tr("detail.fw_blk_desc"))
        btn_mon.connect("clicked", lambda *_: self._set_fw_outbound("monitor_only"))
        btn_blk.connect("clicked", lambda *_: self._set_fw_outbound("block_per_app"))
        mode_row.pack_start(btn_mon, False, False, 0)
        mode_row.pack_start(btn_blk, False, False, 0)
        out_card.pack_start(mode_row, False, False, 0)

        labels = st.details.get("contract_labels", {})
        contract_lbl = Gtk.Label(
            label=tr("detail.fw_first_conn", choices=" · ".join(labels.values())),
            xalign=0.0,
        )
        contract_lbl.set_line_wrap(True)
        contract_lbl.get_style_context().add_class("mintsec-muted")
        out_card.pack_start(contract_lbl, False, False, 0)

        for denial in st.details.get("denials", [])[-5:]:
            d_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            d_lbl = Gtk.Label(
                label=tr(
                    "detail.fw_denied_line",
                    app=denial["app_name"],
                    dest=denial["destination"],
                    reason=denial["reason"],
                ),
                xalign=0.0,
            )
            d_lbl.set_line_wrap(True)
            allow_next = Gtk.Button(label=tr("detail.fw_allow_next"))
            set_accessible(
                allow_next,
                tr("detail.fw_allow_next_a11y", app=denial["app_name"]),
                tr("detail.fw_allow_next_desc"),
            )
            allow_next.connect(
                "clicked",
                lambda _b, app=denial["app_name"]: (
                    self.app_window.controller.firewall.opensnitch.allow_next_attempt(app),
                    self.app_window.controller.invalidate_cache("firewall"),
                    self.app_window.refresh_all(force=True),
                ),
            )
            d_row.pack_start(d_lbl, True, True, 0)
            d_row.pack_start(allow_next, False, False, 0)
            out_card.pack_start(d_row, False, False, 0)

        for trust_rule in st.details.get("trust_rules", []):
            status_str = (
                tr("detail.fw_trust_active")
                if trust_rule["active"]
                else tr("detail.fw_trust_pending")
            )
            t_lbl = Gtk.Label(
                label=tr(
                    "detail.fw_trust_line",
                    mode=trust_rule["trust_mode"],
                    exe=trust_rule["executable_path"],
                    sha=trust_rule["sha256"][:12],
                    status=status_str,
                ),
                xalign=0.0,
            )
            t_lbl.set_line_wrap(True)
            out_card.pack_start(t_lbl, False, False, 0)

        out_box.pack_start(out_card, False, False, 0)
        nb.append_page(out_box, Gtk.Label(label=tr("detail.fw_tab_out")))

        # Aba 4: Regras aplicadas
        rules_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        rules_box.set_margin_top(6)
        rules_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        rules_card.get_style_context().add_class("mintsec-card")
        rules = st.details.get("rules", [])
        if not rules:
            rules_card.pack_start(
                make_empty_state(
                    "security-high-symbolic",
                    tr("detail.fw_rules_empty_title"),
                    tr("detail.fw_rules_empty_sub"),
                ),
                False,
                False,
                0,
            )
        else:
            for r in rules:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                src_note = f" (LAN {r['source_cidr']})" if r.get("source_cidr") else ""
                r_lbl = Gtk.Label(
                    label=f"{r['direction'].upper()} {r['action']} {r['target']}{src_note} — {r['scope']}",
                    xalign=0.0,
                )
                r_lbl.set_line_wrap(True)
                row.pack_start(r_lbl, True, True, 0)
                if r.get("managed_by_suite"):
                    rev = Gtk.Button(label=tr("act.revoke_btn"))
                    set_accessible(
                        rev,
                        f"{tr('act.revoke_btn')} {r['target']}",
                        tr("act.revoke_desc"),
                    )
                    rev.connect("clicked", lambda b, rid=r["rule_id"]: self._on_revoke_fw_rule(rid, b))
                    row.pack_start(rev, False, False, 0)
                rules_card.pack_start(row, False, False, 0)
        rules_box.pack_start(rules_card, False, False, 0)
        nb.append_page(rules_box, Gtk.Label(label=tr("detail.fw_tab_rules")))
        self.body_box.pack_start(nb, False, False, 0)
        nb.show_all()

        target_tab = (
            self._fw_active_tab
            if self._fw_active_tab is not None
            else (1 if st.state == ModuleState.ATIVO else 0)
        )
        nb.set_current_page(target_tab)
        nb.connect(
            "switch-page",
            lambda _nb, _pg, page_num: setattr(self, "_fw_active_tab", int(page_num)),
        )

    def _build_recovery_section(self, st: Any) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("mintsec-card")
        cfg = st.details.get("restic", {}).get("config", {})
        lbl = Gtk.Label(
            label=tr(
                "detail.rec_summary",
                repo=cfg.get("repo_path") or tr("detail.rec_not_set"),
                bk=format_local_datetime(cfg.get("last_backup_at")),
                tst=format_local_datetime(cfg.get("last_restore_test_at")),
            ),
            xalign=0.0,
        )
        lbl.set_line_wrap(True)
        card.pack_start(lbl, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        open_lbl = tr("detail.rec_open_btn")
        open_rec = Gtk.Button(label=open_lbl)
        open_rec.get_style_context().add_class("mintsec-primary-cta")
        set_accessible(open_rec, open_lbl, tr("detail.rec_open_desc"))
        open_rec.connect("clicked", lambda *_: self.app_window.navigate_to("recovery"))
        row.pack_start(open_rec, False, False, 0)
        card.pack_start(row, False, False, 0)
        self.body_box.pack_start(card, False, False, 0)

    def _build_network_section(self, st: Any) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("mintsec-card")
        conn = st.details.get("active_connection", {})
        net_id = conn.get("connection_name") or conn.get("interface") or tr("detail.net_none")
        is_home = bool(st.details.get("is_home", False))
        iso = bool(st.details.get("client_isolation", False))

        hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        hdr_lbl = Gtk.Label(label=tr("detail.net_current", net=net_id), xalign=0.0)
        hdr_lbl.get_style_context().add_class("mintsec-section-title")
        hdr.pack_start(hdr_lbl, True, True, 0)
        hdr.pack_start(
            make_pill(
                tr("detail.net_home_pill") if is_home else tr("detail.net_other_pill"),
                tone="ok" if is_home else "neutral",
            ),
            False,
            False,
            0,
        )
        card.pack_start(hdr, False, False, 0)

        if iso:
            iso_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            iso_box.get_style_context().add_class("mintsec-callout")
            iso_box.get_style_context().add_class("mintsec-callout-warn")
            iso_lbl = Gtk.Label(
                label=st.details.get("isolation_explanation") or tr("detail.net_iso_fallback"),
                xalign=0.0,
            )
            iso_lbl.set_line_wrap(True)
            iso_box.pack_start(iso_lbl, True, True, 0)
            card.pack_start(iso_box, False, False, 0)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        home_btn = Gtk.Button(
            label=tr("detail.net_unmark_home") if is_home else tr("detail.net_mark_home")
        )
        set_accessible(home_btn, tr("detail.net_mark_a11y"), tr("detail.net_mark_desc"))
        home_btn.connect(
            "clicked",
            lambda *_: (
                self.app_window.controller.network.set_network_home(net_id, not is_home),
                self.app_window.controller.invalidate_cache("network"),
                self.app_window.refresh_all(force=True),
            ),
        )
        disc_lbl = tr("detail.net_discover")
        disc_btn = Gtk.Button(label=disc_lbl)
        if is_home:
            disc_btn.get_style_context().add_class("mintsec-primary-cta")
        disc_btn.set_sensitive(is_home)
        set_accessible(disc_btn, disc_lbl, tr("detail.net_discover_desc"))
        disc_btn.connect(
            "clicked",
            lambda *_: self._on_network_discover(net_id),
        )
        btn_row.pack_start(home_btn, False, False, 0)
        btn_row.pack_start(disc_btn, False, False, 0)
        card.pack_start(btn_row, False, False, 0)

        devices = st.details.get("devices", [])
        if not devices:
            card.pack_start(
                make_empty_state(
                    "network-wireless-symbolic",
                    tr("detail.net_empty_title"),
                    tr("detail.net_empty_sub"),
                ),
                False,
                False,
                0,
            )
        else:
            for dev in devices[:15]:
                drow = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                label_txt = dev.get("custom_name") or dev.get("hostname") or dev.get("mac")
                drow.pack_start(
                    Gtk.Label(
                        label=f"{label_txt} ({dev.get('ip') or tr('detail.net_no_ip')}) — {dev.get('mac')}",
                        xalign=0.0,
                    ),
                    True,
                    True,
                    0,
                )
                if not dev.get("recognized"):
                    rec_btn = Gtk.Button(label=tr("detail.net_recognize"))
                    set_accessible(
                        rec_btn,
                        tr("detail.net_recognize_a11y", mac=dev.get("mac")),
                        tr("detail.net_recognize_desc"),
                    )
                    rec_btn.connect(
                        "clicked",
                        lambda _b, m=dev["mac"], nm=label_txt: self._on_network_recognize(m, nm),
                    )
                    drow.pack_start(rec_btn, False, False, 0)
                card.pack_start(drow, False, False, 0)
        self.body_box.pack_start(card, False, False, 0)

    def _build_browsing_section(self, st: Any) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("mintsec-card")
        engine = st.details.get("engine", "dnsmasq")
        vpn_doms = st.details.get("vpn_private_domains", [])
        doh = st.details.get("doh_warnings", [])

        card.pack_start(
            Gtk.Label(
                label=tr(
                    "detail.brow_summary",
                    engine=engine,
                    exc_count=len(st.details.get("local_exceptions", [])),
                    vpn=", ".join(vpn_doms) if vpn_doms else tr("detail.brow_vpn_none"),
                ),
                xalign=0.0,
            ),
            False,
            False,
            0,
        )
        for w in doh:
            w_box = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
            w_box.get_style_context().add_class("mintsec-callout")
            w_box.get_style_context().add_class("mintsec-callout-warn")
            w_lbl = Gtk.Label(
                label=tr("detail.brow_warn", browser=w["browser"], detail=w["detail"]),
                xalign=0.0,
            )
            w_lbl.set_line_wrap(True)
            w_box.pack_start(w_lbl, True, True, 0)
            card.pack_start(w_box, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        dom_entry = Gtk.Entry()
        dom_entry.set_placeholder_text(tr("detail.brow_placeholder"))
        set_accessible(dom_entry, tr("detail.brow_dom_a11y"), tr("detail.brow_dom_desc"))
        reason_btn = Gtk.Button(label=tr("detail.brow_reason_btn"))
        set_accessible(reason_btn, tr("detail.brow_reason_a11y"), tr("detail.brow_reason_desc"))
        exc_lbl = tr("detail.brow_exc_btn")
        exc_btn = Gtk.Button(label=exc_lbl)
        set_accessible(exc_btn, exc_lbl, tr("detail.brow_exc_desc"))
        feedback = Gtk.Label(label="", xalign=0.0)
        feedback.set_line_wrap(True)
        feedback.get_style_context().add_class("mintsec-muted")

        def _on_reason(_b: Gtk.Button) -> None:
            info = self.app_window.controller.browsing.lookup_block_origin(dom_entry.get_text())
            feedback.set_text(f"{info['domain']}: {info['origin']}")

        def _on_exc(_b: Gtk.Button) -> None:
            try:
                self.app_window.controller.browsing.add_local_exception(dom_entry.get_text())
                self.app_window.controller.invalidate_cache("browsing")
                self.app_window.refresh_all(force=True)
            except Exception as exc:
                feedback.set_text(str(exc))

        reason_btn.connect("clicked", _on_reason)
        exc_btn.connect("clicked", _on_exc)
        row.pack_start(dom_entry, True, True, 0)
        row.pack_start(reason_btn, False, False, 0)
        row.pack_start(exc_btn, False, False, 0)
        card.pack_start(row, False, False, 0)
        card.pack_start(feedback, False, False, 0)
        self.body_box.pack_start(card, False, False, 0)

    def _build_isolation_section(self, st: Any) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("mintsec-card")
        aa = st.details.get("apparmor", {})
        bank = st.details.get("bank_mode", {})
        lbl = Gtk.Label(
            label=tr(
                "detail.iso_summary",
                count=aa.get("enforce_count", 0),
                x11=st.details.get("x11_warning", ""),
                bank=bank.get("status_note", tr("detail.iso_bank_fallback")),
            ),
            xalign=0.0,
        )
        lbl.set_line_wrap(True)
        card.pack_start(lbl, False, False, 0)

        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        launch_lbl = tr("detail.iso_launch_btn")
        launch_btn = Gtk.Button(label=launch_lbl)
        launch_btn.get_style_context().add_class("mintsec-primary-cta")
        launch_btn.set_sensitive(bool(st.details.get("browser_available", False)))
        set_accessible(launch_btn, launch_lbl, tr("detail.iso_launch_desc"))
        launch_btn.connect("clicked", self._on_launch_isolated_browser)
        row.pack_start(launch_btn, False, False, 0)
        card.pack_start(row, False, False, 0)
        self.body_box.pack_start(card, False, False, 0)

    def _on_network_discover(self, net_id: str) -> None:
        try:
            self.app_window.controller.network.active_discover(net_id)
            self.app_window.controller.invalidate_cache("network")
            self.app_window.refresh_all(force=True)
        except Exception as exc:
            self._show_error(str(exc))

    def _on_network_recognize(self, mac: str, label: str) -> None:
        try:
            self.app_window.controller.network.recognize_device(mac, label)
            self.app_window.controller.invalidate_cache("network")
            self.app_window.refresh_all(force=True)
        except Exception as exc:
            self._show_error(str(exc))

    def _on_launch_isolated_browser(self, *_args: object) -> None:
        import os
        import shutil
        import subprocess
        import tempfile
        import threading
        from pathlib import Path

        iso = self.app_window.controller.isolation
        bcmd = iso.detect_browser_command()
        if not bcmd:
            return
        prof = Path(tempfile.mkdtemp(prefix="mintsec-browser-"))
        os.chmod(prof, 0o700)
        try:
            cmd = iso.build_bwrap_command(browser_cmd=bcmd, profile_dir=prof)
            proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            shutil.rmtree(prof, ignore_errors=True)
            raise

        def _reap_and_cleanup() -> None:
            try:
                proc.wait()
            finally:
                shutil.rmtree(prof, ignore_errors=True)

        threading.Thread(target=_reap_and_cleanup, daemon=True).start()

    def _build_rescue_section(self, _st: Any) -> None:
        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("mintsec-card")
        lbl = Gtk.Label(label=tr("detail.rescue_note"), xalign=0.0)
        lbl.set_line_wrap(True)
        card.pack_start(lbl, False, False, 0)
        row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        btn = Gtk.Button(label=tr("detail.rescue_btn"))
        btn.get_style_context().add_class("mintsec-primary-cta")
        set_accessible(btn, tr("detail.rescue_a11y"), tr("detail.rescue_desc"))
        btn.connect("clicked", lambda *_: self.app_window.navigate_to("recovery", tab="rescue"))
        row.pack_start(btn, False, False, 0)
        card.pack_start(row, False, False, 0)
        self.body_box.pack_start(card, False, False, 0)

    def _on_update_clamav(self, btn: Any = None, *_args: object) -> None:
        def _done(_res: dict[str, Any]) -> None:
            if not _res.get("ok"):
                err_txt = str(_res.get("stderr") or _res.get("stdout") or "freshclam failed").strip()
                self._show_error(err_txt)
                return
            self.app_window.refresh_all(force=True)

        run_ui_task(
            self.app_window,
            self.app_window.controller.update_antimalware_signatures,
            on_success=_done,
            on_error=lambda exc: self._show_error(format_error_message(exc)),
            busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
        )

    def _save_am_exclusions(self, raw_text: str) -> None:
        items = [part.strip() for part in raw_text.split(",") if part.strip()]
        self.app_window.controller.antimalware.configure(exclusions=items)
        self.app_window.controller.invalidate_cache("antimalware")
        self.app_window.refresh_all(force=True)

    def _on_enable_firewall(self, btn: Any = None, *_args: object) -> None:
        ok = ask_action_confirmation(
            self.app_window,
            title=tr("detail.fw_confirm_title"),
            summary=tr("detail.fw_confirm_summary"),
            actor=tr("detail.fw_confirm_actor"),
            evidence=tr("detail.fw_confirm_evidence"),
            confirm_label=tr("detail.fw_confirm_label"),
            confirm_effect=tr("detail.fw_confirm_effect"),
        )
        if ok:
            def _do_enable() -> Any:
                ctrl = self.app_window.controller
                new_st = ctrl.enable_module("firewall", apply_essential_rules=True)
                if self._fw_auto_allow_on_enable:
                    ctrl._auto_allow_detected_lan_apps()
                    new_st = ctrl.get_module_status("firewall")
                return new_st

            run_ui_task(
                self.app_window,
                _do_enable,
                on_success=lambda new_st: self.app_window.apply_module_status("firewall", new_st),
                on_error=lambda exc: self._show_error(format_error_message(exc)),
                busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
            )

    def _on_allow_fw_preset(self, preset_id: str, lan_only: bool, btn: Any = None) -> None:
        run_ui_task(
            self.app_window,
            lambda: self.app_window.controller.allow_firewall_preset(preset_id, lan_only=lan_only),
            on_success=lambda _res: self.app_window.refresh_all(force=True),
            on_error=lambda exc: self._show_error(format_error_message(exc)),
            busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
        )

    def _on_revoke_fw_preset(self, preset_id: str, btn: Any = None) -> None:
        run_ui_task(
            self.app_window,
            lambda: self.app_window.controller.revoke_firewall_preset(preset_id),
            on_success=lambda _res: self.app_window.refresh_all(force=True),
            on_error=lambda exc: self._show_error(format_error_message(exc)),
            busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
        )

    def _on_allow_custom_ports(
        self,
        raw_name: str,
        raw_ports: str,
        protocol: str,
        direction: str,
        lan_only: bool,
        btn: Any = None,
    ) -> None:
        app_name = str(raw_name or "").strip()
        ports = [
            tok.strip()
            for part in str(raw_ports or "").split(",")
            for tok in part.split()
            if tok.strip()
        ]
        if not app_name or not ports:
            self._show_error(tr("detail.fw_custom_missing"))
            return

        def _done(_res: Any) -> None:
            if self.fw_custom_name_entry is not None:
                self.fw_custom_name_entry.set_text("")
            if self.fw_custom_ports_entry is not None:
                self.fw_custom_ports_entry.set_text("")
            self.app_window.refresh_all(force=True)

        run_ui_task(
            self.app_window,
            lambda: self.app_window.controller.allow_firewall_custom_ports(
                app_name=app_name,
                ports=ports,
                direction=direction,
                protocol=protocol,
                lan_only=lan_only,
            ),
            on_success=_done,
            on_error=lambda exc: self._show_error(format_error_message(exc)),
            busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
        )

    def _on_allow_ufw_profile(self, profile_name: str, btn: Any = None) -> None:
        run_ui_task(
            self.app_window,
            lambda: self.app_window.controller.allow_firewall_ufw_profile(profile_name),
            on_success=lambda _res: self.app_window.refresh_all(force=True),
            on_error=lambda exc: self._show_error(format_error_message(exc)),
            busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
        )

    def _set_fw_outbound(self, mode: str) -> None:
        self.app_window.controller.firewall.configure(outbound_mode=mode)
        self.app_window.controller.invalidate_cache("firewall")
        self.app_window.refresh_all(force=True)

    def _on_revoke_fw_rule(self, rule_id: str, btn: Any = None) -> None:
        run_ui_task(
            self.app_window,
            lambda: self.app_window.controller.revoke_firewall_rule(rule_id),
            on_success=lambda _ok: self.app_window.refresh_all(force=True),
            on_error=lambda exc: self._show_error(format_error_message(exc)),
            busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
        )

    def _on_disable_module(self, mod_id: str, btn: Any = None) -> None:
        friendly = friendly_module_name(
            mod_id,
            self.app_window.controller.manifests[mod_id].display_name,
        )
        ok = ask_action_confirmation(
            self.app_window,
            title=tr("detail.disable_btn"),
            summary=tr("detail.disable_confirm_summary", name=friendly),
            actor="NodusGuard",
            evidence=tr("actions.disable_evidence"),
            confirm_label=tr("detail.disable_confirm_label"),
            confirm_effect=tr("detail.disable_confirm_effect"),
        )
        if ok:
            run_ui_task(
                self.app_window,
                lambda: self.app_window.controller.disable_module(mod_id, revert_suite_changes=True),
                on_success=lambda new_st: self.app_window.apply_module_status(mod_id, new_st),
                on_error=lambda exc: self._show_error(format_error_message(exc)),
                busy_widget=btn if isinstance(btn, Gtk.Widget) else None,
            )

    def _show_error(self, message: str) -> None:
        ask_action_confirmation(
            self.app_window,
            title=tr("detail.err_title"),
            summary=message,
            actor=tr("detail.err_actor"),
            evidence=tr("detail.err_evidence"),
            confirm_label=tr("common.close"),
            confirm_effect=tr("common.close_notice"),
        )
