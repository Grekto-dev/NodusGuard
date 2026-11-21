"""Página Recuperação em Flat Design: Meus arquivos, Sistema (Timeshift) e USB de resgate."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.formatting import format_bytes, format_local_datetime  # noqa: E402
from mintsec_ui.a11y import relate_label, set_accessible  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402
from mintsec_ui.widgets import (  # noqa: E402
    clear_container,
    make_empty_state,
    make_icon_chip,
    make_illustration,
    make_pill,
)


def populate_incident_cards(
    container: Gtk.Box,
    parent_window: Any,
    controller: Any,
    on_cleaned: Any = None,
) -> None:
    """Popula a seção de Pasta do Incidente em Recuperação e em Atividade."""
    clear_container(container)
    inc_title = Gtk.Label(label=tr("rec.inc_title"), xalign=0.0)
    inc_title.get_style_context().add_class("mintsec-section-title")
    container.pack_start(inc_title, False, False, 0)
    reports = controller.incident_manager.list_incidents()
    if not reports:
        container.pack_start(
            make_empty_state(
                "folder-symbolic",
                tr("rec.inc_empty_title"),
                tr("rec.inc_empty_sub"),
            ),
            False,
            False,
            0,
        )
    else:
        for rep in reports:
            row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
            row.set_margin_top(4)
            info = Gtk.Label(
                label=tr(
                    "rec.inc_row",
                    iid=rep.incident_id,
                    count=len(rep.items),
                    size=format_bytes(rep.total_bytes),
                    path=rep.incident_dir,
                ),
                xalign=0.0,
            )
            info.set_line_wrap(True)
            clean_btn = Gtk.Button(label=tr("rec.inc_clean_btn"))
            clean_btn.get_style_context().add_class("destructive-action")
            set_accessible(
                clean_btn,
                tr("rec.inc_clean_a11y", iid=rep.incident_id),
                tr("rec.inc_clean_desc"),
            )

            def _cleanup(_b: Gtk.Button, iid: str = rep.incident_id) -> None:
                ok = ask_action_confirmation(
                    parent_window,
                    title=tr("rec.inc_confirm_title"),
                    summary=tr("rec.inc_confirm_summary", iid=iid),
                    actor=tr("rec.inc_confirm_actor"),
                    evidence=tr("rec.inc_confirm_evidence"),
                    confirm_label=tr("rec.inc_confirm_label"),
                    confirm_effect=tr("rec.inc_confirm_effect"),
                    destructive=True,
                )
                if ok:
                    freed = controller.incident_manager.cleanup_incident(iid, confirmed=True)
                    if on_cleaned is not None:
                        on_cleaned(freed)
                    parent_window.refresh_all(force=False)

            clean_btn.connect("clicked", _cleanup)
            row.pack_start(info, True, True, 0)
            row.pack_start(clean_btn, False, False, 0)
            container.pack_start(row, False, False, 0)
    container.show_all()


class RecoveryPage(Gtk.Box):
    """Gerencia cópias pessoais, pontos do sistema, pasta do incidente e USB de resgate."""

    def __init__(self, app_window: Any) -> None:
        super().__init__(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.app_window = app_window
        self._preselected_path: str | None = None
        self._last_inc_sig: Any = None
        self._last_ts_sig: Any = None
        self._last_usb_sig: Any = None

        self.notebook = Gtk.Notebook()
        self.notebook.get_style_context().add_class("mintsec-tabs")
        self.pack_start(self.notebook, True, True, 0)

        self.files_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.files_tab.set_margin_top(6)
        self.files_tab.set_margin_bottom(12)
        self._build_files_tab()
        self._tab_files_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.files_tab, self._tab_files_lbl)

        self.system_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.system_tab.set_margin_top(6)
        self.system_tab.set_margin_bottom(12)
        self._build_system_tab()
        self._tab_system_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.system_tab, self._tab_system_lbl)

        self.rescue_tab = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=12)
        self.rescue_tab.set_margin_top(6)
        self.rescue_tab.set_margin_bottom(12)
        self._build_rescue_tab()
        self._tab_rescue_lbl = Gtk.Label(label="")
        self.notebook.append_page(self.rescue_tab, self._tab_rescue_lbl)

        self.apply_language()

    def select_tab(self, tab_name: str, path: str | None = None) -> None:
        mapping = {"files": 0, "system": 1, "rescue": 2}
        if tab_name in mapping:
            self.notebook.set_current_page(mapping[tab_name])
        if path:
            self._preselected_path = path
            self.restore_filter_entry.set_text(path)
            self.setup_expander.set_expanded(True)

    def _build_files_tab(self) -> None:
        hero_card = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=18)
        hero_card.get_style_context().add_class("mintsec-card")
        hero_card.get_style_context().add_class("mintsec-hero-card")

        self._art = make_illustration(
            "spot_recovery.png",
            108,
            fallback_icon="folder-saved-search-symbolic",
            a11y_name=tr("rec.art_a11y"),
        )
        self._art.set_valign(Gtk.Align.CENTER)
        hero_card.pack_start(self._art, False, False, 0)

        hero_body = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        self._files_hdr = Gtk.Label(label="", xalign=0.0)
        self._files_hdr.get_style_context().add_class("mintsec-hero-title")
        hero_body.pack_start(self._files_hdr, False, False, 0)

        self._files_sub = Gtk.Label(label="", xalign=0.0)
        self._files_sub.set_line_wrap(True)
        self._files_sub.get_style_context().add_class("mintsec-muted")
        hero_body.pack_start(self._files_sub, False, False, 0)

        metrics_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        metrics_row.set_homogeneous(True)

        chip_bk = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        chip_bk.get_style_context().add_class("mintsec-metric-chip")
        self._bk_cap = Gtk.Label(label="", xalign=0.0)
        self._bk_cap.get_style_context().add_class("mintsec-caption")
        self.last_bk_lbl = Gtk.Label(label="", xalign=0.0)
        self.last_bk_lbl.get_style_context().add_class("mintsec-metric-value")
        chip_bk.pack_start(self._bk_cap, False, False, 0)
        chip_bk.pack_start(self.last_bk_lbl, False, False, 0)

        chip_tst = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=2)
        chip_tst.get_style_context().add_class("mintsec-metric-chip")
        self._tst_cap = Gtk.Label(label="", xalign=0.0)
        self._tst_cap.get_style_context().add_class("mintsec-caption")
        self.last_tst_lbl = Gtk.Label(label="", xalign=0.0)
        self.last_tst_lbl.get_style_context().add_class("mintsec-metric-value")
        chip_tst.pack_start(self._tst_cap, False, False, 0)
        chip_tst.pack_start(self.last_tst_lbl, False, False, 0)

        metrics_row.pack_start(chip_bk, True, True, 0)
        metrics_row.pack_start(chip_tst, True, True, 0)
        hero_body.pack_start(metrics_row, False, False, 0)

        action_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.btn_backup_now = Gtk.Button(label="")
        self.btn_backup_now.get_style_context().add_class("mintsec-primary-cta")
        self.btn_backup_now.connect("clicked", self._on_backup_now)

        self.btn_restore_other = Gtk.Button(label="")
        self.btn_restore_other.get_style_context().add_class("mintsec-ghost-btn")
        self.btn_restore_other.connect("clicked", self._on_restore_other_folder)

        action_row.pack_start(self.btn_backup_now, False, False, 0)
        action_row.pack_start(self.btn_restore_other, False, False, 0)
        hero_body.pack_start(action_row, False, False, 0)

        self.files_feedback = Gtk.Label(label="", xalign=0.0)
        self.files_feedback.set_line_wrap(True)
        self.files_feedback.get_style_context().add_class("mintsec-muted")
        hero_body.pack_start(self.files_feedback, False, False, 0)

        hero_card.pack_start(hero_body, True, True, 0)
        self.files_tab.pack_start(hero_card, False, False, 0)

        # Opções de destino e manutenção recolhíveis para manter a tela leve
        cfg_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        cfg_card.get_style_context().add_class("mintsec-card")

        self.setup_expander = Gtk.Expander(label="")
        self.setup_expander.get_style_context().add_class("mintsec-expander")

        exp_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        exp_box.set_margin_top(10)

        self._guidance_lbl = Gtk.Label(label="", xalign=0.0)
        self._guidance_lbl.set_line_wrap(True)
        self._guidance_lbl.get_style_context().add_class("mintsec-muted")
        exp_box.pack_start(self._guidance_lbl, False, False, 0)

        repo_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._repo_lbl = Gtk.Label(label="", xalign=0.0)
        self.repo_entry = Gtk.Entry()
        relate_label(self._repo_lbl, self.repo_entry)

        self.repo_type_combo = Gtk.ComboBoxText()

        self._save_repo_btn = Gtk.Button(label="")
        self._save_repo_btn.connect("clicked", self._on_save_repo)

        repo_row.pack_start(self._repo_lbl, False, False, 0)
        repo_row.pack_start(self.repo_entry, True, True, 0)
        repo_row.pack_start(self.repo_type_combo, False, False, 0)
        repo_row.pack_start(self._save_repo_btn, False, False, 0)
        exp_box.pack_start(repo_row, False, False, 0)

        self.sep_cred_check = Gtk.CheckButton(label="")
        exp_box.pack_start(self.sep_cred_check, False, False, 0)

        filter_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self._filter_lbl = Gtk.Label(label="", xalign=0.0)
        self.restore_filter_entry = Gtk.Entry()
        relate_label(self._filter_lbl, self.restore_filter_entry)
        filter_row.pack_start(self._filter_lbl, False, False, 0)
        filter_row.pack_start(self.restore_filter_entry, True, True, 0)
        exp_box.pack_start(filter_row, False, False, 0)

        extra_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        self.btn_test_restore = Gtk.Button(label="")
        self.btn_test_restore.get_style_context().add_class("mintsec-ghost-btn")
        self.btn_test_restore.connect("clicked", self._on_test_restore)
        extra_row.pack_start(self.btn_test_restore, False, False, 0)
        exp_box.pack_start(extra_row, False, False, 0)

        self.setup_expander.add(exp_box)
        cfg_card.pack_start(self.setup_expander, False, False, 0)
        self.files_tab.pack_start(cfg_card, False, False, 0)

        # Seção da pasta do incidente
        self.incident_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.incident_card.get_style_context().add_class("mintsec-card")
        self.files_tab.pack_start(self.incident_card, False, False, 0)

    def _build_system_tab(self) -> None:
        self.timeshift_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        self.system_tab.pack_start(self.timeshift_box, False, False, 0)

    def _build_rescue_tab(self) -> None:
        callout = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        callout.get_style_context().add_class("mintsec-callout")
        callout.pack_start(make_icon_chip("drive-removable-media-symbolic", pixel_size=16, tone="warn"), False, False, 0)
        self._rescue_callout_lbl = Gtk.Label(label="", xalign=0.0)
        self._rescue_callout_lbl.set_line_wrap(True)
        self._rescue_callout_lbl.get_style_context().add_class("mintsec-muted")
        callout.pack_start(self._rescue_callout_lbl, True, True, 0)
        self.rescue_tab.pack_start(callout, False, False, 0)

        card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        card.get_style_context().add_class("mintsec-card")
        self._usb_list_title = Gtk.Label(label="", xalign=0.0)
        self._usb_list_title.get_style_context().add_class("mintsec-section-title")
        card.pack_start(self._usb_list_title, False, False, 0)

        self.usb_list_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        card.pack_start(self.usb_list_box, False, False, 0)
        self.rescue_tab.pack_start(card, False, False, 0)

    def apply_language(self) -> None:
        self._tab_files_lbl.set_text(tr("rec.tab_files"))
        self._tab_system_lbl.set_text(tr("rec.tab_system"))
        self._tab_rescue_lbl.set_text(tr("rec.tab_rescue"))

        set_accessible(self._art, tr("rec.art_a11y"), tr("rec.art_a11y"))
        self._files_hdr.set_text(tr("rec.files_title"))
        self._files_sub.set_text(tr("rec.files_sub"))
        self._bk_cap.set_text(tr("rec.last_backup_cap"))
        self._tst_cap.set_text(tr("rec.last_test_cap"))

        bk_lbl = tr("rec.btn_backup_now")
        self.btn_backup_now.set_label(bk_lbl)
        set_accessible(self.btn_backup_now, bk_lbl, tr("rec.btn_backup_desc"))

        self.btn_restore_other.set_label(tr("rec.btn_restore_other"))
        set_accessible(self.btn_restore_other, tr("rec.btn_restore_other_a11y"), tr("rec.btn_restore_other_desc"))

        self.setup_expander.set_label(tr("rec.setup_expander"))
        set_accessible(self.setup_expander, tr("rec.setup_expander"), tr("rec.setup_expander_desc"))
        self._guidance_lbl.set_text(tr("rec.guidance"))

        self._repo_lbl.set_text(tr("rec.repo_label"))
        self.repo_entry.set_placeholder_text(tr("rec.repo_placeholder"))
        set_accessible(self.repo_entry, tr("rec.repo_a11y"), tr("rec.repo_desc"))

        active_repo_type = self.repo_type_combo.get_active_id() or "removable_offline"
        self.repo_type_combo.remove_all()
        self.repo_type_combo.append("removable_offline", tr("rec.type_removable"))
        self.repo_type_combo.append("append_only_remote", tr("rec.type_remote"))
        self.repo_type_combo.append("local", tr("rec.type_local"))
        self.repo_type_combo.set_active_id(active_repo_type)
        set_accessible(self.repo_type_combo, tr("rec.type_a11y"), tr("rec.type_desc"))

        self._save_repo_btn.set_label(tr("common.save"))
        set_accessible(self._save_repo_btn, tr("rec.save_repo_a11y"), tr("rec.save_repo_desc"))

        self.sep_cred_check.set_label(tr("rec.sep_cred"))
        set_accessible(self.sep_cred_check, tr("rec.sep_cred_a11y"), tr("rec.sep_cred_desc"))

        self._filter_lbl.set_text(tr("rec.filter_label"))
        self.restore_filter_entry.set_placeholder_text(tr("rec.filter_placeholder"))
        set_accessible(self.restore_filter_entry, tr("rec.filter_a11y"), tr("rec.filter_desc"))

        tst_lbl = tr("rec.test_restore_btn")
        self.btn_test_restore.set_label(tst_lbl)
        set_accessible(self.btn_test_restore, tst_lbl, tr("rec.test_restore_desc"))

        self._rescue_callout_lbl.set_text(tr("rec.rescue_callout"))
        self._usb_list_title.set_text(tr("rec.usb_list_title"))

        self._last_inc_sig = None
        self._last_ts_sig = None
        self._last_usb_sig = None

    def refresh(self, statuses: dict[str, Any] | None = None) -> None:
        controller = self.app_window.controller
        lang = controller.config_store.load().language
        if statuses is not None and "recovery" in statuses and "rescue" in statuses:
            st = statuses["recovery"]
            rescue_st = statuses["rescue"]
        elif controller.is_live_host_runner:
            cached = controller.get_cached_statuses()
            if cached is not None and "recovery" in cached and "rescue" in cached:
                st = cached["recovery"]
                rescue_st = cached["rescue"]
            else:
                st = None
                rescue_st = None
        else:
            st = controller.recovery.query_status()
            rescue_st = controller.rescue.query_status()

        if st is not None:
            restic_cfg = st.details.get("restic", {}).get("config", {})
            repo_val = (restic_cfg.get("repo_path") or "").strip()
            if not self.repo_entry.get_text():
                self.repo_entry.set_text(repo_val)
            if not repo_val and not self.repo_entry.get_text().strip():
                self.setup_expander.set_expanded(True)
            self.repo_type_combo.set_active_id(restic_cfg.get("repo_type", "removable_offline"))
            self.sep_cred_check.set_active(bool(restic_cfg.get("separate_maintenance_credential", False)))

            last_bk = format_local_datetime(restic_cfg.get("last_backup_at"))
            last_tst = format_local_datetime(restic_cfg.get("last_restore_test_at"))
            tst_res = restic_cfg.get("last_restore_test_result") or tr("rec.last_test_never")
            self.last_bk_lbl.set_text(last_bk or tr("rec.last_backup_never"))
            self.last_tst_lbl.set_text(f"{last_tst} · {tst_res}" if restic_cfg.get("last_restore_test_at") else tst_res)
            self._refresh_timeshift(st.details.get("timeshift", {}), lang)
        else:
            self.last_bk_lbl.set_text(tr("common.checking"))
            self.last_tst_lbl.set_text(tr("common.checking"))

        reports = controller.incident_manager.list_incidents()
        inc_sig = (lang, tuple((r.incident_id, r.total_bytes, len(r.items)) for r in reports))
        if inc_sig != self._last_inc_sig:
            self._last_inc_sig = inc_sig
            populate_incident_cards(
                self.incident_card,
                self.app_window,
                controller,
                on_cleaned=lambda freed: self.files_feedback.set_text(
                    tr("rec.inc_cleaned_msg", size=format_bytes(freed))
                ),
            )

        if rescue_st is not None:
            self._refresh_usb_list(rescue_st, lang)

    def _refresh_timeshift(self, ts: dict[str, Any], lang: str = "en") -> None:
        sig = (
            lang,
            ts.get("installed"),
            ts.get("version"),
            ts.get("mode"),
            tuple((s.get("name"), s.get("mode"), s.get("comments")) for s in ts.get("snapshots", [])),
        )
        if sig == self._last_ts_sig:
            return
        self._last_ts_sig = sig

        clear_container(self.timeshift_box)
        ts_card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=10)
        ts_card.get_style_context().add_class("mintsec-card")

        hdr = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
        hdr.pack_start(make_icon_chip("document-revert-symbolic", pixel_size=18, tone="accent"), False, False, 0)
        ts_title = Gtk.Label(label=tr("rec.ts_title"), xalign=0.0)
        ts_title.get_style_context().add_class("mintsec-section-title")
        hdr.pack_start(ts_title, True, True, 0)
        if ts.get("installed"):
            hdr.pack_start(
                make_pill(tr("rec.ts_mode", mode=ts.get("mode", "local")), tone="neutral"),
                False,
                False,
                0,
            )
        ts_card.pack_start(hdr, False, False, 0)

        if not ts.get("installed"):
            ts_card.pack_start(
                make_empty_state(
                    "document-revert-symbolic",
                    tr("rec.ts_missing_title"),
                    tr("rec.ts_missing_sub"),
                ),
                False,
                False,
                0,
            )
        else:
            meta = Gtk.Label(
                label=tr("rec.ts_meta", version=ts.get("version"), origin=ts.get("origin")),
                xalign=0.0,
            )
            meta.get_style_context().add_class("mintsec-muted")
            ts_card.pack_start(meta, False, False, 0)
            snaps = ts.get("snapshots", [])
            if not snaps:
                ts_card.pack_start(
                    make_empty_state(
                        "document-revert-symbolic",
                        tr("rec.ts_empty_title"),
                        tr("rec.ts_empty_sub"),
                    ),
                    False,
                    False,
                    0,
                )
            else:
                for snap in snaps:
                    s_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
                    s_row.pack_start(Gtk.Label(label=snap["name"], xalign=0.0), False, False, 0)
                    s_row.pack_start(make_pill(snap["mode"], tone="neutral"), False, False, 0)
                    c_lbl = Gtk.Label(label=snap.get("comments") or tr("rec.ts_comment_fallback"), xalign=0.0)
                    c_lbl.get_style_context().add_class("mintsec-muted")
                    s_row.pack_start(c_lbl, True, True, 0)
                    ts_card.pack_start(s_row, False, False, 0)
        self.timeshift_box.pack_start(ts_card, False, False, 0)
        self.timeshift_box.show_all()

    def _refresh_usb_list(self, rescue_st: Any, lang: str = "en") -> None:
        candidates = rescue_st.details.get("candidates", [])
        safe = [c for c in candidates if c.get("safe_for_rescue_write")]
        sig = (
            lang,
            rescue_st.details.get("protected_count", 0),
            bool(rescue_st.details.get("h7_approved")),
            tuple((c.get("path"), c.get("size_bytes"), c.get("model")) for c in safe),
        )
        if sig == self._last_usb_sig:
            return
        self._last_usb_sig = sig

        clear_container(self.usb_list_box)
        if not safe:
            self.usb_list_box.pack_start(
                make_empty_state(
                    "drive-removable-media-symbolic",
                    tr("rec.usb_empty_title"),
                    tr("rec.usb_empty_sub", count=rescue_st.details.get("protected_count", 0)),
                ),
                False,
                False,
                0,
            )
        else:
            for c in safe:
                row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
                lbl = Gtk.Label(
                    label=f"{c['model']} ({format_bytes(c['size_bytes'])}) — {c['path']} [{c.get('serial') or c.get('wwn')}]",
                    xalign=0.0,
                )
                lbl.set_line_wrap(True)
                row.pack_start(lbl, True, True, 0)
                self.usb_list_box.pack_start(row, False, False, 0)

        btn_row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
        write_lbl = tr("rec.usb_write_btn")
        write_btn = Gtk.Button(label=write_lbl)
        can_write = bool(safe) and bool(rescue_st.details.get("h7_approved"))
        write_btn.set_sensitive(can_write)
        if can_write:
            write_btn.get_style_context().add_class("destructive-action")
        set_accessible(write_btn, write_lbl, tr("rec.usb_write_desc"))
        if safe:
            write_btn.connect("clicked", lambda _b, cand=safe[0]: self._on_write_rescue_usb(cand))
        btn_row.pack_start(write_btn, False, False, 0)
        self.usb_list_box.pack_start(btn_row, False, False, 0)
        self.usb_list_box.show_all()

    def _on_write_rescue_usb(self, cand_dict: dict[str, Any]) -> None:
        from mintsec.services.rescue import BlockDeviceCandidate

        chooser = Gtk.FileChooserDialog(
            title=tr("rec.usb_choose_iso"),
            transient_for=self.app_window,
            action=Gtk.FileChooserAction.OPEN,
        )
        chooser.add_buttons(
            tr("common.cancel"),
            Gtk.ResponseType.CANCEL,
            tr("common.select"),
            Gtk.ResponseType.OK,
        )
        iso_path = chooser.get_filename() if chooser.run() == Gtk.ResponseType.OK else None
        chooser.destroy()
        if not iso_path:
            return

        ok = ask_action_confirmation(
            self.app_window,
            title=tr("rec.usb_confirm_title"),
            summary=tr(
                "rec.usb_confirm_summary",
                model=cand_dict["model"],
                size=format_bytes(cand_dict["size_bytes"]),
                path=cand_dict["path"],
            ),
            actor=tr("rec.usb_confirm_actor"),
            evidence=tr(
                "rec.usb_confirm_evidence",
                serial=cand_dict.get("serial") or cand_dict.get("wwn"),
                iso=iso_path,
            ),
            confirm_label=tr("rec.usb_write_btn"),
            confirm_effect=tr("rec.usb_confirm_effect"),
            destructive=True,
        )
        if not ok:
            return

        cand = BlockDeviceCandidate(**cand_dict)
        try:
            res = self.app_window.controller.rescue.validate_and_write_image(
                image_path=Path(iso_path),
                target_path=Path(cand.path),
                expected_identity=cand,
                reopened_identity=cand,
                confirmed=True,
                use_udisks2=True,
            )
            self.files_feedback.set_text(
                tr("rec.usb_done_msg", size=format_bytes(res["bytes_written"]), sha=res["sha256"][:12])
            )
        except Exception as exc:
            self.files_feedback.set_text(tr("rec.usb_fail_msg", err=exc))

    def _on_save_repo(self, *_args: object) -> None:
        repo_path = self.repo_entry.get_text().strip()
        repo_type = self.repo_type_combo.get_active_id() or "removable_offline"
        self.app_window.controller.recovery.configure(
            repo_path=repo_path,
            repo_type=repo_type,
            separate_maintenance_credential=self.sep_cred_check.get_active(),
        )
        self.app_window.controller.invalidate_cache("recovery")
        self.files_feedback.set_text(tr("rec.repo_saved_msg"))
        self.app_window.refresh_all(force=True)

    def _ask_repo_password(self, title: str) -> str | None:
        dialog = Gtk.Dialog(
            title=title,
            transient_for=self.app_window,
            modal=True,
        )
        dialog.get_style_context().add_class("mintsec-dialog")
        dialog.set_default_size(420, -1)
        cancel_lbl = tr("common.cancel")
        ok_lbl = tr("common.continue")
        cancel_btn = dialog.add_button(cancel_lbl, Gtk.ResponseType.CANCEL)
        ok_btn = dialog.add_button(ok_lbl, Gtk.ResponseType.OK)
        ok_btn.get_style_context().add_class("suggested-action")
        set_accessible(cancel_btn, cancel_lbl, cancel_lbl)
        set_accessible(ok_btn, ok_lbl, ok_lbl)

        area = dialog.get_content_area()
        area.set_spacing(8)
        area.set_margin_top(14)
        area.set_margin_bottom(10)
        area.set_margin_start(16)
        area.set_margin_end(16)

        lbl = Gtk.Label(label=tr("rec.pw_label"), xalign=0.0)
        entry = Gtk.Entry()
        entry.set_visibility(False)
        entry.set_activates_default(True)
        relate_label(lbl, entry)
        set_accessible(entry, tr("rec.pw_a11y"), tr("rec.pw_desc"))
        area.pack_start(lbl, False, False, 0)
        area.pack_start(entry, False, False, 0)
        dialog.set_default_response(Gtk.ResponseType.OK)
        dialog.show_all()
        resp = dialog.run()
        pw = entry.get_text()
        dialog.destroy()
        return pw if resp == Gtk.ResponseType.OK and pw else None

    def _on_backup_now(self, *_args: object) -> None:
        pw = self._ask_repo_password(tr("rec.pw_backup_title"))
        if pw is None:
            return
        try:
            res = self.app_window.controller.recovery.backup_now(password=pw)
            self.app_window.controller.invalidate_cache("recovery")
            self.files_feedback.set_text(
                tr("rec.backup_done_msg", ts=format_local_datetime(res.get("completed_at")))
            )
            self.app_window.refresh_all(force=True)
        except Exception as exc:
            self.files_feedback.set_text(tr("rec.backup_fail_msg", err=exc))

    def _on_test_restore(self, *_args: object) -> None:
        pw = self._ask_repo_password(tr("rec.pw_test_title"))
        if pw is None:
            return
        try:
            res = self.app_window.controller.recovery.test_restore(password=pw)
            self.app_window.controller.invalidate_cache("recovery")
            self.files_feedback.set_text(
                tr("rec.test_done_msg", ts=format_local_datetime(res.get("tested_at")), res=res.get("result"))
            )
            self.app_window.refresh_all(force=True)
        except Exception as exc:
            self.files_feedback.set_text(tr("rec.test_fail_msg", err=exc))

    def _on_restore_other_folder(self, *_args: object) -> None:
        chooser = Gtk.FileChooserDialog(
            title=tr("rec.restore_choose_title"),
            transient_for=self.app_window,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        chooser.add_buttons(
            tr("common.cancel"),
            Gtk.ResponseType.CANCEL,
            tr("common.select"),
            Gtk.ResponseType.OK,
        )
        chosen: str | None = None
        if chooser.run() == Gtk.ResponseType.OK:
            chosen = chooser.get_filename()
        chooser.destroy()
        if not chosen:
            return

        pw = self._ask_repo_password(tr("rec.pw_restore_title"))
        if pw is None:
            self.files_feedback.set_text(tr("rec.restore_folder_selected_msg", path=chosen))
            return

        try:
            snaps = self.app_window.controller.recovery.list_snapshots(password=pw)
            if not snaps:
                self.files_feedback.set_text(tr("rec.restore_empty_msg"))
                return
            target_filter = self.restore_filter_entry.get_text().strip()
            target_paths = [target_filter] if target_filter else (snaps[-1].paths or ["/"])
            self.app_window.controller.recovery.restore_files(
                snapshot_id=snaps[-1].snapshot_id,
                paths=target_paths,
                destination_dir=Path(chosen),
                password=pw,
                overwrite_original=False,
            )
            self.files_feedback.set_text(tr("rec.restore_done_msg", path=chosen))
            self.app_window.refresh_all(force=False)
        except Exception as exc:
            self.files_feedback.set_text(tr("rec.restore_fail_msg", err=exc))
