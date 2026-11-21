"""Diálogo de aplicativo pausado e recuperação do incidente (Seção 5.4)."""

from __future__ import annotations

from typing import Callable

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.contracts import PendingDecision  # noqa: E402
from mintsec.services.catalog import SuiteController  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402


class PausedAppDialog(Gtk.Dialog):
    """Apresenta decisões reversíveis para aplicativo pausado mantendo foco inicial em Manter pausado."""

    def __init__(
        self,
        parent: Gtk.Window | None,
        *,
        controller: SuiteController,
        decision: PendingDecision,
        on_open_recovery: Callable[[PendingDecision, bool], None] | None = None,
        on_state_changed: Callable[[], None] | None = None,
    ) -> None:
        super().__init__(
            title=tr("paused.title", app=decision.app_name or tr("paused.proc_fallback")),
            transient_for=parent,
            modal=True,
        )
        self.get_style_context().add_class("mintsec-dialog")
        self.controller = controller
        self.decision = decision
        self.on_open_recovery = on_open_recovery
        self.on_state_changed = on_state_changed
        self.last_outcome: str = "kept_paused"

        self.set_default_size(540, -1)
        self.set_resizable(True)

        content = self.get_content_area()
        content.set_spacing(12)
        content.set_margin_top(16)
        content.set_margin_bottom(14)
        content.set_margin_start(18)
        content.set_margin_end(18)

        app_display = decision.app_name or tr("paused.app_fallback")
        title_lbl = Gtk.Label(
            label=tr("paused.headline", app=app_display),
            xalign=0.0,
        )
        title_lbl.set_line_wrap(True)
        title_lbl.get_style_context().add_class("mintsec-title")
        content.pack_start(title_lbl, False, False, 0)

        info_lbl = Gtk.Label(
            label=tr("paused.info", summary=decision.summary, evidence=decision.evidence),
            xalign=0.0,
        )
        info_lbl.set_line_wrap(True)
        info_lbl.get_style_context().add_class("mintsec-muted")
        content.pack_start(info_lbl, False, False, 0)

        if decision.fan_q_overflow:
            overflow_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
            overflow_box.get_style_context().add_class("mintsec-card")
            overflow_lbl = Gtk.Label(label=tr("paused.overflow_warn"), xalign=0.0)
            overflow_lbl.set_line_wrap(True)
            overflow_lbl.get_style_context().add_class("mintsec-pill-warn")
            overflow_box.pack_start(overflow_lbl, False, False, 0)

            open_full_lbl = tr("paused.open_full_btn")
            self.open_full_backup_btn = Gtk.Button(label=open_full_lbl)
            set_accessible(
                self.open_full_backup_btn,
                open_full_lbl,
                tr("paused.open_full_desc"),
            )
            self.open_full_backup_btn.connect("clicked", self._on_open_full_backup)
            overflow_box.pack_start(self.open_full_backup_btn, False, False, 0)
            content.pack_start(overflow_box, False, False, 0)
        else:
            self.open_full_backup_btn = None

        if decision.affected_paths:
            paths_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
            paths_box.get_style_context().add_class("mintsec-card")
            hdr = Gtk.Label(label=tr("paused.observed_hdr"), xalign=0.0)
            hdr.get_style_context().add_class("mintsec-title")
            paths_box.pack_start(hdr, False, False, 0)
            for p in decision.affected_paths[:8]:
                pl = Gtk.Label(label=f"• {p}", xalign=0.0)
                pl.set_line_wrap(True)
                paths_box.pack_start(pl, False, False, 0)
            content.pack_start(paths_box, False, False, 0)

        self.status_banner = Gtk.Label(label="", xalign=0.0)
        self.status_banner.set_line_wrap(True)
        self.status_banner.set_no_show_all(True)
        content.pack_start(self.status_banner, False, False, 0)

        # Botões com efeitos explicados e acessibilidade ATK
        btn_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=8)
        content.pack_start(btn_box, False, False, 0)

        keep_lbl = tr("paused.keep_btn")
        self.keep_btn = Gtk.Button(label=keep_lbl)
        set_accessible(self.keep_btn, keep_lbl, tr("paused.keep_desc"))
        self.keep_btn.connect("clicked", self._on_keep_paused)
        btn_box.pack_start(self.keep_btn, False, False, 0)

        restore_label = (
            tr("paused.restore_detected_btn")
            if decision.fan_q_overflow
            else tr("paused.restore_btn")
        )
        self.restore_btn = Gtk.Button(label=restore_label)
        set_accessible(self.restore_btn, restore_label, tr("paused.restore_desc"))
        self.restore_btn.connect("clicked", self._on_restore)
        btn_box.pack_start(self.restore_btn, False, False, 0)

        resume_lbl = tr("paused.resume_btn")
        self.resume_btn = Gtk.Button(label=resume_lbl)
        set_accessible(self.resume_btn, resume_lbl, tr("paused.resume_desc"))
        self.resume_btn.connect("clicked", self._on_resume)
        btn_box.pack_start(self.resume_btn, False, False, 0)

        term_label = tr("paused.term_btn", app=app_display)
        self.terminate_btn = Gtk.Button(label=term_label)
        self.terminate_btn.get_style_context().add_class("destructive-action")
        set_accessible(self.terminate_btn, term_label, tr("paused.term_desc"))
        self.terminate_btn.connect("clicked", self._on_terminate)
        btn_box.pack_start(self.terminate_btn, False, False, 0)

        self.connect("map-event", self._on_map_focus)
        self.connect("delete-event", self._on_close_keep_paused)
        self.show_all()
        self.keep_btn.grab_focus()

    def _on_map_focus(self, *_args: object) -> bool:
        self.keep_btn.grab_focus()
        return False

    def _on_close_keep_paused(self, *_args: object) -> bool:
        self.last_outcome = "kept_paused"
        return False

    def _on_keep_paused(self, *_args: object) -> None:
        self.controller.apply_paused_app_decision(self.decision.pending_id, "keep_paused")
        self.last_outcome = "kept_paused"
        self.response(Gtk.ResponseType.CLOSE)

    def _on_resume(self, *_args: object) -> None:
        ok = ask_action_confirmation(
            self,
            title=tr("paused.resume_confirm_title"),
            summary=tr("paused.resume_confirm_summary", app=self.decision.app_name or tr("paused.app_obj_fallback")),
            actor=tr("paused.confirm_actor"),
            evidence=self.decision.evidence,
            confirm_label=tr("paused.resume_btn"),
            confirm_effect=tr("paused.resume_confirm_effect"),
            cancel_label=tr("paused.keep_btn"),
            cancel_effect=tr("paused.keep_cancel_effect"),
        )
        if not ok:
            return
        self.controller.apply_paused_app_decision(
            self.decision.pending_id,
            "resume",
            service_confirmed=True,
        )
        self.last_outcome = "resumed"
        self.status_banner.set_text(tr("paused.resumed_banner"))
        self.status_banner.show()
        if self.on_state_changed:
            self.on_state_changed()
        self.response(Gtk.ResponseType.OK)

    def _on_terminate(self, *_args: object) -> None:
        app_display = self.decision.app_name or tr("paused.app_obj_fallback")
        ok = ask_action_confirmation(
            self,
            title=tr("paused.term_confirm_title", app=app_display),
            summary=tr("paused.term_confirm_summary", app=app_display),
            actor=tr("paused.confirm_actor"),
            evidence=self.decision.evidence,
            confirm_label=tr("paused.term_confirm_label", app=app_display),
            confirm_effect=tr("paused.term_confirm_effect"),
            cancel_label=tr("paused.keep_btn"),
            cancel_effect=tr("paused.keep_paused_effect"),
            destructive=True,
        )
        if not ok:
            return
        self.controller.apply_paused_app_decision(
            self.decision.pending_id,
            "terminate",
            service_confirmed=True,
        )
        self.last_outcome = "terminated"
        self.status_banner.set_text(tr("paused.terminated_banner"))
        self.status_banner.show()
        if self.on_state_changed:
            self.on_state_changed()
        self.response(Gtk.ResponseType.OK)

    def _on_restore(self, *_args: object) -> None:
        self.last_outcome = "restore_detected"
        if self.on_open_recovery:
            self.on_open_recovery(self.decision, False)
        self.response(Gtk.ResponseType.APPLY)

    def _on_open_full_backup(self, *_args: object) -> None:
        self.last_outcome = "open_full_backup"
        if self.on_open_recovery:
            self.on_open_recovery(self.decision, True)
        self.response(Gtk.ResponseType.APPLY)
