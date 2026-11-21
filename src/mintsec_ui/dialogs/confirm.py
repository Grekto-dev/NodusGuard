"""Diálogo padronizado de confirmação exibindo quem agiu, evidência e efeito dos botões."""

from __future__ import annotations

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402


def ask_action_confirmation(
    parent: Gtk.Window | None,
    *,
    title: str,
    summary: str,
    actor: str,
    evidence: str,
    confirm_label: str,
    confirm_effect: str,
    cancel_label: str | None = None,
    cancel_effect: str | None = None,
    destructive: bool = False,
) -> bool:
    """Exibe diálogo acessível com evidência e efeito explícito de cada botão."""
    resolved_cancel_label = cancel_label if cancel_label is not None else tr("common.cancel")
    resolved_cancel_effect = cancel_effect if cancel_effect is not None else tr("confirm.default_cancel_effect")

    dialog = Gtk.Dialog(
        title=title,
        transient_for=parent,
        modal=True,
    )
    dialog.get_style_context().add_class("mintsec-dialog")
    dialog.set_default_size(480, -1)
    dialog.set_resizable(True)

    cancel_btn = dialog.add_button(resolved_cancel_label, Gtk.ResponseType.CANCEL)
    confirm_btn = dialog.add_button(confirm_label, Gtk.ResponseType.OK)
    if destructive:
        confirm_btn.get_style_context().add_class("destructive-action")
    else:
        confirm_btn.get_style_context().add_class("suggested-action")

    set_accessible(cancel_btn, resolved_cancel_label, resolved_cancel_effect)
    set_accessible(confirm_btn, confirm_label, confirm_effect)

    area = dialog.get_content_area()
    area.set_spacing(10)
    area.set_margin_top(16)
    area.set_margin_bottom(12)
    area.set_margin_start(18)
    area.set_margin_end(18)

    lbl_summary = Gtk.Label(label=summary, xalign=0.0)
    lbl_summary.set_line_wrap(True)
    lbl_summary.get_style_context().add_class("mintsec-title")
    area.pack_start(lbl_summary, False, False, 0)

    details_box = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=4)
    details_box.get_style_context().add_class("mintsec-card")

    for caption in (
        tr("confirm.source_line", actor=actor),
        tr("confirm.evidence_line", evidence=evidence),
        tr("confirm.on_confirm_line", label=confirm_label, effect=confirm_effect),
        tr("confirm.on_cancel_line", label=resolved_cancel_label, effect=resolved_cancel_effect),
    ):
        lbl = Gtk.Label(label=caption, xalign=0.0)
        lbl.set_line_wrap(True)
        lbl.get_style_context().add_class("mintsec-muted")
        details_box.pack_start(lbl, False, False, 0)

    area.pack_start(details_box, False, False, 0)
    dialog.show_all()
    cancel_btn.grab_focus()
    resp = dialog.run()
    dialog.destroy()
    return resp == Gtk.ResponseType.OK
