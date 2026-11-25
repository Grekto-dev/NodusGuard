"""Diálogo detalhado de erro com causa provável, solução sugerida e detalhes técnicos."""

from __future__ import annotations

from typing import Any, Callable

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.formatting import ErrorReport, build_error_report  # noqa: E402
from mintsec_ui.a11y import set_accessible  # noqa: E402
from mintsec_ui.i18n import get_language, tr  # noqa: E402


def build_error_dialog(
    parent: Gtk.Window | None,
    error: Exception | str,
    *,
    operation: str = "",
    source: str = "",
    title: str | None = None,
    open_logs_cb: Callable[[], Any] | None = None,
) -> tuple[Gtk.Dialog, ErrorReport]:
    """Constrói diálogo de erro detalhado e acessível sem bloquear o loop."""
    report = build_error_report(error, operation=operation, lang=get_language())
    dialog = Gtk.Dialog(
        title=title or tr("err.dialog_title"),
        transient_for=parent,
        modal=True,
    )
    dialog.get_style_context().add_class("mintsec-dialog")
    dialog.set_default_size(520, -1)
    dialog.set_resizable(True)

    logs_btn = None
    if open_logs_cb is not None:
        logs_btn = dialog.add_button(tr("err.open_logs_btn"), Gtk.ResponseType.HELP)
        set_accessible(logs_btn, tr("err.open_logs_btn"), tr("err.open_logs_desc"))

    close_btn = dialog.add_button(tr("common.close"), Gtk.ResponseType.CLOSE)
    close_btn.get_style_context().add_class("suggested-action")
    set_accessible(close_btn, tr("common.close"), tr("common.close_notice"))

    area = dialog.get_content_area()
    area.set_spacing(10)
    area.set_margin_top(16)
    area.set_margin_bottom(12)
    area.set_margin_start(18)
    area.set_margin_end(18)

    head = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=10)
    icon = Gtk.Image.new_from_icon_name("dialog-error-symbolic", Gtk.IconSize.DND)
    icon.set_pixel_size(28)
    icon.set_valign(Gtk.Align.START)
    head.pack_start(icon, False, False, 0)

    lbl_summary = Gtk.Label(label=report.summary, xalign=0.0)
    lbl_summary.set_line_wrap(True)
    lbl_summary.set_selectable(True)
    lbl_summary.get_style_context().add_class("mintsec-title")
    head.pack_start(lbl_summary, True, True, 0)
    area.pack_start(head, False, False, 0)

    card = Gtk.Box(orientation=Gtk.Orientation.VERTICAL, spacing=6)
    card.get_style_context().add_class("mintsec-card")

    lines = [
        tr("err.what_happened", cause=report.cause),
        tr("err.how_to_fix", suggestion=report.suggestion),
    ]
    if source or operation:
        origin_txt = f"{source} — {operation}".strip(" —") if (source and operation) else (source or operation)
        lines.append(tr("err.source_op", value=origin_txt))

    for text_line in lines:
        lbl = Gtk.Label(label=text_line, xalign=0.0)
        lbl.set_line_wrap(True)
        lbl.get_style_context().add_class("mintsec-muted")
        card.pack_start(lbl, False, False, 0)

    area.pack_start(card, False, False, 0)

    tech_exp = Gtk.Expander(label=tr("err.tech_expander"))
    tech_exp.get_style_context().add_class("mintsec-expander")
    set_accessible(tech_exp, tr("err.tech_expander"), tr("err.tech_desc"))

    scroller = Gtk.ScrolledWindow()
    scroller.set_policy(Gtk.PolicyType.AUTOMATIC, Gtk.PolicyType.AUTOMATIC)
    scroller.set_min_content_height(96)
    tv = Gtk.TextView()
    tv.set_editable(False)
    tv.set_cursor_visible(False)
    tv.set_wrap_mode(Gtk.WrapMode.WORD_CHAR)
    tv.get_style_context().add_class("mintsec-log-view")
    tv.get_buffer().set_text(report.technical_details)
    scroller.add(tv)
    tech_exp.add(scroller)
    area.pack_start(tech_exp, False, False, 0)

    dialog.show_all()
    close_btn.grab_focus()
    return dialog, report


def show_error_dialog(
    parent: Gtk.Window | None,
    error: Exception | str,
    *,
    operation: str = "",
    source: str = "",
    title: str | None = None,
    open_logs_cb: Callable[[], Any] | None = None,
) -> ErrorReport:
    """Exibe diálogo de erro detalhado e retorna o ErrorReport gerado."""
    dialog, report = build_error_dialog(
        parent,
        error,
        operation=operation,
        source=source,
        title=title,
        open_logs_cb=open_logs_cb,
    )
    resp = dialog.run()
    dialog.destroy()
    if resp == Gtk.ResponseType.HELP and open_logs_cb is not None:
        open_logs_cb()
    return report
