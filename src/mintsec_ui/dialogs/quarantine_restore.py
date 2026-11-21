"""Diálogos de confirmação de quarentena, destino de restauração e colisão."""

from __future__ import annotations

from pathlib import Path

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.services.antimalware import AntimalwareService, QuarantineItem, RestoreCollisionError  # noqa: E402
from mintsec_ui.a11y import relate_label, set_accessible  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.i18n import tr  # noqa: E402


def confirm_quarantine(
    parent: Gtk.Window | None,
    *,
    file_path: str,
    detection_name: str,
) -> bool:
    """Confirma mudança do item suspeito para a quarentena."""
    return ask_action_confirmation(
        parent,
        title=tr("quar.confirm_title"),
        summary=tr("quar.confirm_summary", name=Path(file_path).name),
        actor=tr("quar.confirm_actor"),
        evidence=tr("quar.confirm_evidence", det=detection_name, path=file_path),
        confirm_label=tr("quar.confirm_label"),
        confirm_effect=tr("quar.confirm_effect"),
        cancel_label=tr("quar.keep_label"),
        cancel_effect=tr("quar.keep_effect"),
    )


def restore_quarantine_interactive(
    parent: Gtk.Window | None,
    *,
    service: AntimalwareService,
    item: QuarantineItem,
    initial_destination: str | None = None,
) -> Path | None:
    """Permite escolher caminho de restauração via teclado e resolve colisões explicitamente."""
    dialog = Gtk.Dialog(
        title=tr("quar.restore_title"),
        transient_for=parent,
        modal=True,
    )
    dialog.get_style_context().add_class("mintsec-dialog")
    dialog.set_default_size(520, -1)
    cancel_lbl = tr("common.cancel")
    restore_lbl = tr("quar.restore_ok_btn")
    cancel_btn = dialog.add_button(cancel_lbl, Gtk.ResponseType.CANCEL)
    restore_btn = dialog.add_button(restore_lbl, Gtk.ResponseType.OK)
    restore_btn.get_style_context().add_class("suggested-action")
    set_accessible(cancel_btn, cancel_lbl, tr("quar.restore_keep_desc"))
    set_accessible(restore_btn, restore_lbl, tr("quar.restore_ok_desc"))

    area = dialog.get_content_area()
    area.set_spacing(10)
    area.set_margin_top(16)
    area.set_margin_bottom(12)
    area.set_margin_start(18)
    area.set_margin_end(18)

    meta_lbl = Gtk.Label(
        label=tr("quar.meta", path=item.original_path, det=item.detection_name, sha=item.sha256[:16]),
        xalign=0.0,
    )
    meta_lbl.set_line_wrap(True)
    meta_lbl.get_style_context().add_class("mintsec-muted")
    area.pack_start(meta_lbl, False, False, 0)

    dest_lbl = Gtk.Label(label=tr("quar.dest_label"), xalign=0.0, use_underline=True)
    area.pack_start(dest_lbl, False, False, 0)

    row = Gtk.Box(orientation=Gtk.Orientation.HORIZONTAL, spacing=8)
    dest_entry = Gtk.Entry()
    dest_entry.set_text(initial_destination or item.original_path)
    dest_entry.set_activates_default(True)
    relate_label(dest_lbl, dest_entry)
    set_accessible(dest_entry, tr("quar.dest_a11y"), tr("quar.dest_desc"))
    row.pack_start(dest_entry, True, True, 0)

    browse_btn = Gtk.Button(label=tr("quar.browse_btn"))
    set_accessible(browse_btn, tr("quar.browse_a11y"), tr("quar.browse_desc"))

    def _on_browse(_btn: Gtk.Button) -> None:
        chooser = Gtk.FileChooserDialog(
            title=tr("quar.browse_title"),
            transient_for=dialog,
            action=Gtk.FileChooserAction.SELECT_FOLDER,
        )
        chooser.add_buttons(
            tr("common.cancel"),
            Gtk.ResponseType.CANCEL,
            tr("common.select"),
            Gtk.ResponseType.OK,
        )
        if chooser.run() == Gtk.ResponseType.OK and chooser.get_filename():
            chosen_dir = Path(chooser.get_filename())
            dest_entry.set_text(str(chosen_dir / Path(item.original_path).name))
        chooser.destroy()

    browse_btn.connect("clicked", _on_browse)
    row.pack_start(browse_btn, False, False, 0)
    area.pack_start(row, False, False, 0)

    dialog.set_default_response(Gtk.ResponseType.OK)
    dialog.show_all()
    resp = dialog.run()
    chosen_text = dest_entry.get_text().strip()
    dialog.destroy()

    if resp != Gtk.ResponseType.OK or not chosen_text:
        return None

    try:
        return service.restore_quarantined(
            item.item_id,
            destination_path=chosen_text,
            collision_policy="ask",
        )
    except RestoreCollisionError as col:
        policy = _ask_collision_resolution(parent, col.destination_path)
        if policy is None:
            return None
        return service.restore_quarantined(
            item.item_id,
            destination_path=chosen_text,
            collision_policy=policy,
        )


def _ask_collision_resolution(parent: Gtk.Window | None, destination: Path) -> str | None:
    dialog = Gtk.Dialog(
        title=tr("quar.col_title"),
        transient_for=parent,
        modal=True,
    )
    dialog.get_style_context().add_class("mintsec-dialog")
    dialog.add_button(tr("common.cancel"), Gtk.ResponseType.CANCEL)
    dialog.add_button(tr("quar.col_rename"), 1)
    overwrite_btn = dialog.add_button(tr("quar.col_overwrite"), 2)
    overwrite_btn.get_style_context().add_class("destructive-action")

    area = dialog.get_content_area()
    area.set_margin_top(16)
    area.set_margin_bottom(12)
    area.set_margin_start(18)
    area.set_margin_end(18)
    lbl = Gtk.Label(label=tr("quar.col_msg", dest=destination), xalign=0.0)
    lbl.set_line_wrap(True)
    area.pack_start(lbl, False, False, 0)
    dialog.show_all()
    resp = dialog.run()
    dialog.destroy()
    if resp == 1:
        return "rename"
    if resp == 2:
        return "overwrite"
    return None
