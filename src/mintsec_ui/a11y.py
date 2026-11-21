"""Utilitários de acessibilidade ATK para navegação por teclado e leitor de tela Orca."""

from __future__ import annotations

import gi

gi.require_version("Atk", "1.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Atk, Gtk  # noqa: E402


def set_accessible(
    widget: Gtk.Widget,
    name: str,
    description: str | None = None,
    role: Atk.Role | None = None,
) -> None:
    """Define nome, descrição e papel ATK para leitura fiel pelo Orca."""
    acc = widget.get_accessible()
    if acc is None:
        return
    if name:
        acc.set_name(name)
    if description:
        acc.set_description(description)
    if role is not None:
        acc.set_role(role)


def relate_label(label: Gtk.Label, target: Gtk.Widget) -> None:
    """Associa rótulo e controle via relação ATK_RELATION_LABELLED_BY."""
    label.set_mnemonic_widget(target)
    target_acc = target.get_accessible()
    label_acc = label.get_accessible()
    if target_acc is None or label_acc is None:
        return
    target_acc.add_relationship(Atk.RelationType.LABELLED_BY, label_acc)
    label_acc.add_relationship(Atk.RelationType.LABEL_FOR, target_acc)
