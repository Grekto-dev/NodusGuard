"""Entrada sob demanda para diálogos disparados pelo agente de sessão Rust."""

from __future__ import annotations

import argparse
import sys

import gi

gi.require_version("Gtk", "3.0")
from gi.repository import Gtk  # noqa: E402

from mintsec.services.catalog import SuiteController  # noqa: E402
from mintsec_ui.dialogs.confirm import ask_action_confirmation  # noqa: E402
from mintsec_ui.dialogs.paused_app import PausedAppDialog  # noqa: E402
from mintsec_ui.i18n import set_language, tr  # noqa: E402
from mintsec_ui.theme import ThemeManager  # noqa: E402
from mintsec_ui.widgets import install_app_icon  # noqa: E402


def main(argv: list[str] | None = None) -> int:
    controller = SuiteController()
    cfg = controller.config_store.load()
    set_language(cfg.language)
    install_app_icon()

    parser = argparse.ArgumentParser(description=tr("runner.cli_desc"))
    parser.add_argument("--pending-id", required=True, help=tr("runner.cli_help"))
    args = parser.parse_args(argv)

    ThemeManager().apply(theme_mode=cfg.theme_mode, theme_preset=cfg.theme_preset)

    decision = controller.pending_store.get(args.pending_id)
    if decision is None:
        ask_action_confirmation(
            None,
            title=tr("runner.missing_title"),
            summary=tr("runner.missing_summary"),
            actor=tr("runner.missing_actor"),
            evidence=args.pending_id,
            confirm_label=tr("common.close"),
            confirm_effect=tr("common.close_notice"),
        )
        return 0

    if decision.kind == "paused_app":
        dlg = PausedAppDialog(None, controller=controller, decision=decision)
        dlg.run()
        dlg.destroy()
        return 0

    approved = ask_action_confirmation(
        None,
        title=decision.title,
        summary=decision.summary,
        actor=decision.module_id,
        evidence=decision.evidence,
        confirm_label=tr("runner.review_confirm"),
        confirm_effect=tr("runner.review_effect"),
        cancel_label=tr("runner.keep_label"),
        cancel_effect=tr("runner.keep_effect"),
    )
    if approved:
        controller.pending_store.resolve(decision.pending_id, resolution="reviewed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
