"""Aplicação GTK 3 principal da Suíte de Segurança para Linux Mint."""

from __future__ import annotations

import argparse
import sys

import gi

gi.require_version("Gio", "2.0")
gi.require_version("Gtk", "3.0")
from gi.repository import Gio, Gtk  # noqa: E402

from mintsec.services.catalog import SuiteController  # noqa: E402
from mintsec_ui.i18n import set_language, tr  # noqa: E402
from mintsec_ui.widgets import install_app_icon  # noqa: E402
from mintsec_ui.window import SuiteWindow  # noqa: E402


class SecuritySuiteApp(Gtk.Application):
    """Instância gráfica que encerra completamente ao fechar a janela."""

    def __init__(
        self,
        *,
        controller: SuiteController | None = None,
        initial_page: str = "home",
        initial_tab: str | None = None,
        initial_path: str | None = None,
        start_minimized: bool = False,
    ) -> None:
        super().__init__(
            application_id="org.mintsecurity.Suite",
            flags=Gio.ApplicationFlags.NON_UNIQUE,
        )
        self.controller = controller or SuiteController()
        set_language(self.controller.config_store.load().language)
        self.initial_page = initial_page
        self.initial_tab = initial_tab
        self.initial_path = initial_path
        self.start_minimized = start_minimized
        self.window: SuiteWindow | None = None

    def do_activate(self) -> None:
        install_app_icon()
        if self.window is None:
            self.window = SuiteWindow(self, controller=self.controller)
            if self.initial_page != "home" or self.initial_tab or self.initial_path:
                self.window.navigate_to(
                    self.initial_page,
                    tab=self.initial_tab,
                    path=self.initial_path,
                )
        if self.start_minimized and self.window.tray.has_active_backend:
            self.window.hide()
            self.window.home_page.set_animations_active(False)
            return
        self.window.present()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=tr("win.app_tagline"))
    parser.add_argument(
        "--page",
        choices=[
            "home",
            "scans",
            "quarantine",
            "protections",
            "recovery",
            "activity",
            "notifications",
            "settings",
        ],
        default="home",
        help=tr("win.cli_page_help"),
    )
    parser.add_argument("--tab", help=tr("win.cli_tab_help"))
    parser.add_argument("--path", help=tr("win.cli_path_help"))
    parser.add_argument("--minimized", action="store_true")
    args, remaining = parser.parse_known_args(argv)

    app = SecuritySuiteApp(
        initial_page=args.page,
        initial_tab=args.tab,
        initial_path=args.path,
        start_minimized=args.minimized,
    )
    return int(app.run([sys.argv[0], *remaining]))


if __name__ == "__main__":
    sys.exit(main())
