"""Gerenciamento de inicialização automática por sessão (XDG autostart)."""

from __future__ import annotations

import os
from pathlib import Path

from mintsec.contracts import atomic_write_text, ensure_private_dir


def get_autostart_file(config_home: Path | None = None) -> Path:
    """Retorna o caminho do arquivo .desktop de autostart em XDG_CONFIG_HOME."""
    base = config_home or Path(os.environ.get("XDG_CONFIG_HOME") or (Path.home() / ".config"))
    return base / "autostart" / "nodusguard.desktop"


def sync_autostart(enabled: bool, *, config_home: Path | None = None) -> Path:
    """Cria ou remove a entrada XDG de inicialização automática com o sistema."""
    target = get_autostart_file(config_home=config_home)
    if target.parent.is_symlink():
        raise PermissionError(f"Diretório de autostart não pode ser symlink: {target.parent}")
    if target.is_symlink():
        raise PermissionError(f"Arquivo de autostart não pode ser symlink: {target}")
    if not enabled:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass
        return target

    ensure_private_dir(target.parent, 0o755)
    desktop_entry = (
        "[Desktop Entry]\n"
        "Type=Application\n"
        "Name=NodusGuard\n"
        "GenericName=Computer Protection\n"
        "GenericName[pt_BR]=Proteção do computador\n"
        "Comment=Background tray monitor and scheduled security checks\n"
        "Comment[pt_BR]=Monitoramento na área de notificação e verificações agendadas\n"
        "Exec=mint-security-suite --minimized\n"
        "Icon=nodusguard\n"
        "Terminal=false\n"
        "X-GNOME-Autostart-enabled=true\n"
        "X-GNOME-Autostart-Delay=5\n"
        "Categories=System;Security;\n"
    )
    atomic_write_text(target, desktop_entry, mode=0o644)
    return target
