# Contributing to NodusGuard

Thank you for your interest in contributing to **NodusGuard**!

## Development Philosophy

- **Clear by default**: Keep the primary interface approachable for everyday desktop users. Detailed options belong inside per-module views or collapsible expanders rather than cluttered top-level dashboards.
- **No silent destructive actions**: Sensitive or irreversible actions must prompt explicitly, preserve user-created rules/files on deactivation, and avoid Polkit credential caching for destructive operations.
- **Zero idle background overhead**: GTK widgets must never trigger idle repaint loops (`idle_repaints == 0`), and host status inspection must remain non-blocking.
- **Language parity**: Every user-facing string in `src/mintsec_ui/` must go through `mintsec_ui.i18n.tr()` and keep strict key parity between `en` and `pt_BR`.

## Local Setup (Linux Mint 22.x / Ubuntu 24.04)

```bash
sudo apt update
sudo apt install -y \
  build-essential gcc make dpkg-dev pkg-config \
  python3 python3-gi python3-gi-cairo python3-pil python3-dbus \
  gir1.2-gtk-3.0 gir1.2-atk-1.0 gir1.2-gdkpixbuf-2.0 \
  xserver-xephyr xvfb dbus-x11 at-spi2-core adwaita-icon-theme gnome-themes-extra \
  ufw bubblewrap

# Install Rust toolchain (if not already installed)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

## Running Checks Before Opening a Pull Request

```bash
# 1. Build and self-test the C11 helpers
make helpers
./helpers/mintsec-netmon/mintsec-netmon --self-test
./helpers/mintsec-containment/mintsec-containment --self-test

# 2. Run Rust unit tests & Clippy lints
cargo test --locked --manifest-path agent/Cargo.toml
cargo clippy --locked --manifest-path agent/Cargo.toml --all-targets -- -D warnings

# 3. Run the full Python + GTK/Xephyr test suite
PYTHONWARNINGS=default PYTHONPATH=src python3 -m unittest discover -s tests -p "test_*.py" -v

# 4. Verify UI contrast, ATK accessibility, viewports, and zero idle repaints
PYTHONPATH=src python3 scripts/verify_h8.py

# 5. Build all 11 Debian packages locally
python3 scripts/build_debs.py
```

## UI & Accessibility Rules

1. Every visible interactive widget (`Gtk.Button`, `Gtk.Entry`, `Gtk.ComboBox`, `Gtk.Expander`, `Gtk.Switch`, `Gtk.CheckButton`) must call `set_accessible(...)`.
2. GTK tests added outside `tests/test_h8_ui.py` must run inside an isolated subprocess with its own `Xephyr` display so `unittest discover` never shares or invalidates another test's X display connection.
3. Verify `set(TRANSLATIONS["en"]) == set(TRANSLATIONS["pt_BR"])` before committing translation changes.
