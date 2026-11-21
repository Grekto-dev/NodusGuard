# NodusGuard — Architecture Overview

## Overview

NodusGuard is a modular, open-source security suite targeting Linux Mint 22.x (Ubuntu 24.04 LTS base), structured across six decoupled layers:

1. **GTK 3 Desktop Panel (`src/mintsec_ui/`)**:
   - Server-side window decorations (SSD), flat-design adaptive palettes (soft lavender, neutral light, modern dark, graphite dark) driven by `theme_bg_color` luminance, complete omission of custom CSS in High Contrast mode, full ATK accessibility (keyboard navigation and Orca screen reader compatibility), live English (`en` default) and Brazilian Portuguese (`pt_BR`) localization (`i18n.py`), multi-size transparent PNG icons (`assets/`), and **zero idle repaints** when idle.
2. **Core, D-Bus & Module Services (`src/mintsec/`)**:
   - Versioned JSON contracts for all 7 modules (`manifests/*.json`), system D-Bus activation (`dbus_client.py`), real package/version/origin inspection (`dpkg-query` + `apt-cache policy`), `aptkit` installation integration, non-retentive Polkit authorization for destructive actions, optional WAL SQLite event history (`history.py`), exclusive `UDisks2` device opening (`OpenDevice` with `O_EXCL`), and out-of-`$HOME` incident preservation folders (`incident.py`).
3. **OpenSnitch Connector, Post-Update Trust & APT Hooks (`src/mintsec/opensnitch_grpc.py`, `src/mintsec/firewall_trust.py`, `apt/`, `bin/mint-security-apt-hook`)**:
   - Framed protobuf Unix-socket client with automatic reconnect, SHA-256 verification cache keyed by `(dev, ino, ctime_ns, size)` (`p95 < 5 ms`), root-owned path-chain validation up to `/`, and `DPkg::Pre-Install-Pkgs` / `DPkg::Post-Invoke` trust revalidation hooks.
4. **Hardened Native C11 Helpers (`helpers/`)**:
   - `mintsec-netmon`: local ARP/DHCP observer scoped with `CAP_NET_RAW`.
   - `mintsec-containment`: `FAN_OPEN_EXEC_PERM` loop (`FAN_CLOEXEC`, `200 ms` budget, `FAN_Q_OVERFLOW` awareness), `inotify` canary watcher, `cgroup v2` freezer controller (`frozen 1` / `populated 0`), and `sd_notify` watchdog heartbeat (`WatchdogSec=5s`).
5. **Offline Rescue & Isolated Session Launcher (`scripts/build_rescue_iso.py`, `bin/mint-security-bank-mode`)**:
   - Hybrid BIOS + UEFI rescue ISO builder via `grub-mkrescue` with read-only root mount and an experimental separate-session launcher for Bank Mode.
6. **Rust Session Agent (`agent/`)**:
   - `org.kde.StatusNotifierItem` tray integration, grouped D-Bus desktop notifications, and on-demand GTK confirmation dialogs (`mint-security-dialog`).

## Core Commands

```bash
# Build C helpers and Rust agent, then run self-tests, Rust tests, and Python unit tests
make test

# Run full homologation suite H1–H8 (includes QEMU/KVM 6.14 + BIOS/UEFI + Xephyr)
make homologate

# Build hybrid BIOS + UEFI offline rescue ISO
PYTHONPATH=src python3 scripts/build_rescue_iso.py --iso --out dist/mintsec-rescue-live.iso

# Build all 11 modular .deb packages into dist/
make deb
```

See detailed test evidence in [homologation-report.md](homologation-report.md) and [release-manifest.json](release-manifest.json).
