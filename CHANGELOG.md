# Changelog

All notable changes to **NodusGuard** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-11-21

### Added
- **Unified GTK 3 Control Panel (`NodusGuard`)**:
  - Clean flat-design interface with server-side window decorations, light/dark/high-contrast theme adaptation, and zero idle repaints.
  - Interactive language switcher supporting **English** (default) and **Brazilian Portuguese (`pt_BR`)** live without restarting.
  - **Settings → About** page displaying version (`0.1.0`), official app icon, and open-source project credits.
  - Multi-size RGBA application icon (`48×48`, `64×64`, `128×128`, `256×256`) registered globally and packaged into `hicolor`.
  - Custom flat-design illustrations created with ComfyUI and Qwen Image 2.1.
- **Modular Protection Architecture (7 Modules)**:
  - **Antivirus**: unprivileged ClamAV on-demand & scheduled scans, FreshClam updates, and confirmed quarantine with collision handling.
  - **Network Shield (Firewall)**: UFW incoming firewall with essential rule preservation + OpenSnitch per-application outbound contract and APT SHA-256 post-update trust verification.
  - **File Backups & Recovery**: encrypted `restic` backups, Timeshift system snapshots, out-of-`$HOME` incident preservation folder, and Nemo/Caja/Thunar file-manager integrations.
  - **Wi-Fi Network**: NetworkManager device inventory with a `CAP_NET_RAW` ARP/DHCP helper (`mintsec-netmon`) and client-isolation safeguards.
  - **Safe Browsing**: local DNS filtering via `dnsmasq` with local exceptions, DoH conflict detection, and split-VPN domain preservation.
  - **Protected Browser & Isolation**: AppArmor status inspection, Bubblewrap isolated browser sessions, and experimental nested Bank Mode (`mint-security-bank-mode`).
  - **Emergency USB Rescue**: GPG-verified rescue ISO builder (BIOS + UEFI) and exclusive `UDisks2` block-device imaging with identity re-verification.
- **Native Rust Session Agent (`mint-security-agent`)**: `StatusNotifierItem` tray integration, grouped D-Bus notifications, and on-demand GTK confirmation dialogs.
- **Hardened C11 System Helpers**: `mintsec-netmon` and `mintsec-containment` (`FAN_OPEN_EXEC_PERM`, `inotify` canary monitor, `cgroup v2` freezer, `sd_notify` watchdog).
- **Modular Debian Packaging**: 11 `.deb` packages (`core`, 7 protection modules, and 3 file-manager integrations) plus automated GitHub CI & Release workflows.
