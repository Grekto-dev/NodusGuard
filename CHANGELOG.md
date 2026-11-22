# Changelog

All notable changes to **NodusGuard** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-22

### Added
- **Home Protection Hero Animation & Recommendations**:
  - Added an ultra-light vector Cairo hero animation (`ProtectionStatusCanvas`) switching smoothly between emerald green (healthy) and alert red (issues/paused), with cached radial glow surfaces and automatic pause when off-page, minimized, hidden, or in high contrast.
  - Added Last Scan & Virus Database status chips, quick **Update DB** button, and actionable protection recommendations with **Ignore** and **Restore ignored** controls.
- **System Tray Icon & Pause Protection Popup**:
  - Added status-reactive tray icons (`ok`, `alert`, `paused`) via `XApp.StatusIcon` (with `AyatanaAppIndicator3` fallback), where left-clicking always opens the **Home** page and right-clicking opens the full tray menu (`NodusGuard`, `Pause Protection…`, conditional `Resume Protection`, `Settings`, `Enable Do Not Disturb`, `Game Mode`, `About`, `Quit`).
  - Added `PauseProtectionDialog` offering timed pauses (`1 minute`, `3 minutes`, `5 minutes`, `15 minutes`, `30 minutes`, `1 hour`, `3 hours`, `5 hours`), **Pause until application restart**, and **Pause**.
- **Full System Scan, Live % & ETA Progress, Quarantine & Notifications**:
  - Added **Full system scan** (`scope="system"`, excluding virtual mounts) alongside live scan progress bars, `%` counters, and smoothed ETA across all scans.
  - Added dedicated **Quarantine** and **Notifications** pages, moving the notification bell counter to the left of **Settings** at the bottom of the sidebar.
- **Autostart & Periodic Automation Defaults**:
  - Enabled autostart (`--minimized` via XDG `.desktop`) and daily automatic quick scans + DB updates by default, configurable in **Settings**.

### Security & Performance
- Hardened JSON state/config readers against symlinks (including broken symlinks), oversized payloads, and corrupted files.
- Enforced thread-safe locking (`RLock`), config field sanitization, symlink rejection in XDG autostart management, capped error lists on system scans, companion `.service` units honoring pause/Game Mode schedules, and notification popup suppression in Rust session agent during DND/Game Mode/Pause (while keeping critical `paused_app` alerts active).
- Added granular sub-signatures on Home, lazy hidden-page rendering, pixbuf cache trimming + GC on minimize-to-tray, non-allocating `PendingStore.count_open()`, and mtime/WAL-aware caching in `HistoryStore`.

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
