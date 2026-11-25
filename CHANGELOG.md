# Changelog

All notable changes to **NodusGuard** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.5] - 2026-11-25

### Fixed
- **Full Bilingual Language Consistency (`en` / `pt_BR`)**:
  - Made date/time and binary size formatters (`format_local_datetime`, `format_confirmed_at`, `format_bytes`) language-aware and wired UI helpers (`format_ui_datetime`, `format_ui_bytes`) across Home, Scans, Quarantine, Recovery, Activity, Notifications, and Module Detail pages.
  - Added localized descriptions and engine names (`manifest.<id>.desc`, `manifest.<id>.engine`) plus bidirectional text/log translation (`localize_text`, `localize_log_entry`) covering package origins, backend evidence/mode strings, essential firewall rule previews, OpenSnitch choice labels, X11/Bank Mode notices, history actions/reasons, and Settings → Logs entries.
  - Added automated Xephyr zero-leak regression tests (`tests/test_language_isolation.py`) ensuring zero Portuguese text leaks when running in English and clean live switching.

## [0.2.4] - 2026-11-25

### Added
- **Non-Intrusive Global Progress & Activity Indicator**:
  - Added a subtle collapsible progress bar (`activity_bar`) in the main window that shows live background operations and deterministic progress percentages (`Checking protections…`, module switches, database updates, package installs, firewall edits, batch recommendation apply) and hides completely with zero idle timers once finished.
  - Added static loading progress indicators in Protections and Module Detail placeholders.
- **Application Logs Tab (`Settings → Logs`)**:
  - Added persistent symlink-safe operational logging (`AppLogStore` under `XDG_STATE_HOME/app.log.jsonl`) recording checks, scans, protection changes, and error diagnostics, with level filtering (`Info`, `Warnings`, `Errors`), keyword search, refresh, and confirmation-guarded **Clear logs…** action.
- **Detailed & Actionable Error Diagnostics**:
  - Added structured error classification (`build_error_report` + `show_error_dialog`) explaining probable causes, recommended fixes, expandable technical details, and a direct **Open Logs** shortcut for Polkit denials, root/daemon issues, D-Bus errors, timeouts, FreshClam lock/DNS failures, missing binaries, and firewall rule rejections.

## [0.2.3] - 2026-11-25

### Added
- **Configurable System Title Bar (`use_system_titlebar`)**:
  - Added a **Use system title bar** checkbox in **Settings → General**, defaulting to `true` (native system SSD window frame).
  - Unchecking switches live between native window borders (SSD) and NodusGuard's flat integrated `Gtk.HeaderBar` (CSD) while preserving window visibility, size, position, maximize state, and dark/light/high-contrast theme consistency.

## [0.2.2] - 2026-11-25

### Added
- **Firewall App Exceptions (`Allow apps` tab)**:
  - Added curated presets for popular companion and LAN tools — including **KDE Connect** (`1714:1764` TCP/UDP) and **AudioRelay** (`59100/tcp`, `59200/udp`), plus Warpinator, LocalSend, Tailscale, Syncthing, Steam Remote Play, Sunshine/Moonlight, Samba, Spotify Connect, SSH, and CUPS — with local-subnet LAN scoping (`192.168.0.0/16`, `10.0.0.0/8`, etc.).
  - Added live non-loopback network listener discovery (`ss`), safe `/etc/ufw/applications.d` UFW profile listing & allow controls, custom app/port/protocol/direction form, automatic LAN app allowance on firewall activation, and Polkit-guarded D-Bus methods (`AllowAppPreset`, `RevokeAppPreset`, `AllowCustomPorts`, `AllowUfwProfile`).
- **One-Click Automatic Protection Recommendations**:
  - Upgraded **Home** recommendations with **Apply all automatically** (`apply_recommendation` / `apply_all_recommendations`) to enable protections, update signatures, schedule automatic quick scans, and allow detected LAN companion apps in one click.

## [0.2.1] - 2026-11-22

### Added
- **Pause & Resume Security Scans**:
  - Added a **Pause scan / Resume scan** control during active ClamAV scans, using process-group `SIGSTOP`/`SIGCONT` signaling and excluding paused intervals from ETA calculations.
- **Immediate & Default Post-Scan Power Action**:
  - Added a **When scan finishes** selector (`Do nothing`, `Suspend PC`, `Shut down PC`) on the Scans page that applies immediately even to scans already in progress, with a cancellable countdown via `org.freedesktop.login1` (and `systemctl` fallback).
  - Added **Default action after scan** (`default_scan_post_action`, defaulting to `none`) in **Settings → Alerts & Protection**.

### Fixed
- **Polkit & Root Elevation Routing**:
  - Routed privileged Firewall (`enable`, `disable`, `revoke_rule`), Safe Browsing (`enable`, `disable`), and ClamAV (`FreshClam` database updates) mutations through the root D-Bus services (`mint-security-daemon`) instead of invoking root-only binaries from the unprivileged UI process.
  - Isolated root daemon persistence under `STATE_DIRECTORY` (`/var/lib/mint-security-suite`), mapped `AuthorizationError` cleanly to `org.freedesktop.DBus.Error.AccessDenied`, and granted required systemd capabilities (`CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_DAC_OVERRIDE`, `CAP_SETUID`, `CAP_SETGID`) without relaxing `ProtectSystem=strict` or Polkit boundaries.
  - Stopped active on-demand `mintsec-*.service` units during core `.deb` upgrades so updated daemon code and systemd units take effect immediately.

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
