# Homologation Report H1–H8 (Linux Mint 22.3 Baseline)

- **Observed baseline host kernel**: `7.0.0-43-generic`
- **Locally verified components**: Core 7-module architecture + OpenSnitch contract & SHA-256 APT trust hooks + local DNS (`dnsmasq`) & LAN inventory + Isolated Browser (`bubblewrap`) + live H1 micro-VM KVM verification (`6.14.0-37-generic`) + hybrid BIOS/UEFI rescue ISO in QEMU/KVM + H8 GTK UI verification (`0` idle repaints).
- **Retained as experimental / hardware-matrix pending**: Bank Mode across legacy Intel/Nouveau/modesetting physical VTs, signed Secure Boot USB testing on bare metal, external `FAN_OPEN_EXEC_PERM` on kernels 6.8/7.0, 2/4 GiB physical HDD benchmark matrix, and bare-metal MATE/Xfce/LMDE sessions.

## Assay Summary

| Assay | Status | Key Recorded Evidence |
|---|---|---|
| **H1** | `PARTIAL_KVM_6_14_PASS` | `mintsec-containment --self-test` OK (`budget=200ms`, `FAN_CLOEXEC`, `cgroup.events`, `FAN_Q_OVERFLOW`); live KVM micro-VM (`6.14.0-37-generic`) passed `fork`, `vfork`, `posix_spawn`, and `SIGKILL` recovery. |
| **H2** | `PASS_CONTRACT_VERIFIED` | Waiter isolation, queue-full recovery, offline default-deny / monitor-allow semantics, and `allow_next_attempt` verified against framing client. |
| **H3** | `PASS` | `cold_first_hash_ms=0.092`, `hot_cache_p95_ms=0.588` (`target <= 5.0 ms`), symlink and dynamic library tampering rejected, APT trust abort/verify hooks passed. |
| **H4** | `PARTIAL_LOCAL_PASS` | `agent_pss_kib=724`, `agent_open_fds=9`, modular enable/disable and interrupted-scan handling verified; 2/4 GiB physical HDD benchmark pending hardware matrix. |
| **H5** | `PASS` | Local `dnsmasq` selected and verified with IPv4/IPv6 + split-VPN domain preservation; `mintsec-netmon --self-test` OK (`ARP + DHCP`); live Wi-Fi/LAN discovery gate enforced. |
| **H6** | `PASS` | Independent restore preserving incident folder, quarantine collision resolution, `FAN_Q_OVERFLOW` incomplete reconstruction notice, and low false-positive gate verified. |
| **H7** | `EXPERIMENTAL_PENDING_HARDWARE` | 9 host block nodes protected, LUKS/LVM/RAID refusal, swapped-media refusal, GPG signature + readback verification, QEMU BIOS & UEFI read-only boot, unprivileged `bwrap` smoke test, and nested `Xephyr` Bank Mode passed. |
| **H8** | `PASS_XEPHYR_CINNAMON_ENV` | 4/4 GTK/Xephyr tests passing: WCAG 2.2 light/dark contrast, High Contrast CSS omission, full keyboard/ATK accessibility, responsive 1366×768 and 1024×600 (`Sans 15`) layout, and **0 idle repaints**. |
