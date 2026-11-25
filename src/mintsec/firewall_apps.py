"""Catálogo curado de aplicativos de rede e detecção segura para o firewall NodusGuard."""

from __future__ import annotations

import ipaddress
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Any

_PROFILE_NAME_RE = re.compile(r"^[A-Za-z0-9 ._+-]{1,48}$")
_SS_PROC_RE = re.compile(r'"([^"]+)",pid=\d+')
_MAX_PROFILE_BYTES = 256 * 1024

DEFAULT_APP_DESKTOP_DIRS: tuple[Path, ...] = (
    Path("/usr/share/applications"),
    Path("/usr/local/share/applications"),
    Path("/var/lib/flatpak/exports/share/applications"),
)


@dataclass(frozen=True)
class FirewallAppPreset:
    """Modelo declarativo de portas e detecção para aplicativos comuns de rede."""

    preset_id: str
    name: str
    category: str
    summary_en: str
    summary_pt: str
    ports: tuple[tuple[str, str], ...]  # ((direction, target), ...)
    default_lan_only: bool
    detect_binaries: tuple[str, ...]
    detect_desktop_tokens: tuple[str, ...]
    detect_process_names: tuple[str, ...]
    auto_allow_on_enable: bool = False


FIREWALL_APP_PRESETS: tuple[FirewallAppPreset, ...] = (
    FirewallAppPreset(
        preset_id="kdeconnect",
        name="KDE Connect / GSConnect",
        category="phone_desktop",
        summary_en="Phone & PC clipboard, notifications, remote input, and file sharing",
        summary_pt="Conexão celular-PC: área de transferência, notificações, controle remoto e arquivos",
        ports=(("in", "1714:1764/tcp"), ("in", "1714:1764/udp")),
        default_lan_only=True,
        detect_binaries=("kdeconnectd", "kdeconnect-app", "kdeconnect-cli"),
        detect_desktop_tokens=("kdeconnect", "gsconnect"),
        detect_process_names=("kdeconnectd", "gsconnect", "gjs"),
        auto_allow_on_enable=True,
    ),
    FirewallAppPreset(
        preset_id="audiorelay",
        name="AudioRelay",
        category="audio_streaming",
        summary_en="Stream PC/Android audio and microphone over Wi-Fi or USB",
        summary_pt="Transmissão de áudio e microfone entre PC e celular pela rede local",
        ports=(("in", "59100/tcp"), ("in", "59200/udp")),
        default_lan_only=True,
        detect_binaries=("audiorelay",),
        detect_desktop_tokens=("audiorelay", "audio-relay"),
        detect_process_names=("audiorelay", "audio-relay"),
        auto_allow_on_enable=True,
    ),
    FirewallAppPreset(
        preset_id="warpinator",
        name="Warpinator",
        category="file_sharing",
        summary_en="Linux Mint local network file transfer between computers",
        summary_pt="Transferência local de arquivos do Linux Mint entre computadores",
        ports=(("in", "42000/tcp"), ("in", "42001/tcp")),
        default_lan_only=True,
        detect_binaries=("warpinator",),
        detect_desktop_tokens=("warpinator",),
        detect_process_names=("warpinator",),
        auto_allow_on_enable=True,
    ),
    FirewallAppPreset(
        preset_id="localsend",
        name="LocalSend",
        category="file_sharing",
        summary_en="Cross-platform LAN file and text sharing",
        summary_pt="Compartilhamento rápido de arquivos e textos na rede local",
        ports=(("in", "53317/tcp"), ("in", "53317/udp")),
        default_lan_only=True,
        detect_binaries=("localsend", "localsend_app"),
        detect_desktop_tokens=("localsend",),
        detect_process_names=("localsend", "localsend_app"),
        auto_allow_on_enable=True,
    ),
    FirewallAppPreset(
        preset_id="tailscale",
        name="Tailscale VPN",
        category="vpn",
        summary_en="Direct WireGuard mesh connections for Tailscale nodes",
        summary_pt="Conexões diretas WireGuard para nós na rede Tailscale",
        ports=(("in", "41641/udp"),),
        default_lan_only=False,
        detect_binaries=("tailscale", "tailscaled"),
        detect_desktop_tokens=("tailscale",),
        detect_process_names=("tailscaled",),
        auto_allow_on_enable=True,
    ),
    FirewallAppPreset(
        preset_id="syncthing",
        name="Syncthing",
        category="file_sharing",
        summary_en="Continuous peer-to-peer folder synchronization",
        summary_pt="Sincronização contínua de pastas ponto a ponto",
        ports=(("in", "22000/tcp"), ("in", "22000/udp"), ("in", "21027/udp")),
        default_lan_only=False,
        detect_binaries=("syncthing",),
        detect_desktop_tokens=("syncthing",),
        detect_process_names=("syncthing",),
    ),
    FirewallAppPreset(
        preset_id="steam_remote_play",
        name="Steam Remote Play",
        category="gaming",
        summary_en="Local game streaming and controller discovery for Steam",
        summary_pt="Transmissão local de jogos e descoberta de controles pelo Steam",
        ports=(("in", "27036/tcp"), ("in", "27031:27036/udp")),
        default_lan_only=True,
        detect_binaries=("steam",),
        detect_desktop_tokens=("steam",),
        detect_process_names=("steam",),
    ),
    FirewallAppPreset(
        preset_id="sunshine",
        name="Sunshine / Moonlight",
        category="gaming",
        summary_en="Low-latency desktop and game streaming host for Moonlight clients",
        summary_pt="Servidor de streaming de jogos e área de trabalho para clientes Moonlight",
        ports=(
            ("in", "47984/tcp"),
            ("in", "47989/tcp"),
            ("in", "48010/tcp"),
            ("in", "47998:48000/udp"),
        ),
        default_lan_only=True,
        detect_binaries=("sunshine",),
        detect_desktop_tokens=("sunshine",),
        detect_process_names=("sunshine",),
    ),
    FirewallAppPreset(
        preset_id="samba",
        name="Samba (LAN File Sharing)",
        category="file_sharing",
        summary_en="Windows/SMB shared folders on your local network",
        summary_pt="Compartilhamento de pastas Windows/SMB na rede local",
        ports=(("in", "137/udp"), ("in", "138/udp"), ("in", "139/tcp"), ("in", "445/tcp")),
        default_lan_only=True,
        detect_binaries=("smbd",),
        detect_desktop_tokens=("samba",),
        detect_process_names=("smbd", "nmbd"),
    ),
    FirewallAppPreset(
        preset_id="spotify_connect",
        name="Spotify Connect",
        category="audio_streaming",
        summary_en="Local speaker discovery and remote playback control",
        summary_pt="Descoberta de alto-falantes e controle de reprodução na rede local",
        ports=(("in", "57621/tcp"), ("in", "5353/udp")),
        default_lan_only=True,
        detect_binaries=("spotify",),
        detect_desktop_tokens=("spotify",),
        detect_process_names=("spotify",),
    ),
    FirewallAppPreset(
        preset_id="ssh",
        name="SSH (Remote Access)",
        category="remote_access",
        summary_en="Encrypted terminal and SFTP access from local network devices",
        summary_pt="Acesso seguro de terminal e transferência SFTP na rede local",
        ports=(("in", "22/tcp"),),
        default_lan_only=True,
        detect_binaries=("sshd",),
        detect_desktop_tokens=("openssh",),
        detect_process_names=("sshd",),
    ),
    FirewallAppPreset(
        preset_id="cups",
        name="Network Printing (CUPS)",
        category="printing",
        summary_en="Shared printers and IPP discovery across your home network",
        summary_pt="Impressoras compartilhadas e descoberta IPP na rede local",
        ports=(("in", "631/tcp"), ("in", "631/udp")),
        default_lan_only=True,
        detect_binaries=("cupsd",),
        detect_desktop_tokens=("cups",),
        detect_process_names=("cupsd",),
    ),
)

PRESETS_BY_ID: dict[str, FirewallAppPreset] = {p.preset_id: p for p in FIREWALL_APP_PRESETS}

_PROCESS_TO_PRESET: dict[str, str] = {}
for _preset in FIREWALL_APP_PRESETS:
    for _proc in _preset.detect_process_names:
        if _proc not in _PROCESS_TO_PRESET:
            _PROCESS_TO_PRESET[_proc.lower()] = _preset.preset_id


def detect_local_lan_cidr(runner: Any) -> str:
    """Detecta faixa privada RFC1918 local (ex.: 192.168.0.0/16) somente para escopo LAN."""
    ip_bin = runner.which("ip") if runner is not None else None
    if not ip_bin:
        return "192.168.0.0/16"
    try:
        res = runner.run([ip_bin, "-4", "-o", "addr", "show", "scope", "global"], timeout=2.0)
    except Exception:  # noqa: BLE001
        return "192.168.0.0/16"
    if res.returncode != 0:
        return "192.168.0.0/16"

    for line in res.stdout.splitlines():
        for token in line.split():
            if "/" not in token:
                continue
            try:
                iface_ip = ipaddress.ip_interface(token).ip
            except ValueError:
                continue
            if not isinstance(iface_ip, ipaddress.IPv4Address):
                continue
            octets = iface_ip.packed
            if octets[0] == 192 and octets[1] == 168:
                return "192.168.0.0/16"
            if octets[0] == 10:
                return "10.0.0.0/8"
            if octets[0] == 172 and 16 <= octets[1] <= 31:
                return "172.16.0.0/12"
    return "192.168.0.0/16"


def detect_listening_apps(runner: Any) -> list[dict[str, Any]]:
    """Lista processos ouvindo fora de loopback via ss -tulnpH (somente leitura)."""
    ss_bin = runner.which("ss") if runner is not None else None
    if not ss_bin:
        return []
    try:
        res = runner.run([ss_bin, "-tulnpH"], timeout=3.0)
    except Exception:  # noqa: BLE001
        return []
    if res.returncode != 0 or not res.stdout.strip():
        return []

    by_proc: dict[str, dict[str, Any]] = {}
    for line in res.stdout.splitlines():
        parts = line.split()
        if len(parts) < 5:
            continue
        netid = parts[0].strip().lower()
        if netid not in {"tcp", "udp"}:
            continue
        local_addr = parts[4].strip()
        if (
            local_addr.startswith("127.")
            or local_addr.startswith("[::1]")
            or local_addr.startswith("::1:")
            or "%lo:" in local_addr
        ):
            continue
        if ":" not in local_addr:
            continue
        port_str = local_addr.rsplit(":", 1)[-1].strip()
        if not port_str.isdigit():
            continue
        port_num = int(port_str)
        if not (1 <= port_num <= 65535):
            continue

        proc_names = _SS_PROC_RE.findall(line)
        if not proc_names:
            continue
        proc = proc_names[0].strip()
        if not proc:
            continue
        port_target = f"{port_num}/{netid}"
        entry = by_proc.setdefault(
            proc,
            {
                "process": proc,
                "ports": [],
                "preset_id": _PROCESS_TO_PRESET.get(proc.lower(), ""),
            },
        )
        if port_target not in entry["ports"]:
            entry["ports"].append(port_target)

    out = list(by_proc.values())
    for item in out:
        item["ports"].sort()
    out.sort(key=lambda it: it["process"].lower())
    return out


def list_ufw_app_profiles(
    profiles_dir: Path = Path("/etc/ufw/applications.d"),
) -> list[dict[str, Any]]:
    """Lê perfis UFW em /etc/ufw/applications.d rejeitando symlinks e payloads excessivos."""
    try:
        dir_st = os.lstat(profiles_dir)
    except OSError:
        return []
    if stat.S_ISLNK(dir_st.st_mode) or not stat.S_ISDIR(dir_st.st_mode):
        return []

    profiles: list[dict[str, Any]] = []
    for fpath in sorted(profiles_dir.iterdir()):
        try:
            st = os.lstat(fpath)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode) or not stat.S_ISREG(st.st_mode):
            continue
        if st.st_size > _MAX_PROFILE_BYTES:
            continue
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        cur_name: str | None = None
        cur_data: dict[str, str] = {}

        def _flush() -> None:
            if not cur_name:
                return
            if cur_name.startswith("-") or not _PROFILE_NAME_RE.match(cur_name):
                return
            ports_val = cur_data.get("ports", "").strip()
            if not ports_val:
                return
            profiles.append(
                {
                    "name": cur_name,
                    "title": cur_data.get("title", cur_name).strip() or cur_name,
                    "description": cur_data.get("description", "").strip(),
                    "ports": ports_val,
                }
            )

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            if line.startswith("[") and line.endswith("]"):
                _flush()
                cur_name = line[1:-1].strip()
                cur_data = {}
            elif cur_name and "=" in line:
                k, v = line.split("=", 1)
                cur_data[k.strip().lower()] = v.strip()
        _flush()

    profiles.sort(key=lambda p: p["name"].lower())
    return profiles


def _scan_desktop_filenames(dirs: tuple[Path, ...]) -> set[str]:
    names: set[str] = set()
    for d in dirs:
        try:
            if d.is_dir():
                for entry in d.iterdir():
                    n = entry.name.lower()
                    if n.endswith(".desktop"):
                        names.add(n)
        except OSError:
            continue
    return names


def detect_app_presets(
    runner: Any,
    *,
    extra_app_dirs: tuple[Path, ...] | list[Path] | None = None,
    listening_apps: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    """Retorna os presets curados ordenados por apps em execução e instalados."""
    user_apps = Path.home() / ".local/share/applications"
    dirs = (*DEFAULT_APP_DESKTOP_DIRS, user_apps, *(extra_app_dirs or ()))
    desktop_names = _scan_desktop_filenames(dirs)
    running_rows = listening_apps if listening_apps is not None else detect_listening_apps(runner)
    running_procs = {str(r.get("process", "")).lower() for r in running_rows}

    results: list[dict[str, Any]] = []
    for preset in FIREWALL_APP_PRESETS:
        has_bin = any(runner.which(b) is not None for b in preset.detect_binaries) if runner is not None else False
        has_desktop = any(
            tok in fname
            for fname in desktop_names
            for tok in preset.detect_desktop_tokens
        )
        is_running = any(p.lower() in running_procs for p in preset.detect_process_names)
        installed = bool(has_bin or has_desktop or is_running)
        results.append(
            {
                "preset_id": preset.preset_id,
                "name": preset.name,
                "category": preset.category,
                "summary_en": preset.summary_en,
                "summary_pt": preset.summary_pt,
                "ports": [f"{tgt}" for _d, tgt in preset.ports],
                "default_lan_only": preset.default_lan_only,
                "auto_allow_on_enable": preset.auto_allow_on_enable,
                "installed": installed,
                "running": is_running,
                "detected": installed or is_running,
            }
        )

    results.sort(key=lambda it: (not it["running"], not it["installed"], it["name"].lower()))
    return results
