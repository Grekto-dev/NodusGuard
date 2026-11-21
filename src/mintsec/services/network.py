"""Módulo 4: Rede Wi-Fi local (NetworkManager, vizinhança e auxiliar ARP/DHCP)."""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mintsec.contracts import (
    ModuleManifest,
    ModuleState,
    ModuleStatus,
    atomic_write_json,
    read_json_safe,
    xdg_dir,
)
from mintsec.formatting import now_iso
from mintsec.services.base import ModuleService

_IFACE_RE = re.compile(r"^[a-zA-Z0-9_.:@-]{1,32}$")
_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_MAX_OBSERVED_DEVICES = 512


@dataclass
class ObservedDevice:
    """Dispositivo observado na rede local via ip neigh ou auxiliar ARP/DHCP."""

    mac: str
    ip: str
    interface: str
    hostname: str = ""
    custom_name: str = ""
    recognized: bool = False
    first_seen_at: str = ""
    last_seen_at: str = ""
    source: str = "neigh"

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class NetworkService(ModuleService):
    """Identifica rede ativa, gerencia rede Casa, inventário e isolamento de clientes."""

    def __init__(
        self,
        *,
        manifest: ModuleManifest,
        config_store: Any,
        pending_store: Any,
        history_store: Any,
        package_inspector: Any = None,
        runner: Any = None,
        authorizer: Any = None,
        data_dir: Path | None = None,
    ) -> None:
        super().__init__(
            manifest=manifest,
            config_store=config_store,
            pending_store=pending_store,
            history_store=history_store,
            package_inspector=package_inspector,
            runner=runner,
            authorizer=authorizer,
        )
        self.data_dir = data_dir or xdg_dir("XDG_DATA_HOME", ".local/share")
        self.state_path = self.data_dir / "network_state.json"

    def resolve_netmon_binary(self) -> str | None:
        """Localiza o auxiliar isolado mintsec-netmon instalado ou no repositório."""
        installed = self.runner.which("mintsec-netmon")
        if installed:
            return installed
        local_bin = Path(__file__).resolve().parents[3] / "helpers/mintsec-netmon/mintsec-netmon"
        return str(local_bin) if local_bin.is_file() else None

    def _load_state(self) -> dict[str, Any]:
        return read_json_safe(
            self.state_path,
            default={
                "enabled": False,
                "home_networks": [],
                "known_devices": {},  # mac -> custom_name
                "observed_devices": {},  # mac -> ObservedDevice dict
                "client_isolation_networks": [],
                "last_confirmed_at": None,
            },
        )

    def _save_state(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.state_path, data, mode=0o600)

    def inspect_active_connection(self) -> dict[str, Any]:
        """Lê interface e conexão ativa no NetworkManager (somente leitura)."""
        nmcli = self.runner.which("nmcli")
        if not nmcli:
            return {"interface": "", "connection_name": "", "type": "unknown", "ssid": ""}

        res = self.runner.run(
            [nmcli, "-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "dev", "status"],
            timeout=5.0,
        )
        if res.returncode != 0:
            return {"interface": "", "connection_name": "", "type": "unknown", "ssid": ""}

        for line in res.stdout.splitlines():
            parts = line.split(":", 3)
            if len(parts) < 4:
                continue
            dev, dtype, dstate, conn = parts
            if dstate.startswith("connected") and dtype in ("wifi", "ethernet"):
                return {
                    "interface": dev,
                    "type": dtype,
                    "state": dstate,
                    "connection_name": conn,
                    "ssid": conn if dtype == "wifi" else "",
                }
        return {"interface": "", "connection_name": "", "type": "none", "ssid": ""}

    def read_neighbor_table(self, interface: str | None = None) -> list[dict[str, str]]:
        """Lê a tabela de vizinhança do kernel via ip -j neigh show."""
        ip_bin = self.runner.which("ip")
        if not ip_bin:
            return []
        argv = [ip_bin, "-j", "neigh", "show"]
        if interface:
            clean_iface = interface.strip()
            if clean_iface.startswith("-") or not _IFACE_RE.match(clean_iface):
                raise ValueError(f"Interface de rede inválida: {interface}")
            argv.extend(["dev", clean_iface])
        res = self.runner.run(argv, timeout=5.0)
        if res.returncode != 0 or not res.stdout.strip():
            return []
        try:
            entries = json.loads(res.stdout)
        except json.JSONDecodeError:
            return []

        devices: list[dict[str, str]] = []
        for row in entries:
            lladdr = str(row.get("lladdr", "")).lower()
            dst = str(row.get("dst", ""))
            dev = str(row.get("dev", ""))
            # Filtra link-local IPv6 quando apenas queremos inventário ou preserva ambos com MAC válido
            if not lladdr or ":" not in lladdr:
                continue
            devices.append({"mac": lladdr, "ip": dst, "interface": dev})
        return devices

    def ingest_observations(
        self,
        observations: list[dict[str, str]],
        *,
        network_id: str,
        alert_on_new: bool = True,
        client_isolation: bool | None = None,
    ) -> dict[str, Any]:
        """Processa observações de ARP/DHCP ou vizinhança e alerta sobre dispositivos novos."""
        state = self._load_state()
        known = dict(state.get("known_devices", {}))
        observed = dict(state.get("observed_devices", {}))
        old_iso_nets = list(state.get("client_isolation_networks", []))
        iso_nets = set(old_iso_nets)
        if client_isolation is True and network_id:
            iso_nets.add(network_id)
        elif client_isolation is False and network_id in iso_nets:
            iso_nets.discard(network_id)

        ts = now_iso()
        newly_observed: list[ObservedDevice] = []
        dirty = sorted(iso_nets) != sorted(old_iso_nets)

        for obs in observations:
            mac = str(obs.get("mac", "")).lower().strip()
            if not _MAC_RE.match(mac):
                continue
            ip = str(obs.get("ip", "")).strip()
            iface = str(obs.get("interface", obs.get("iface", ""))).strip()
            hostname = str(obs.get("hostname", "")).strip()
            source = str(obs.get("protocol", obs.get("source", "neigh"))).lower()
            is_new = mac not in observed and mac not in known
            prev = observed.get(mac, {})
            new_ip = ip or prev.get("ip", "")
            new_iface = iface or prev.get("interface", "")
            new_host = hostname or prev.get("hostname", "")
            new_custom = known.get(mac, prev.get("custom_name", ""))
            new_rec = mac in known
            if (
                not prev
                or prev.get("ip") != new_ip
                or prev.get("interface") != new_iface
                or prev.get("hostname") != new_host
                or prev.get("custom_name") != new_custom
                or prev.get("recognized") != new_rec
                or prev.get("source") != source
            ):
                dirty = True
            dev = ObservedDevice(
                mac=mac,
                ip=new_ip,
                interface=new_iface,
                hostname=new_host,
                custom_name=new_custom,
                recognized=new_rec,
                first_seen_at=prev.get("first_seen_at") or ts,
                last_seen_at=ts,
                source=source,
            )
            observed[mac] = dev.to_dict()
            if is_new:
                newly_observed.append(dev)
                if alert_on_new:
                    self.pending_store.create(
                        kind="new_network_device",
                        module_id="network",
                        app_name=mac,
                        title="Novo dispositivo observado",
                        summary=(
                            f"Dispositivo {mac} ({dev.ip or 'sem IP'}) observado na rede "
                            f"'{network_id or dev.interface}'."
                        ),
                        evidence=f"Fonte: {source.upper()} · Interface: {dev.interface}",
                        actions=["recognize_device"],
                        metadata={"mac": mac, "ip": dev.ip, "network_id": network_id},
                    )

        if len(observed) > _MAX_OBSERVED_DEVICES:
            dirty = True
            ordered_macs = sorted(
                observed.keys(),
                key=lambda m: (m in known, str(observed[m].get("last_seen_at", ""))),
            )
            for evict_mac in ordered_macs[: len(observed) - _MAX_OBSERVED_DEVICES]:
                observed.pop(evict_mac, None)

        if alert_on_new or dirty:
            state["observed_devices"] = observed
            state["client_isolation_networks"] = sorted(iso_nets)
            state["last_confirmed_at"] = ts
            self._save_state(state)
        return {
            "total_observed": len(observed),
            "newly_observed": [d.to_dict() for d in newly_observed],
            "client_isolation": network_id in iso_nets if network_id else False,
        }

    def recognize_device(self, mac: str, name: str) -> ModuleStatus:
        """Marca MAC como reconhecido pelo usuário ('Reconheço este dispositivo')."""
        clean_mac = mac.strip().lower()
        clean_name = name.strip() or clean_mac
        state = self._load_state()
        known = dict(state.get("known_devices", {}))
        known[clean_mac] = clean_name
        state["known_devices"] = known
        if clean_mac in state.get("observed_devices", {}):
            state["observed_devices"][clean_mac]["recognized"] = True
            state["observed_devices"][clean_mac]["custom_name"] = clean_name
        self._save_state(state)

        for pending in self.pending_store.list_open():
            if pending.kind == "new_network_device" and pending.app_name == clean_mac:
                self.pending_store.resolve(pending.pending_id, resolution="recognized")

        self.record_event(
            action="Dispositivo de rede reconhecido",
            reason=f"{clean_mac} nomeado como '{clean_name}'.",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
        )
        return self.query_status()

    def set_network_home(self, network_id: str, is_home: bool = True) -> ModuleStatus:
        """Marca ou desmarca uma rede como 'Casa'."""
        clean = network_id.strip()
        if not clean:
            raise ValueError("Identificador de rede vazio.")
        state = self._load_state()
        homes = set(state.get("home_networks", []))
        if is_home:
            homes.add(clean)
        else:
            homes.discard(clean)
        state["home_networks"] = sorted(homes)
        self._save_state(state)
        return self.query_status()

    def active_discover(self, network_id: str) -> list[dict[str, str]]:
        """Descoberta ativa permitida exclusivamente quando a rede estiver marcada como Casa."""
        state = self._load_state()
        if network_id not in state.get("home_networks", []):
            raise PermissionError(
                "A descoberta ativa ('Procurar dispositivos agora') exige que a rede esteja marcada como Casa."
            )
        conn = self.inspect_active_connection()
        neigh = self.read_neighbor_table(interface=conn.get("interface") or None)
        self.ingest_observations(neigh, network_id=network_id, alert_on_new=True)
        return neigh

    def query_status(self) -> ModuleStatus:
        installed, version, origin, _ = self.inspect_primary_packages()
        state = self._load_state()
        conn = self.inspect_active_connection()
        net_id = conn.get("connection_name") or conn.get("interface") or ""
        is_home = net_id in state.get("home_networks", [])
        iso_active = net_id in state.get("client_isolation_networks", [])

        if not installed:
            return self.build_status(
                state=ModuleState.AUSENTE,
                installed_version=None,
                package_origin="Não instalado",
                mode_summary="NetworkManager não encontrado",
                evidence="Pacote network-manager ausente.",
            )

        enabled = bool(state.get("enabled", False)) or self._module_enabled_flag(False)
        devices = list(state.get("observed_devices", {}).values())
        if not enabled:
            return self.build_status(
                state=ModuleState.DESATIVADO,
                installed_version=version,
                package_origin=origin,
                mode_summary="Inventário passivo desativado",
                evidence="Ative para observar dispositivos na rede local.",
                details={
                    "active_connection": conn,
                    "is_home": is_home,
                    "client_isolation": iso_active,
                    "devices": devices,
                    "home_networks": state.get("home_networks", []),
                },
            )

        # Quando ativo, complementa com vizinhança atual do kernel (somente leitura)
        if conn.get("interface"):
            live_neigh = self.read_neighbor_table(interface=conn["interface"])
            if live_neigh:
                self.ingest_observations(live_neigh, network_id=net_id, alert_on_new=False)
                state = self._load_state()
                devices = list(state.get("observed_devices", {}).values())

        isolation_note = (
            " Visibilidade limitada: rede com isolamento de clientes."
            if iso_active
            else ""
        )
        mode_summary = (
            f"Rede {'Casa' if is_home else 'Pública/Outra'}: {net_id or 'sem conexão'} · "
            f"{len(devices)} dispositivo(s)"
        )
        return self.build_status(
            state=ModuleState.ATIVO,
            installed_version=version,
            package_origin=origin,
            mode_summary=mode_summary,
            evidence=f"Observação passiva na interface {conn.get('interface') or 'local'}.{isolation_note}",
            last_confirmed_at=state.get("last_confirmed_at") or now_iso(),
            details={
                "active_connection": conn,
                "is_home": is_home,
                "client_isolation": iso_active,
                "isolation_explanation": (
                    "Redes com isolamento de clientes bloqueiam ARP/tráfego direto entre aparelhos; "
                    "apenas o roteador e anúncios recebidos ficam visíveis."
                    if iso_active
                    else ""
                ),
                "devices": devices,
                "home_networks": state.get("home_networks", []),
            },
        )

    def configure(self, **options: Any) -> ModuleStatus:
        if "network_id" in options and "is_home" in options:
            return self.set_network_home(str(options["network_id"]), bool(options["is_home"]))
        return self.query_status()

    def enable(self, **options: Any) -> ModuleStatus:
        state = self._load_state()
        state["enabled"] = True
        state["last_confirmed_at"] = now_iso()
        self._save_state(state)
        self._set_module_enabled_flag(True)
        self.record_event(
            action="Inventário de rede local ativado",
            reason="Observação passiva habilitada.",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
        )
        return self.query_status()

    def disable(self, *, revert_suite_changes: bool = False) -> ModuleStatus:
        state = self._load_state()
        state["enabled"] = False
        if revert_suite_changes:
            state["home_networks"] = []
        self._save_state(state)
        self._set_module_enabled_flag(False)
        self.record_event(
            action="Inventário de rede desativado",
            reason="Auxiliar ARP/DHCP interrompido.",
            confirmation_state="confirmed",
            actor="user",
        )
        return self.query_status()
