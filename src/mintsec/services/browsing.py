"""Módulo 5: Navegação (Filtro DNS local com preservação de VPN e exceções)."""

from __future__ import annotations

import ipaddress
import json
import os
import re
from pathlib import Path
from typing import Any

from mintsec.contracts import (
    ModuleManifest,
    ModuleState,
    ModuleStatus,
    atomic_write_json,
    atomic_write_text,
    read_json_safe,
    xdg_dir,
)
from mintsec.formatting import now_iso
from mintsec.services.base import ModuleService

_DOMAIN_RE = re.compile(
    r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$"
)


def _validate_domain(domain: str) -> str:
    raw = str(domain)
    if "\r" in raw or "\n" in raw or "\0" in raw or "/" in raw or "#" in raw:
        raise ValueError(f"Domínio inválido: {domain}")
    clean = raw.strip().lower().rstrip(".")
    if not clean or len(clean) > 253 or not _DOMAIN_RE.match(clean):
        raise ValueError(f"Domínio inválido: {domain}")
    return clean


def _validate_resolver_ip(addr: str) -> str:
    raw = str(addr)
    if "\r" in raw or "\n" in raw or "\0" in raw or "/" in raw:
        raise ValueError(f"Endereço de resolvedor inválido: {addr}")
    clean = raw.strip()
    if not clean:
        raise ValueError("Endereço de resolvedor vazio.")
    ip_part, sep, port_part = clean.partition("#")
    ipaddress.ip_address(ip_part)
    if sep:
        if not port_part.isdigit() or not (1 <= int(port_part) <= 65535):
            raise ValueError(f"Porta de resolvedor inválida: {addr}")
    return clean

DEFAULT_BLOCKLIST: dict[str, str] = {
    "phishing-demo.invalid": "phishing",
    "malware-dropper.invalid": "malware",
    "cryptominer-pool.invalid": "mineracao",
}

BLOCK_CATEGORY_LABELS = {
    "phishing": "Lista local: phishing",
    "malware": "Lista local: malware",
    "mineracao": "Lista local: mineração indesejada",
}


class BrowsingService(ModuleService):
    """Gerencia filtro DNS local, exceções, resolvedor por domínio e detecção de DoH."""

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
        nm_conf_dropin: Path | None = None,
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
        self.state_path = self.data_dir / "browsing_state.json"
        self.runtime_dir = self.data_dir / "browsing"
        self._doh_cache: tuple[str, tuple[tuple[str, int, int], ...], list[dict[str, str]]] | None = None
        if nm_conf_dropin is not None:
            self.nm_conf_dropin = nm_conf_dropin
        elif os.geteuid() == 0:
            self.nm_conf_dropin = Path("/etc/NetworkManager/conf.d/99-mintsec-dns.conf")
        else:
            self.nm_conf_dropin = self.runtime_dir / "99-mintsec-dns.conf"

    def _load_state(self) -> dict[str, Any]:
        return read_json_safe(
            self.state_path,
            default={
                "enabled": False,
                "engine": "dnsmasq",  # selecionado pelos critérios H5 (ou dnscrypt-proxy)
                "upstream_resolvers": ["1.1.1.1", "9.9.9.9"],
                "blocklist": dict(DEFAULT_BLOCKLIST),
                "local_exceptions": [],
                "domain_resolvers": {},  # domain -> resolver_ip autorizado
                "vpn_private_domains": [],
                "external_blocks": {},  # domain -> reason/upstream
                "last_confirmed_at": None,
            },
        )

    def _save_state(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.state_path, data, mode=0o600)

    def detect_vpn_private_domains(self) -> list[str]:
        """Consulta domínios privados de VPN ativos via resolvectl (somente leitura)."""
        resolvectl = self.runner.which("resolvectl")
        if not resolvectl:
            return []
        res = self.runner.run([resolvectl, "domain"], timeout=3.0)
        if res.returncode != 0:
            return []
        domains: list[str] = []
        for line in res.stdout.splitlines():
            if not any(tok in line for tok in ("tun", "wg", "tailscale", "vpn")):
                continue
            for part in line.split(":", 1)[-1].split():
                clean = part.lstrip("~")
                if "." in clean and clean not in domains:
                    domains.append(clean)
        return domains

    def detect_browser_doh(self, home_dir: Path | None = None) -> list[dict[str, str]]:
        """Inspeciona (somente leitura) se Firefox/Chromium usam DoH próprio fora do filtro."""
        base = home_dir or Path.home()
        candidate_files: list[Path] = []
        ff_root = base / ".mozilla/firefox"
        if ff_root.is_dir():
            candidate_files.extend(sorted(ff_root.glob("*/prefs.js")))
        for _, rel in (
            ("Chromium", ".config/chromium/Default/Preferences"),
            ("Google Chrome", ".config/google-chrome/Default/Preferences"),
        ):
            pref_file = base / rel
            if pref_file.is_file():
                candidate_files.append(pref_file)

        sig_list: list[tuple[str, int, int]] = []
        for fpath in candidate_files:
            try:
                st = fpath.stat()
                sig_list.append((str(fpath), int(st.st_mtime_ns), int(st.st_size)))
            except OSError:
                continue
        sig = tuple(sig_list)
        if self._doh_cache is not None and self._doh_cache[0] == str(base) and self._doh_cache[1] == sig:
            return [dict(item) for item in self._doh_cache[2]]

        warnings: list[dict[str, str]] = []
        if ff_root.is_dir():
            for prefs in ff_root.glob("*/prefs.js"):
                try:
                    txt = prefs.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    continue
                if "network.trr.mode" not in txt:
                    continue
                match = re.search(r'user_pref\("network\.trr\.mode",\s*(\d+)\)', txt)
                if match and int(match.group(1)) in (2, 3):
                    warnings.append(
                        {
                            "browser": "Firefox",
                            "profile": prefs.parent.name,
                            "detail": "DNS sobre HTTPS (DoH) próprio ativado; consultas do navegador ficam fora da cobertura local.",
                        }
                    )

        for br_name, rel in (
            ("Chromium", ".config/chromium/Default/Preferences"),
            ("Google Chrome", ".config/google-chrome/Default/Preferences"),
        ):
            pref_file = base / rel
            if pref_file.is_file():
                try:
                    raw_txt = pref_file.read_text(encoding="utf-8", errors="replace")
                    if "dns_over_https" not in raw_txt:
                        continue
                    data = json.loads(raw_txt)
                    doh_mode = data.get("dns_over_https", {}).get("mode", "")
                    if doh_mode in ("automatic", "secure"):
                        warnings.append(
                            {
                                "browser": br_name,
                                "profile": "Default",
                                "detail": f"DoH próprio ({doh_mode}) ativo no navegador fora da cobertura do filtro local.",
                            }
                        )
                except Exception:
                    pass
        self._doh_cache = (str(base), sig, [dict(item) for item in warnings])
        return warnings

    def lookup_block_origin(self, domain: str) -> dict[str, Any]:
        """Informa a origem comprovada do bloqueio ou registra como desconhecida."""
        clean = domain.strip().lower().rstrip(".")
        state = self._load_state()
        exceptions = {d.lower() for d in state.get("local_exceptions", [])}
        if clean in exceptions:
            return {
                "domain": clean,
                "blocked": False,
                "origin": "Exceção local ativa",
                "known": True,
            }

        cat = state.get("blocklist", {}).get(clean)
        if cat:
            return {
                "domain": clean,
                "blocked": True,
                "origin": BLOCK_CATEGORY_LABELS.get(cat, f"Lista local: {cat}"),
                "source": "local",
                "known": True,
            }

        ext = state.get("external_blocks", {}).get(clean)
        if ext:
            return {
                "domain": clean,
                "blocked": True,
                "origin": f"Resolvedor externo ({ext})",
                "source": "external_resolver",
                "known": True,
            }

        return {
            "domain": clean,
            "blocked": False,
            "origin": "Origem desconhecida",
            "source": "unknown",
            "known": False,
        }

    def add_local_exception(self, domain: str) -> ModuleStatus:
        """Revoga a regra local para o domínio especificado."""
        clean = _validate_domain(domain)
        state = self._load_state()
        exc = list(state.get("local_exceptions", []))
        if clean not in exc:
            exc.append(clean)
        state["local_exceptions"] = exc
        state["last_confirmed_at"] = now_iso()
        self._save_state(state)
        self.write_runtime_configs()
        self.record_event(
            action="Exceção DNS local adicionada",
            reason=f"Regra local revogada para {clean}.",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
            revert_action=f"remove_dns_exception:{clean}",
        )
        return self.query_status()

    def remove_local_exception(self, domain: str) -> ModuleStatus:
        clean = _validate_domain(domain)
        state = self._load_state()
        state["local_exceptions"] = [d for d in state.get("local_exceptions", []) if d != clean]
        self._save_state(state)
        self.write_runtime_configs()
        return self.query_status()

    def authorize_external_resolver(
        self,
        domain: str,
        resolver_ip: str,
        *,
        vpn_domains: list[str] | None = None,
    ) -> dict[str, Any]:
        """Autoriza outro resolvedor somente para o domínio indicado, preservando VPN."""
        clean = _validate_domain(domain)
        clean_ip = _validate_resolver_ip(resolver_ip)

        state = self._load_state()
        detected_vpn = vpn_domains if vpn_domains is not None else (
            state.get("vpn_private_domains") or self.detect_vpn_private_domains()
        )
        # Nunca sobrescrever domínios privados da VPN
        for vpn_dom in detected_vpn:
            vd = vpn_dom.lower().lstrip(".")
            if clean == vd or clean.endswith(f".{vd}"):
                raise PermissionError(
                    f"O domínio '{clean}' pertence ao domínio privado da VPN '{vd}' e não pode ser redirecionado."
                )

        domain_resolvers = dict(state.get("domain_resolvers", {}))
        domain_resolvers[clean] = clean_ip
        state["domain_resolvers"] = domain_resolvers
        state["vpn_private_domains"] = list(detected_vpn)
        state["last_confirmed_at"] = now_iso()
        self._save_state(state)
        self.write_runtime_configs()
        self.record_event(
            action="Resolvedor autorizado por domínio",
            reason=f"Domínio {clean} direcionado para {clean_ip} preservando VPN.",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
        )
        return {
            "domain": clean,
            "resolver_ip": clean_ip,
            "preserved_vpn_domains": list(detected_vpn),
        }

    def generate_dnsmasq_config(
        self,
        *,
        listen_addr: str = "127.0.0.1",
        port: int = 53,
        upstream_servers: list[str] | None = None,
        vpn_resolvers: dict[str, str] | None = None,
    ) -> str:
        """Gera configuração dnsmasq com bloqueio local (IPv4+IPv6), exceções e VPN intacta."""
        ipaddress.ip_address(listen_addr)
        if not (1 <= int(port) <= 65535):
            raise ValueError(f"Porta DNS inválida: {port}")
        state = self._load_state()
        exceptions = {_validate_domain(d) for d in state.get("local_exceptions", [])}
        upstreams = upstream_servers if upstream_servers is not None else state.get("upstream_resolvers", ["1.1.1.1"])
        lines = [
            f"listen-address={listen_addr}",
            f"port={int(port)}",
            "bind-interfaces",
            "no-resolv",
            "no-hosts",
            "domain-needed",
            "bogus-priv",
        ]
        for up in upstreams:
            lines.append(f"server={_validate_resolver_ip(up)}")

        # Preservação explícita de domínios privados de VPN
        for vpn_dom, vpn_srv in (vpn_resolvers or {}).items():
            lines.append(f"server=/{_validate_domain(vpn_dom)}/{_validate_resolver_ip(vpn_srv)}")

        # Resolvedores autorizados por domínio após bloqueio externo
        for dom, res_ip in sorted(state.get("domain_resolvers", {}).items()):
            lines.append(f"server=/{_validate_domain(dom)}/{_validate_resolver_ip(res_ip)}")

        # Bloqueio local IPv4 e IPv6 (NXDOMAIN / endereço nulo) exceto domínios com exceção
        for dom in sorted(state.get("blocklist", {}).keys()):
            clean_dom = _validate_domain(dom)
            if clean_dom in exceptions:
                continue
            lines.append(f"address=/{clean_dom}/0.0.0.0")
            lines.append(f"address=/{clean_dom}/::")

        return "\n".join(lines) + "\n"

    def write_runtime_configs(self) -> Path:
        conf_path = self.runtime_dir / "dnsmasq.conf"
        atomic_write_text(conf_path, self.generate_dnsmasq_config(), mode=0o600)
        return conf_path

    def query_status(self) -> ModuleStatus:
        dnscrypt_info = self.package_inspector.inspect_package("dnscrypt-proxy", binaries=["dnscrypt-proxy"])
        dnsmasq_info = self.package_inspector.inspect_package("dnsmasq", binaries=["dnsmasq"])
        dnsmasq_base = self.package_inspector.inspect_package("dnsmasq-base", binaries=["dnsmasq"])
        state = self._load_state()
        vpn_domains = state.get("vpn_private_domains") or self.detect_vpn_private_domains()
        doh_warnings = self.detect_browser_doh()

        installed = dnscrypt_info.installed or dnsmasq_info.installed or dnsmasq_base.installed
        chosen_info = dnsmasq_info if dnsmasq_info.installed else (
            dnscrypt_info if dnscrypt_info.installed else dnsmasq_base
        )

        if not installed:
            return self.build_status(
                state=ModuleState.AUSENTE,
                installed_version=None,
                package_origin="Não instalado",
                mode_summary="Filtro DNS local não instalado",
                evidence="Nenhum motor DNS local instalado.",
                details={
                    "engine": state.get("engine", "dnsmasq"),
                    "blocklist": state.get("blocklist", {}),
                    "local_exceptions": state.get("local_exceptions", []),
                    "domain_resolvers": state.get("domain_resolvers", {}),
                    "vpn_private_domains": vpn_domains,
                    "doh_warnings": doh_warnings,
                },
            )

        enabled = bool(state.get("enabled", False)) or self._module_enabled_flag(False)
        mod_state = ModuleState.ATIVO if enabled else ModuleState.DESATIVADO
        engine_label = state.get("engine", "dnsmasq")
        mode_summary = (
            f"Filtro DNS local ({engine_label}) ativo · {len(state.get('blocklist', {}))} regra(s)"
            if enabled
            else f"Motor {engine_label} disponível (desativado)"
        )
        evidence = (
            "Filtro local aplicado preservando domínios privados de VPN."
            if enabled
            else "Ative para filtrar domínios de phishing, malware e mineração."
        )

        return self.build_status(
            state=mod_state,
            installed_version=chosen_info.version,
            package_origin=chosen_info.origin,
            mode_summary=mode_summary,
            evidence=evidence,
            last_confirmed_at=state.get("last_confirmed_at"),
            details={
                "engine": engine_label,
                "blocklist": state.get("blocklist", {}),
                "local_exceptions": state.get("local_exceptions", []),
                "domain_resolvers": state.get("domain_resolvers", {}),
                "vpn_private_domains": vpn_domains,
                "doh_warnings": doh_warnings,
            },
        )

    def configure(self, **options: Any) -> ModuleStatus:
        state = self._load_state()
        if "engine" in options and options["engine"] in {"dnsmasq", "dnscrypt-proxy"}:
            state["engine"] = options["engine"]
        if "upstream_resolvers" in options:
            state["upstream_resolvers"] = [_validate_resolver_ip(r) for r in options["upstream_resolvers"]]
        if "vpn_private_domains" in options:
            state["vpn_private_domains"] = [_validate_domain(d) for d in options["vpn_private_domains"]]
        self._save_state(state)
        self.write_runtime_configs()
        return self.query_status()

    def enable(self, **options: Any) -> ModuleStatus:
        if options:
            self.configure(**options)
        state = self._load_state()
        state["enabled"] = True
        state["last_confirmed_at"] = now_iso()
        self._save_state(state)
        self.write_runtime_configs()
        nm_mode = 0o644 if self.nm_conf_dropin.parent == Path("/etc/NetworkManager/conf.d") else 0o600
        atomic_write_text(self.nm_conf_dropin, "[main]\ndns=dnsmasq\n", mode=nm_mode)
        self._set_module_enabled_flag(True)
        self.record_event(
            action="Filtro DNS local ativado",
            reason=f"Motor {state.get('engine')} ativo com reversão configurada.",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
        )
        return self.query_status()

    def disable(self, *, revert_suite_changes: bool = False) -> ModuleStatus:
        state = self._load_state()
        state["enabled"] = False
        if revert_suite_changes:
            state["local_exceptions"] = []
            state["domain_resolvers"] = {}
            self.nm_conf_dropin.unlink(missing_ok=True)
            (self.runtime_dir / "dnsmasq.conf").unlink(missing_ok=True)
        self._save_state(state)
        self._set_module_enabled_flag(False)
        self.record_event(
            action="Filtro DNS local desativado",
            reason="Configuração DNS anterior restaurada." if revert_suite_changes else "Filtro pausado.",
            confirmation_state="confirmed",
            actor="user",
        )
        return self.query_status()
