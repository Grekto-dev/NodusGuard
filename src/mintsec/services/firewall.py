"""Módulo 2: Firewall (UFW para entrada e contrato OpenSnitch para saída)."""

from __future__ import annotations

import ipaddress
import os
import re
import uuid
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
from mintsec.firewall_apps import PRESETS_BY_ID, detect_local_lan_cidr, list_ufw_app_profiles
from mintsec.formatting import now_iso
from mintsec.firewall_trust import AptTrustHookProcessor, OpenSnitchBridge, TrustStore
from mintsec.opensnitch_grpc import OpenSnitchGrpcClient
from mintsec.runner import SubprocessRunner
from mintsec.services.base import ModuleService

_FW_TARGET_RE = re.compile(
    r"^(\d{1,5}(?::\d{1,5})?(?:/(?:tcp|udp))?|[a-zA-Z][a-zA-Z0-9._-]{0,31})$"
)
_UFW_PROFILE_RE = re.compile(r"^[A-Za-z0-9 ._+-]{1,48}$")


def _validate_rule_inputs(direction: str, target: str, action: str) -> tuple[str, str, str]:
    clean_dir = str(direction).strip().lower()
    if clean_dir not in {"in", "out"}:
        raise ValueError(f"Direção de regra inválida: {direction}")
    clean_action = str(action).strip().upper()
    if clean_action not in {"ALLOW", "DENY", "REJECT"}:
        raise ValueError(f"Ação de regra inválida: {action}")
    clean_target = str(target).strip()
    if not clean_target or clean_target.startswith("-") or not _FW_TARGET_RE.match(clean_target):
        raise ValueError(f"Alvo de regra de firewall inválido: {target}")
    port_spec, sep, _proto = clean_target.partition("/")
    if port_spec[0].isdigit():
        if ":" in port_spec:
            if not sep:
                raise ValueError(f"Faixa de portas requer /tcp ou /udp: {target}")
            start_s, end_s = port_spec.split(":", 1)
            start_p, end_p = int(start_s), int(end_s)
            if not (1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p):
                raise ValueError(f"Faixa de portas fora do intervalo (1-65535): {target}")
        else:
            port_n = int(port_spec)
            if not (1 <= port_n <= 65535):
                raise ValueError(f"Porta fora do intervalo (1-65535): {target}")
    return clean_dir, clean_target, clean_action


def _validate_source_cidr(source_cidr: str | None) -> str:
    if source_cidr is None:
        return ""
    raw = str(source_cidr).strip()
    if not raw:
        return ""
    if raw.startswith("-") or "\r" in raw or "\n" in raw or "\0" in raw or any(ch.isspace() for ch in raw):
        raise ValueError(f"Faixa de rede inválida: {source_cidr}")
    return str(ipaddress.ip_network(raw, strict=False))


def _validate_app_label(name: str) -> str:
    clean = str(name or "").strip()
    if not clean or "\r" in clean or "\n" in clean or "\0" in clean or len(clean) > 64:
        raise ValueError(f"Nome de aplicativo inválido: {name}")
    return clean


def _build_ufw_rule_argv(
    ufw_bin: str,
    *,
    delete: bool,
    direction: str,
    target: str,
    action: str,
    source_cidr: str = "",
    is_profile: bool = False,
) -> list[str]:
    """Constrói comando ufw seguro preservando formato simples para regras globais."""
    verb = action.lower()
    if is_profile:
        return [ufw_bin, "delete", verb, target] if delete else [ufw_bin, verb, target]
    if not source_cidr:
        argv = [ufw_bin]
        if delete:
            argv.append("delete")
        argv.append(verb)
        if direction == "out":
            argv.append("out")
        argv.append(target)
        return argv

    port_part, _sep, proto_part = target.partition("/")
    argv = [ufw_bin]
    if delete:
        argv.append("delete")
    argv.append(verb)
    if direction == "out":
        argv.extend(["out", "to", source_cidr, "port", port_part])
    else:
        argv.extend(["in", "from", source_cidr, "to", "any", "port", port_part])
    if proto_part:
        argv.extend(["proto", proto_part])
    return argv


@dataclass
class FirewallRule:
    """Regra de firewall com rastreio de origem (suíte vs externa) e reversibilidade."""

    rule_id: str
    direction: str  # 'in' | 'out'
    target: str
    action: str  # 'ALLOW' | 'DENY' | 'REJECT'
    scope: str
    app_name: str = ""
    destination: str = "Qualquer"
    validity: str = "Permanente"
    managed_by_suite: bool = False
    raw_spec: str = ""
    source_cidr: str = ""
    preset_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _rule_from_dict(raw: dict[str, Any]) -> FirewallRule:
    return FirewallRule(
        rule_id=str(raw.get("rule_id", "")),
        direction=str(raw.get("direction", "in")),
        target=str(raw.get("target", "")),
        action=str(raw.get("action", "ALLOW")),
        scope=str(raw.get("scope", "")),
        app_name=str(raw.get("app_name", "")),
        destination=str(raw.get("destination", "Qualquer")),
        validity=str(raw.get("validity", "Permanente")),
        managed_by_suite=bool(raw.get("managed_by_suite", False)),
        raw_spec=str(raw.get("raw_spec", "")),
        source_cidr=str(raw.get("source_cidr", "")),
        preset_id=str(raw.get("preset_id", "")),
    )


ESSENTIAL_RULES_PREVIEW = [
    {
        "id": "essential-dns",
        "title": "Resolução de nomes (DNS)",
        "direction": "out",
        "port_proto": "53/udp, 53/tcp",
        "reason": "Permite consultar endereços na internet e na rede local.",
    },
    {
        "id": "essential-dhcp",
        "title": "Configuração automática de rede (DHCP)",
        "direction": "in/out",
        "port_proto": "67,68/udp",
        "reason": "Mantém o recebimento de endereço IP pelo roteador.",
    },
    {
        "id": "essential-vpn",
        "title": "Túneis VPN (WireGuard / OpenVPN)",
        "direction": "out",
        "port_proto": "51820/udp, 1194/udp",
        "reason": "Evita bloqueio de conexões VPN configuradas pelo usuário.",
    },
    {
        "id": "essential-mdns",
        "title": "Descoberta local de impressoras (mDNS)",
        "direction": "in",
        "port_proto": "5353/udp",
        "reason": "Mantém descoberta básica na rede local quando habilitada.",
    },
]

OPENSNITCH_CONTRACT_LABELS = {
    "pending_decision": "Aguardando decisão",
    "allow_next_attempt": "Permitir a próxima tentativa",
    "remember_version": "Lembrar esta versão",
    "trust_package_updates": "Confiar também nas atualizações deste pacote",
}


class FirewallService(ModuleService):
    """Gerencia entrada por UFW e estado/contrato de saída por aplicativo."""

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
        ufw_conf_path: Path | None = None,
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
        self.state_path = self.data_dir / "firewall_state.json"
        self.ufw_conf_path = ufw_conf_path or Path("/etc/ufw/ufw.conf")
        self.trust_store = TrustStore(
            self.data_dir / "firewall_trust.json",
            runner=self.runner,
        )
        self.apt_hooks = AptTrustHookProcessor(self.trust_store)
        self.opensnitch = OpenSnitchBridge(
            pending_store=self.pending_store,
            trust_store=self.trust_store,
            denials_path=self.data_dir / "firewall_denials.json",
        )
        self.opensnitch_client = OpenSnitchGrpcClient(bridge=self.opensnitch)

    def _load_state(self) -> dict[str, Any]:
        return read_json_safe(
            self.state_path,
            default={
                "suite_enabled_ufw": False,
                "managed_rules": [],
                "outbound_rules": [],
                "last_checked_at": None,
            },
        )

    def _save_state(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.state_path, data, mode=0o600)

    def _read_ufw_conf_enabled(self) -> bool | None:
        if not self.ufw_conf_path.exists():
            return None
        try:
            content = self.ufw_conf_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
        for line in content.splitlines():
            stripped = line.strip()
            if stripped.startswith("ENABLED="):
                val = stripped.split("=", 1)[1].strip().strip("\"'").lower()
                return val == "yes"
        return None

    def _inspect_ufw_live(self) -> tuple[bool | None, list[FirewallRule], str]:
        """Consulta estado real do UFW sem alterar configurações."""
        ufw_bin = self.runner.which("ufw")
        conf_enabled = self._read_ufw_conf_enabled()
        if not ufw_bin:
            return None, [], "Binário ufw ausente."

        # Evita 130 ms de execução do script ufw apenas para falhar sem root
        if isinstance(self.runner, SubprocessRunner) and os.geteuid() != 0:
            if conf_enabled is True:
                return True, [], "Ativo conforme /etc/ufw/ufw.conf (regras detalhadas exigem elevação)."
            if conf_enabled is False:
                return False, [], "Inativo conforme /etc/ufw/ufw.conf."
            return None, [], "Sem permissão para ler o estado ao vivo do UFW."

        res = self.runner.run([ufw_bin, "status", "numbered"], timeout=5.0)
        if res.returncode == 0:
            lines = res.stdout.splitlines()
            active = any("Status: active" in ln or "Estado: ativo" in ln for ln in lines)
            inactive = any("Status: inactive" in ln or "Estado: inativo" in ln for ln in lines)
            rules = self._parse_ufw_numbered_rules(res.stdout)
            if active:
                return True, rules, "Consultado diretamente via ufw status."
            if inactive:
                return False, rules, "UFW inativo segundo ufw status."

        if conf_enabled is True:
            return True, [], "Ativo conforme /etc/ufw/ufw.conf (regras detalhadas exigem elevação)."
        if conf_enabled is False:
            return False, [], "Inativo conforme /etc/ufw/ufw.conf."
        return None, [], "Sem permissão para ler o estado ao vivo do UFW."

    def _parse_ufw_numbered_rules(self, stdout: str) -> list[FirewallRule]:
        rules: list[FirewallRule] = []
        state_data = self._load_state()
        managed_list = [_rule_from_dict(r) for r in state_data.get("managed_rules", [])]
        pattern = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW IN|ALLOW OUT|DENY IN|DENY OUT|ALLOW|DENY|REJECT)\s+(.+)$")
        for line in stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            num, target, action_dir, source = match.groups()
            direction = "out" if "OUT" in action_dir else "in"
            action = action_dir.split()[0]
            clean_target = target.strip()
            clean_source = source.strip()
            norm_target = re.sub(r"\s+\(v6\)$", "", clean_target)
            norm_source = re.sub(r"\s+\(v6\)$", "", clean_source)
            matched = next(
                (
                    mr
                    for mr in managed_list
                    if mr.direction == direction
                    and mr.raw_spec in (clean_target, norm_target)
                    and (
                        (not mr.source_cidr and norm_source in ("Anywhere", ""))
                        or (mr.source_cidr and norm_source == mr.source_cidr)
                    )
                ),
                None,
            )
            raw_spec = f"{clean_target} {action_dir} {clean_source}".strip()
            rules.append(
                FirewallRule(
                    rule_id=matched.rule_id if matched is not None else f"ufw-{num}",
                    direction=direction,
                    target=clean_target,
                    action=action,
                    scope=matched.scope if matched is not None else f"UFW #{num} ({clean_source})",
                    app_name=matched.app_name if matched is not None else "",
                    destination=clean_source,
                    managed_by_suite=matched is not None,
                    raw_spec=matched.raw_spec if matched is not None else raw_spec,
                    source_cidr=matched.source_cidr if matched is not None else ("" if norm_source == "Anywhere" else norm_source),
                    preset_id=matched.preset_id if matched is not None else "",
                )
            )
        return rules

    def query_status(self) -> ModuleStatus:
        installed, version, origin, _ = self.inspect_primary_packages()
        opensnitch_info = self.package_inspector.inspect_package("opensnitch", binaries=["opensnitchd"])
        cfg = self.config_store.load()
        state_data = self._load_state()
        managed_rules = [_rule_from_dict(r) for r in state_data.get("managed_rules", [])]

        if not installed:
            return self.build_status(
                state=ModuleState.AUSENTE,
                installed_version=None,
                package_origin="Não instalado",
                mode_summary="UFW não instalado",
                evidence="Pacote ufw não encontrado.",
                details={
                    "essential_rules": ESSENTIAL_RULES_PREVIEW,
                    "outbound_mode": cfg.firewall_outbound_mode,
                    "opensnitch_installed": opensnitch_info.installed,
                    "opensnitch_version": opensnitch_info.version,
                    "rules": [],
                    "managed_rules": [],
                    "allowed_presets": [],
                    "contract_labels": OPENSNITCH_CONTRACT_LABELS,
                },
            )

        ufw_active, live_rules, live_evidence = self._inspect_ufw_live()
        merged_rules = live_rules if live_rules else managed_rules

        if ufw_active is None:
            mod_state = ModuleState.INDISPONIVEL
            mode_summary = "Estado do UFW indisponível sem autorização"
        elif ufw_active:
            mod_state = ModuleState.ATIVO
            out_label = (
                "Saída em bloqueio por aplicativo"
                if cfg.firewall_outbound_mode == "block_per_app" and opensnitch_info.installed
                else "Saída em monitoramento"
            )
            mode_summary = f"Firewall de entrada ativo · {out_label}"
        else:
            mod_state = ModuleState.DESATIVADO
            mode_summary = "Firewall de entrada desativado"

        sock_status = self.opensnitch_client.probe_daemon_socket()
        return self.build_status(
            state=mod_state,
            installed_version=version,
            package_origin=origin,
            mode_summary=mode_summary,
            evidence=live_evidence,
            last_confirmed_at=state_data.get("last_checked_at") or now_iso(),
            details={
                "ufw_active": ufw_active,
                "essential_rules": ESSENTIAL_RULES_PREVIEW,
                "outbound_mode": cfg.firewall_outbound_mode,
                "opensnitch_installed": opensnitch_info.installed,
                "opensnitch_version": opensnitch_info.version,
                "opensnitch_origin": opensnitch_info.origin,
                "opensnitch_socket": {
                    "path": sock_status.socket_path,
                    "reachable": sock_status.reachable,
                    "grpcio_available": sock_status.grpcio_available,
                    "detail": sock_status.detail,
                },
                "rules": [r.to_dict() for r in merged_rules],
                "managed_rules": [r.to_dict() for r in managed_rules],
                "allowed_presets": sorted({r.preset_id for r in managed_rules if r.preset_id}),
                "managed_rules_count": len(managed_rules),
                "contract_labels": OPENSNITCH_CONTRACT_LABELS,
                "trust_rules": [r.to_dict() for r in self.trust_store.list_rules()],
                "denials": self.opensnitch.list_denials(),
            },
        )

    def preview_essential_rules(self) -> list[dict[str, str]]:
        """Retorna as regras essenciais exibidas antes da ativação."""
        return list(ESSENTIAL_RULES_PREVIEW)

    def configure(self, **options: Any) -> ModuleStatus:
        if "outbound_mode" in options:
            mode = str(options["outbound_mode"])
            self.config_store.update(firewall_outbound_mode=mode)
            self.record_event(
                action="Modo de saída do firewall alterado",
                reason=(
                    "Definido como Só monitorar."
                    if mode == "monitor_only"
                    else "Definido como Bloquear por aplicativo."
                ),
                confirmation_state="confirmed",
                actor="user",
                reversible=True,
                revert_action="set_outbound_monitor_only",
            )
        return self.query_status()

    def enable(self, **options: Any) -> ModuleStatus:
        """Ativa UFW com confirmação administrativa, registrando regras gerenciadas pela suíte."""
        caller_uid = options.get("caller_uid")
        preauthorized = bool(options.get("_preauthorized", False))
        apply_essential = bool(options.get("apply_essential_rules", True))
        if not preauthorized:
            self.authorizer.require("org.mintsecurity.firewall.configure", caller_uid=caller_uid)

        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")

        state_data = self._load_state()
        was_active, _, _ = self._inspect_ufw_live()
        if was_active is False or was_active is None:
            state_data["suite_enabled_ufw"] = True

        if apply_essential:
            for item in ESSENTIAL_RULES_PREVIEW:
                if item["id"] == "essential-dns":
                    self._apply_managed_rule(state_data, ufw_bin, "out", "53", "ALLOW", "DNS essencial")
                elif item["id"] == "essential-dhcp":
                    self._apply_managed_rule(state_data, ufw_bin, "in", "68/udp", "ALLOW", "DHCP cliente")

        res = self.runner.run([ufw_bin, "--force", "enable"], timeout=10.0)
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao ativar UFW: {res.stderr.strip() or res.stdout.strip()}")

        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self._set_module_enabled_flag(True)
        self.record_event(
            action="Firewall de entrada ativado",
            reason="UFW ativado com visualização prévia de regras essenciais.",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
            revert_action="disable_firewall_revert",
        )
        return self.query_status()

    def _apply_managed_rule(
        self,
        state_data: dict[str, Any],
        ufw_bin: str,
        direction: str,
        target: str,
        action: str,
        scope: str,
        *,
        app_name: str = "",
        source_cidr: str = "",
        preset_id: str = "",
    ) -> FirewallRule:
        clean_dir, clean_target, clean_action = _validate_rule_inputs(direction, target, action)
        clean_cidr = _validate_source_cidr(source_cidr)
        clean_app = _validate_app_label(app_name) if app_name else ""

        managed: list[dict[str, Any]] = []
        for prev in state_data.get("managed_rules", []):
            if prev.get("direction") == clean_dir and prev.get("raw_spec") == clean_target:
                prev_cidr = str(prev.get("source_cidr", ""))
                if prev_cidr != clean_cidr:
                    del_argv = _build_ufw_rule_argv(
                        ufw_bin,
                        delete=True,
                        direction=str(prev.get("direction", "in")),
                        target=str(prev.get("raw_spec", "")),
                        action=str(prev.get("action", "ALLOW")),
                        source_cidr=prev_cidr,
                        is_profile=str(prev.get("preset_id", "")).startswith("ufw-profile:"),
                    )
                    self.runner.run(del_argv, timeout=10.0)
                continue
            managed.append(prev)

        argv = _build_ufw_rule_argv(
            ufw_bin,
            delete=False,
            direction=clean_dir,
            target=clean_target,
            action=clean_action,
            source_cidr=clean_cidr,
        )
        res = self.runner.run(argv, timeout=10.0)
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao aplicar regra {clean_target}: {res.stderr.strip()}")
        rule = FirewallRule(
            rule_id=f"suite-{uuid.uuid4().hex[:8]}",
            direction=clean_dir,
            target=clean_target,
            action=clean_action,
            scope=scope,
            app_name=clean_app,
            destination=clean_cidr or "Qualquer",
            managed_by_suite=True,
            raw_spec=clean_target,
            source_cidr=clean_cidr,
            preset_id=str(preset_id or ""),
        )
        managed.append(rule.to_dict())
        state_data["managed_rules"] = managed
        return rule

    def add_rule(
        self,
        *,
        direction: str,
        target: str,
        action: str = "ALLOW",
        scope: str = "Regra adicionada pelo usuário",
        app_name: str = "",
        source_cidr: str = "",
        preset_id: str = "",
        caller_uid: int | None = None,
        preauthorized: bool = False,
    ) -> FirewallRule:
        """Adiciona uma regra gerenciada pela suíte com suporte a revogação."""
        if not preauthorized:
            self.authorizer.require("org.mintsecurity.firewall.configure", caller_uid=caller_uid)
        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")
        state_data = self._load_state()
        rule = self._apply_managed_rule(
            state_data,
            ufw_bin,
            direction,
            target,
            action,
            scope,
            app_name=app_name,
            source_cidr=source_cidr,
            preset_id=preset_id,
        )
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self.record_event(
            action=f"Regra de firewall {rule.action} {rule.target}",
            reason=scope,
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
            revert_action=f"revoke_rule:{rule.rule_id}",
            details={"rule_id": rule.rule_id, "target": target, "source_cidr": rule.source_cidr},
        )
        return rule

    def allow_app_preset(
        self,
        preset_id: str,
        *,
        lan_only: bool | None = None,
        source_cidr: str | None = None,
        caller_uid: int | None = None,
        preauthorized: bool = False,
    ) -> dict[str, Any]:
        """Libera um aplicativo curado (ex.: KDE Connect, AudioRelay) no UFW com escopo LAN opcional."""
        clean_id = str(preset_id or "").strip()
        preset = PRESETS_BY_ID.get(clean_id)
        if preset is None:
            raise ValueError(f"Aplicativo predefinido desconhecido: {preset_id}")
        if not preauthorized:
            self.authorizer.require("org.mintsecurity.firewall.configure", caller_uid=caller_uid)
        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")

        use_lan = preset.default_lan_only if lan_only is None else bool(lan_only)
        cidr = (
            _validate_source_cidr(source_cidr)
            if (use_lan and source_cidr)
            else (detect_local_lan_cidr(self.runner) if use_lan else "")
        )
        scope_label = f"{preset.name} ({cidr})" if cidr else preset.name

        state_data = self._load_state()
        created: list[dict[str, Any]] = []
        for p_dir, p_target in preset.ports:
            rule = self._apply_managed_rule(
                state_data,
                ufw_bin,
                p_dir,
                p_target,
                "ALLOW",
                scope_label,
                app_name=preset.name,
                source_cidr=cidr,
                preset_id=preset.preset_id,
            )
            created.append(rule.to_dict())
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self.record_event(
            action=f"Aplicativo liberado no firewall: {preset.name}",
            reason=f"Portas {', '.join(t for _, t in preset.ports)} liberadas ({cidr or 'qualquer origem'}).",
            confirmation_state="confirmed",
            actor="user",
            app_name=preset.name,
            reversible=True,
            revert_action=f"revoke_preset:{preset.preset_id}",
        )
        return {
            "ok": True,
            "preset_id": preset.preset_id,
            "source_cidr": cidr,
            "rules": created,
            "status": self.query_status().to_dict(),
        }

    def revoke_app_preset(
        self,
        preset_id: str,
        *,
        caller_uid: int | None = None,
        preauthorized: bool = False,
    ) -> dict[str, Any]:
        """Remove todas as regras gerenciadas pertencentes a um aplicativo predefinido."""
        clean_id = str(preset_id or "").strip()
        if not clean_id:
            raise ValueError("Identificador de aplicativo vazio.")
        if not preauthorized:
            self.authorizer.require("org.mintsecurity.firewall.configure", caller_uid=caller_uid)
        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")

        state_data = self._load_state()
        managed = list(state_data.get("managed_rules", []))
        keep: list[dict[str, Any]] = []
        removed = 0
        for raw_rule in managed:
            if str(raw_rule.get("preset_id", "")) != clean_id:
                keep.append(raw_rule)
                continue
            rule = _rule_from_dict(raw_rule)
            argv = _build_ufw_rule_argv(
                ufw_bin,
                delete=True,
                direction=rule.direction,
                target=rule.raw_spec,
                action=rule.action,
                source_cidr=rule.source_cidr,
                is_profile=clean_id.startswith("ufw-profile:"),
            )
            res = self.runner.run(argv, timeout=10.0)
            if res.returncode != 0:
                raise RuntimeError(f"Falha ao remover regra {rule.target}: {res.stderr.strip()}")
            removed += 1

        state_data["managed_rules"] = keep
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        if removed:
            label = PRESETS_BY_ID[clean_id].name if clean_id in PRESETS_BY_ID else clean_id
            self.record_event(
                action=f"Permissão de firewall removida: {label}",
                reason=f"{removed} regra(s) removida(s).",
                confirmation_state="confirmed",
                actor="user",
                app_name=label,
            )
        return {
            "ok": True,
            "preset_id": clean_id,
            "removed": removed,
            "status": self.query_status().to_dict(),
        }

    def allow_custom_app_ports(
        self,
        *,
        app_name: str,
        ports: list[str],
        direction: str = "in",
        protocol: str = "both",
        lan_only: bool = True,
        source_cidr: str | None = None,
        caller_uid: int | None = None,
        preauthorized: bool = False,
    ) -> dict[str, Any]:
        """Libera portas ou faixas personalizadas para um aplicativo escolhido pelo usuário."""
        clean_app = _validate_app_label(app_name)
        clean_dir = str(direction).strip().lower()
        if clean_dir not in {"in", "out"}:
            raise ValueError(f"Direção inválida: {direction}")
        clean_proto = str(protocol).strip().lower()
        if clean_proto not in {"tcp", "udp", "both"}:
            raise ValueError(f"Protocolo inválido: {protocol}")

        raw_ports = [str(p).strip() for p in ports if str(p).strip()]
        if not raw_ports or len(raw_ports) > 20:
            raise ValueError("Informe entre 1 e 20 portas ou faixas válidas.")

        expanded_targets: list[str] = []
        for entry in raw_ports:
            if "/" in entry:
                _validate_rule_inputs(clean_dir, entry, "ALLOW")
                expanded_targets.append(entry)
            else:
                protos = ("tcp", "udp") if clean_proto == "both" else (clean_proto,)
                for pr in protos:
                    candidate = f"{entry}/{pr}"
                    _validate_rule_inputs(clean_dir, candidate, "ALLOW")
                    expanded_targets.append(candidate)

        if not preauthorized:
            self.authorizer.require("org.mintsecurity.firewall.configure", caller_uid=caller_uid)
        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")

        cidr = (
            _validate_source_cidr(source_cidr)
            if (lan_only and source_cidr)
            else (detect_local_lan_cidr(self.runner) if lan_only else "")
        )
        scope_label = f"{clean_app} ({cidr})" if cidr else clean_app
        preset_tag = f"custom:{clean_app.lower()}"

        state_data = self._load_state()
        created: list[dict[str, Any]] = []
        for tgt in expanded_targets:
            rule = self._apply_managed_rule(
                state_data,
                ufw_bin,
                clean_dir,
                tgt,
                "ALLOW",
                scope_label,
                app_name=clean_app,
                source_cidr=cidr,
                preset_id=preset_tag,
            )
            created.append(rule.to_dict())
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self.record_event(
            action=f"Porta(s) liberada(s) para {clean_app}",
            reason=f"Regras {', '.join(expanded_targets)} ({cidr or 'qualquer origem'}).",
            confirmation_state="confirmed",
            actor="user",
            app_name=clean_app,
            reversible=True,
        )
        return {
            "ok": True,
            "app_name": clean_app,
            "source_cidr": cidr,
            "rules": created,
            "status": self.query_status().to_dict(),
        }

    def allow_ufw_profile(
        self,
        profile_name: str,
        *,
        profiles_dir: Path | None = None,
        caller_uid: int | None = None,
        preauthorized: bool = False,
    ) -> dict[str, Any]:
        """Libera um perfil oficial listado em /etc/ufw/applications.d."""
        clean_name = str(profile_name or "").strip()
        if not clean_name or clean_name.startswith("-") or not _UFW_PROFILE_RE.match(clean_name):
            raise ValueError(f"Perfil UFW inválido: {profile_name}")
        available = list_ufw_app_profiles(profiles_dir or Path("/etc/ufw/applications.d"))
        matched_prof = next((p for p in available if p["name"] == clean_name), None)
        if matched_prof is None:
            raise ValueError(f"Perfil UFW não encontrado em applications.d: {clean_name}")

        if not preauthorized:
            self.authorizer.require("org.mintsecurity.firewall.configure", caller_uid=caller_uid)
        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")

        res = self.runner.run([ufw_bin, "allow", clean_name], timeout=10.0)
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao liberar perfil {clean_name}: {res.stderr.strip()}")

        state_data = self._load_state()
        pid = f"ufw-profile:{clean_name}"
        managed = [r for r in state_data.get("managed_rules", []) if r.get("preset_id") != pid]
        rule = FirewallRule(
            rule_id=f"suite-{uuid.uuid4().hex[:8]}",
            direction="in",
            target=clean_name,
            action="ALLOW",
            scope=f"Perfil UFW: {clean_name} ({matched_prof['ports']})",
            app_name=clean_name,
            destination="Qualquer",
            managed_by_suite=True,
            raw_spec=clean_name,
            source_cidr="",
            preset_id=pid,
        )
        managed.append(rule.to_dict())
        state_data["managed_rules"] = managed
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self.record_event(
            action=f"Perfil UFW liberado: {clean_name}",
            reason=f"Portas do perfil: {matched_prof['ports']}.",
            confirmation_state="confirmed",
            actor="user",
            app_name=clean_name,
            reversible=True,
            revert_action=f"revoke_rule:{rule.rule_id}",
        )
        return {
            "ok": True,
            "profile_name": clean_name,
            "rule": rule.to_dict(),
            "status": self.query_status().to_dict(),
        }

    def revoke_rule(
        self,
        rule_id: str,
        *,
        caller_uid: int | None = None,
        preauthorized: bool = False,
    ) -> bool:
        """Revoga uma regra específica criada pela suíte preservando regras externas."""
        if not preauthorized:
            self.authorizer.require("org.mintsecurity.firewall.configure", caller_uid=caller_uid)
        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")
        state_data = self._load_state()
        managed = list(state_data.get("managed_rules", []))
        target_raw = next((r for r in managed if r["rule_id"] == rule_id), None)
        if target_raw is None:
            return False

        target_rule = _rule_from_dict(target_raw)
        is_profile = target_rule.preset_id.startswith("ufw-profile:")
        if not is_profile:
            clean_dir, clean_target, clean_action = _validate_rule_inputs(
                target_rule.direction,
                target_rule.raw_spec,
                target_rule.action,
            )
            clean_cidr = _validate_source_cidr(target_rule.source_cidr)
        else:
            clean_dir, clean_target, clean_action, clean_cidr = (
                "in",
                target_rule.raw_spec,
                "ALLOW",
                "",
            )
        argv = _build_ufw_rule_argv(
            ufw_bin,
            delete=True,
            direction=clean_dir,
            target=clean_target,
            action=clean_action,
            source_cidr=clean_cidr,
            is_profile=is_profile,
        )
        res = self.runner.run(argv, timeout=10.0)
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao revogar regra: {res.stderr.strip()}")

        state_data["managed_rules"] = [r for r in managed if r["rule_id"] != rule_id]
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self.record_event(
            action="Regra de firewall revogada",
            reason=f"Regra {target_rule.target} ({target_rule.scope}) removida.",
            confirmation_state="confirmed",
            actor="user",
        )
        return True

    def disable(
        self,
        *,
        revert_suite_changes: bool = False,
        caller_uid: int | None = None,
        preauthorized: bool = False,
    ) -> ModuleStatus:
        """Desativa UFW e, se pedido, reverte apenas as regras gerenciadas pela suíte."""
        action_id = "org.mintsecurity.firewall.reset" if revert_suite_changes else "org.mintsecurity.firewall.configure"
        if not preauthorized:
            self.authorizer.require(action_id, caller_uid=caller_uid)
        ufw_bin = self.runner.which("ufw")
        if not ufw_bin:
            raise FileNotFoundError("Binário ufw não encontrado.")

        state_data = self._load_state()
        if revert_suite_changes:
            # Remove apenas regras gerenciadas pela suíte; regras externas do usuário permanecem intactas
            for raw_rule in list(state_data.get("managed_rules", [])):
                rule = _rule_from_dict(raw_rule)
                is_profile = rule.preset_id.startswith("ufw-profile:")
                if not is_profile:
                    clean_dir, clean_target, clean_action = _validate_rule_inputs(
                        rule.direction,
                        rule.raw_spec,
                        rule.action,
                    )
                    clean_cidr = _validate_source_cidr(rule.source_cidr)
                else:
                    clean_dir, clean_target, clean_action, clean_cidr = "in", rule.raw_spec, "ALLOW", ""
                argv = _build_ufw_rule_argv(
                    ufw_bin,
                    delete=True,
                    direction=clean_dir,
                    target=clean_target,
                    action=clean_action,
                    source_cidr=clean_cidr,
                    is_profile=is_profile,
                )
                self.runner.run(argv, timeout=10.0)
            state_data["managed_rules"] = []

        res = self.runner.run([ufw_bin, "disable"], timeout=10.0)
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao desativar UFW: {res.stderr.strip()}")

        state_data["suite_enabled_ufw"] = False
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self._set_module_enabled_flag(False)
        self.record_event(
            action="Firewall desativado",
            reason=(
                "Regras criadas pela suíte revertidas; regras externas preservadas."
                if revert_suite_changes
                else "Regras existentes mantidas no sistema."
            ),
            confirmation_state="confirmed",
            actor="user",
        )
        return self.query_status()
