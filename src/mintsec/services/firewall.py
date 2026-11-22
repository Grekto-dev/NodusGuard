"""Módulo 2: Firewall (UFW para entrada e contrato OpenSnitch para saída)."""

from __future__ import annotations

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
from mintsec.formatting import now_iso
from mintsec.firewall_trust import AptTrustHookProcessor, OpenSnitchBridge, TrustStore
from mintsec.opensnitch_grpc import OpenSnitchGrpcClient
from mintsec.runner import SubprocessRunner
from mintsec.services.base import ModuleService


_FW_TARGET_RE = re.compile(
    r"^(\d{1,5}(?::\d{1,5})?(?:/(?:tcp|udp))?|[a-zA-Z][a-zA-Z0-9._-]{0,31})$"
)


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
    return clean_dir, clean_target, clean_action


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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
        managed_specs = {r.get("raw_spec") for r in state_data.get("managed_rules", [])}
        pattern = re.compile(r"^\[\s*(\d+)\]\s+(.+?)\s{2,}(ALLOW IN|ALLOW OUT|DENY IN|DENY OUT|ALLOW|DENY|REJECT)\s+(.+)$")
        for line in stdout.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            num, target, action_dir, source = match.groups()
            direction = "out" if "OUT" in action_dir else "in"
            action = action_dir.split()[0]
            raw_spec = f"{target} {action_dir} {source}".strip()
            rules.append(
                FirewallRule(
                    rule_id=f"ufw-{num}",
                    direction=direction,
                    target=target.strip(),
                    action=action,
                    scope=f"UFW #{num} ({source.strip()})",
                    managed_by_suite=raw_spec in managed_specs or target.strip() in managed_specs,
                    raw_spec=raw_spec,
                )
            )
        return rules

    def query_status(self) -> ModuleStatus:
        installed, version, origin, _ = self.inspect_primary_packages()
        opensnitch_info = self.package_inspector.inspect_package("opensnitch", binaries=["opensnitchd"])
        cfg = self.config_store.load()
        state_data = self._load_state()

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
                    "contract_labels": OPENSNITCH_CONTRACT_LABELS,
                },
            )

        ufw_active, live_rules, live_evidence = self._inspect_ufw_live()
        managed_rules = [FirewallRule(**r) for r in state_data.get("managed_rules", [])]
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
    ) -> FirewallRule:
        clean_dir, clean_target, clean_action = _validate_rule_inputs(direction, target, action)
        verb = clean_action.lower()
        argv = [ufw_bin, verb]
        if clean_dir == "out":
            argv.append("out")
        argv.append(clean_target)
        res = self.runner.run(argv, timeout=10.0)
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao aplicar regra {clean_target}: {res.stderr.strip()}")
        rule = FirewallRule(
            rule_id=f"suite-{uuid.uuid4().hex[:8]}",
            direction=clean_dir,
            target=clean_target,
            action=clean_action,
            scope=scope,
            managed_by_suite=True,
            raw_spec=clean_target,
        )
        managed = [r for r in state_data.get("managed_rules", []) if r.get("raw_spec") != clean_target]
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
        rule = self._apply_managed_rule(state_data, ufw_bin, direction, target, action, scope)
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self.record_event(
            action=f"Regra de firewall {rule.action} {rule.target}",
            reason=scope,
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
            revert_action=f"revoke_rule:{rule.rule_id}",
            details={"rule_id": rule.rule_id, "target": target},
        )
        return rule

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
        target_rule = next((r for r in managed if r["rule_id"] == rule_id), None)
        if target_rule is None:
            return False

        clean_dir, clean_target, clean_action = _validate_rule_inputs(
            target_rule["direction"],
            target_rule["raw_spec"],
            target_rule["action"],
        )
        verb = clean_action.lower()
        argv = [ufw_bin, "delete", verb]
        if clean_dir == "out":
            argv.append("out")
        argv.append(clean_target)
        res = self.runner.run(argv, timeout=10.0)
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao revogar regra: {res.stderr.strip()}")

        state_data["managed_rules"] = [r for r in managed if r["rule_id"] != rule_id]
        state_data["last_checked_at"] = now_iso()
        self._save_state(state_data)
        self.record_event(
            action="Regra de firewall revogada",
            reason=f"Regra {target_rule['target']} ({target_rule['scope']}) removida.",
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
            for rule in list(state_data.get("managed_rules", [])):
                clean_dir, clean_target, clean_action = _validate_rule_inputs(
                    rule["direction"],
                    rule["raw_spec"],
                    rule["action"],
                )
                verb = clean_action.lower()
                argv = [ufw_bin, "delete", verb]
                if clean_dir == "out":
                    argv.append("out")
                argv.append(clean_target)
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
