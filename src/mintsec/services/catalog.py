"""Catálogo unificado dos 7 módulos, cálculo do escudo da página inicial e fluxos."""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Callable

from mintsec.app_log import AppLogEntry, AppLogStore
from mintsec.auth import CallerAuthorizer
from mintsec.autostart import sync_autostart as sync_autostart_file
from mintsec.config import VALID_PAUSE_MODES, VALID_SCAN_POST_ACTIONS, ConfigStore, SuiteConfig
from mintsec.contracts import (
    ModuleManifest,
    ModuleState,
    ModuleStatus,
    PendingDecision,
    load_manifests,
)
from mintsec.dbus_client import SystemModuleClient, is_system_bus_mode
from mintsec.firewall_apps import (
    PRESETS_BY_ID,
    detect_app_presets,
    detect_listening_apps,
    detect_local_lan_cidr,
    list_ufw_app_profiles,
)
from mintsec.formatting import format_confirmed_at, now_iso
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.packaging import AptKitInstaller, PackageInspector
from mintsec.pending import PendingStore
from mintsec.power import execute_post_scan_action as run_post_scan_power_action
from mintsec.runner import CommandRunner, SubprocessRunner

SYSTEM_PRIVILEGED_MODULES = frozenset({"firewall", "browsing"})
from mintsec.services.antimalware import AntimalwareService
from mintsec.services.base import ModuleService
from mintsec.services.browsing import BrowsingService
from mintsec.services.containment import ContainmentService
from mintsec.services.firewall import FirewallService
from mintsec.services.isolation import IsolationService
from mintsec.services.network import NetworkService
from mintsec.services.recovery import RecoveryService
from mintsec.services.rescue import RescueService


@dataclass(frozen=True)
class HomeVerdict:
    """Estado principal apresentado pelo escudo na página Início."""

    headline: str
    evidence_text: str
    severity: str  # 'ok' | 'setup' | 'warning' | 'critical'
    primary_cta_label: str | None
    primary_cta_action: str | None
    primary_cta_target: str | None = None


class PlannedModuleService(ModuleService):
    """Representação honesta para os módulos das fases 2 e 3."""

    def query_status(self) -> ModuleStatus:
        installed, version, origin, _ = self.inspect_primary_packages()
        phase_note = (
            "Previsto para a Fase 2 (Proteção contínua)"
            if self.manifest.phase == "continuous"
            else "Experimental · condicionado à homologação H7"
        )
        if not installed:
            return self.build_status(
                state=ModuleState.AUSENTE,
                installed_version=None,
                package_origin="Não instalado",
                mode_summary=phase_note,
                evidence="Pacote do módulo não instalado.",
            )
        enabled = self._module_enabled_flag(False)
        state = ModuleState.ATIVO if enabled else ModuleState.DESATIVADO
        return self.build_status(
            state=state,
            installed_version=version,
            package_origin=origin,
            mode_summary=phase_note,
            evidence=f"Pacote base presente ({origin}). {phase_note}.",
            last_confirmed_at=now_iso() if enabled else None,
        )

    def configure(self, **options: Any) -> ModuleStatus:
        return self.query_status()

    def enable(self, **options: Any) -> ModuleStatus:
        self._set_module_enabled_flag(True)
        return self.query_status()

    def disable(self, *, revert_suite_changes: bool = False) -> ModuleStatus:
        self._set_module_enabled_flag(False)
        return self.query_status()


class SuiteController:
    """Fachada central consumida pelo painel GTK 3 e pelos serviços D-Bus."""

    def __init__(
        self,
        *,
        manifests_dir: Path | None = None,
        config_store: ConfigStore | None = None,
        pending_store: PendingStore | None = None,
        history_store: HistoryStore | None = None,
        incident_manager: IncidentManager | None = None,
        runner: CommandRunner | None = None,
        authorizer: CallerAuthorizer | None = None,
        installer: AptKitInstaller | None = None,
        data_dir: Path | None = None,
        clamav_db_dir: Path | None = None,
        post_scan_executor: Callable[[str], dict[str, Any]] | None = None,
        app_log_store: AppLogStore | None = None,
    ) -> None:
        self._post_scan_executor = post_scan_executor
        self._extra_fw_app_dirs: tuple[Path, ...] = ()
        self._fw_profiles_dir: Path | None = None
        self.manifests: dict[str, ModuleManifest] = load_manifests(manifests_dir)
        self.config_store = config_store or ConfigStore()
        cfg = self.config_store.load()
        self.pending_store = pending_store or PendingStore()
        self.history_store = history_store or HistoryStore(enabled=cfg.history_enabled)
        self.app_log = app_log_store or AppLogStore(
            (data_dir / "app.log.jsonl") if data_dir is not None else None
        )
        self.incident_manager = incident_manager or IncidentManager()
        self.runner = runner or SubprocessRunner()
        self.package_inspector = PackageInspector(self.runner)
        self.authorizer = authorizer or CallerAuthorizer()
        self.installer = installer or AptKitInstaller(dry_run=not is_system_bus_mode())
        self.dbus_client = SystemModuleClient(self.manifests)

        common = dict(
            config_store=self.config_store,
            pending_store=self.pending_store,
            history_store=self.history_store,
            package_inspector=self.package_inspector,
            runner=self.runner,
            authorizer=self.authorizer,
        )
        self.antimalware = AntimalwareService(
            manifest=self.manifests["antimalware"],
            data_dir=data_dir,
            clamav_db_dir=clamav_db_dir,
            **common,
        )
        self.firewall = FirewallService(
            manifest=self.manifests["firewall"],
            data_dir=data_dir,
            **common,
        )
        self.recovery = RecoveryService(
            manifest=self.manifests["recovery"],
            incident_manager=self.incident_manager,
            data_dir=data_dir,
            **common,
        )
        self.containment = ContainmentService(
            config_store=self.config_store,
            pending_store=self.pending_store,
        )
        self.network = NetworkService(
            manifest=self.manifests["network"],
            data_dir=data_dir,
            **common,
        )
        self.browsing = BrowsingService(
            manifest=self.manifests["browsing"],
            data_dir=data_dir,
            **common,
        )
        self.isolation = IsolationService(
            manifest=self.manifests["isolation"],
            data_dir=data_dir,
            **common,
        )
        self.rescue = RescueService(
            manifest=self.manifests["rescue"],
            data_dir=data_dir,
            **common,
        )
        self.services: dict[str, ModuleService] = {
            "antimalware": self.antimalware,
            "firewall": self.firewall,
            "recovery": self.recovery,
            "network": self.network,
            "browsing": self.browsing,
            "isolation": self.isolation,
            "rescue": self.rescue,
        }
        self._cache_lock = threading.Lock()
        self._status_cache: dict[str, ModuleStatus] = {}
        self._status_cache_ts: float = 0.0
        self._refresh_in_flight: bool = False
        self._refresh_force_queued: bool = False
        self._refresh_callbacks: list[Callable[[dict[str, ModuleStatus]], None]] = []

    MODULE_ORDER = ("antimalware", "firewall", "recovery", "network", "browsing", "isolation", "rescue")

    @property
    def is_live_host_runner(self) -> bool:
        """Indica se usa o runner real de subprocessos (em contraste com fakes de teste)."""
        return isinstance(self.runner, SubprocessRunner)

    def invalidate_cache(self, module_id: str | None = None, *, include_packages: bool = False) -> None:
        """Invalida o cache em memória de estado de módulos (e opcionalmente pacotes)."""
        if include_packages:
            self.package_inspector.invalidate_cache()
        with self._cache_lock:
            if module_id is None:
                self._status_cache.clear()
                self._status_cache_ts = 0.0
            else:
                self._status_cache.pop(module_id, None)
                self._status_cache_ts = 0.0

    def get_cached_statuses(self, *, max_age_secs: float | None = None) -> dict[str, ModuleStatus] | None:
        """Retorna os 7 estados cacheados se completos e dentro da validade, ou None."""
        with self._cache_lock:
            if len(self._status_cache) < len(self.services):
                return None
            if max_age_secs is not None and (time.monotonic() - self._status_cache_ts) > max_age_secs:
                return None
            return {mid: self._status_cache[mid] for mid in self.MODULE_ORDER if mid in self._status_cache}

    def _use_system_bus(self) -> bool:
        return self.is_live_host_runner and is_system_bus_mode()

    def _enrich_firewall_status(self, status: ModuleStatus) -> ModuleStatus:
        """Anexa presets de apps, escutas ativas, perfis UFW e faixa LAN ao status do firewall."""
        details = dict(status.details)
        listening = detect_listening_apps(self.runner)
        lan_cidr = detect_local_lan_cidr(self.runner)
        profiles = (
            list_ufw_app_profiles(self._fw_profiles_dir)
            if self._fw_profiles_dir is not None
            else list_ufw_app_profiles()
        )
        allowed_presets = {str(p) for p in (details.get("allowed_presets") or []) if p}
        for rule in details.get("managed_rules") or details.get("rules") or []:
            pid = str(rule.get("preset_id") or "")
            if pid:
                allowed_presets.add(pid)
        presets = detect_app_presets(
            self.runner,
            extra_app_dirs=self._extra_fw_app_dirs,
            listening_apps=listening,
        )
        for preset in presets:
            preset["allowed"] = preset["preset_id"] in allowed_presets
        details["app_presets"] = presets
        details["listening_apps"] = listening
        details["ufw_profiles"] = profiles
        details["lan_cidr"] = lan_cidr
        details["allowed_presets"] = sorted(allowed_presets)
        return ModuleStatus(
            module_id=status.module_id or "firewall",
            display_name=status.display_name or self.manifests["firewall"].display_name,
            state=status.state,
            installed_version=status.installed_version,
            package_origin=status.package_origin,
            mode_summary=status.mode_summary,
            last_confirmed_at=status.last_confirmed_at,
            evidence=status.evidence,
            degraded_reason=status.degraded_reason,
            needs_setup=status.needs_setup,
            phase=status.phase,
            experimental=status.experimental,
            details=details,
        )

    def _overlay_firewall_user_state(self, status: ModuleStatus) -> ModuleStatus:
        """Mescla preferências e estado do usuário (saída/OpenSnitch) no status vindo do daemon."""
        cfg = self.config_store.load()
        details = dict(status.details)
        details["outbound_mode"] = cfg.firewall_outbound_mode
        details["trust_rules"] = [r.to_dict() for r in self.firewall.trust_store.list_rules()]
        details["denials"] = self.firewall.opensnitch.list_denials()
        opensnitch_installed = bool(details.get("opensnitch_installed", False))
        mode_summary = status.mode_summary
        if status.state == ModuleState.ATIVO:
            out_label = (
                "Saída em bloqueio por aplicativo"
                if cfg.firewall_outbound_mode == "block_per_app" and opensnitch_installed
                else "Saída em monitoramento"
            )
            mode_summary = f"Firewall de entrada ativo · {out_label}"
        merged = ModuleStatus(
            module_id=status.module_id or "firewall",
            display_name=status.display_name or self.manifests["firewall"].display_name,
            state=status.state,
            installed_version=status.installed_version,
            package_origin=status.package_origin,
            mode_summary=mode_summary,
            last_confirmed_at=status.last_confirmed_at,
            evidence=status.evidence,
            degraded_reason=status.degraded_reason,
            needs_setup=status.needs_setup,
            phase=status.phase,
            experimental=status.experimental,
            details=details,
        )
        return self._enrich_firewall_status(merged)

    def _query_module(self, module_id: str) -> ModuleStatus:
        if module_id == "firewall" and self._use_system_bus():
            data = self.dbus_client.query_status("firewall", self.firewall)
            return self._overlay_firewall_user_state(ModuleStatus.from_dict(data))
        st = self.services[module_id].query_status()
        if module_id == "firewall":
            return self._enrich_firewall_status(st)
        return st

    def _sync_user_module_flag(self, module_id: str, enabled: bool) -> None:
        svc = self.services.get(module_id)
        if svc is None:
            return
        svc._set_module_enabled_flag(enabled)
        if module_id == "browsing":
            b_state = self.browsing._load_state()
            b_state["enabled"] = bool(enabled)
            if enabled:
                b_state["last_confirmed_at"] = now_iso()
            self.browsing._save_state(b_state)

    def enable_module(self, module_id: str, **options: Any) -> ModuleStatus:
        """Ativa um módulo usando daemon D-Bus privilegiado quando aplicável."""
        svc = self.services[module_id]
        if module_id in SYSTEM_PRIVILEGED_MODULES and self._use_system_bus():
            raw = self.dbus_client.enable(module_id, svc, options or None)
            st = ModuleStatus.from_dict(raw)
            self._sync_user_module_flag(module_id, st.state == ModuleState.ATIVO)
            if module_id == "firewall":
                st = self._overlay_firewall_user_state(st)
                self.history_store.record(
                    module_id="firewall",
                    action="Firewall de entrada ativado",
                    reason="UFW ativado com visualização prévia de regras essenciais.",
                    confirmation_state="confirmed",
                    actor="user",
                    reversible=True,
                    revert_action="disable_firewall_revert",
                )
            else:
                self.history_store.record(
                    module_id="browsing",
                    action="Filtro DNS local ativado",
                    reason="Filtro local habilitado pelo serviço administrativo.",
                    confirmation_state="confirmed",
                    actor="user",
                    reversible=True,
                )
            self.invalidate_cache(module_id)
            self.log_event("INFO", module_id, f"Módulo ativado: {module_id}", source="controller")
            return st
        st = svc.enable(**options)
        self.invalidate_cache(module_id)
        self.log_event("INFO", module_id, f"Módulo ativado: {module_id}", source="controller")
        return st

    def disable_module(self, module_id: str, *, revert_suite_changes: bool = False) -> ModuleStatus:
        """Desativa um módulo usando daemon D-Bus privilegiado quando aplicável."""
        svc = self.services[module_id]
        if module_id in SYSTEM_PRIVILEGED_MODULES and self._use_system_bus():
            raw = self.dbus_client.disable(
                module_id,
                svc,
                revert_suite_changes=revert_suite_changes,
            )
            st = ModuleStatus.from_dict(raw)
            self._sync_user_module_flag(module_id, st.state == ModuleState.ATIVO)
            if module_id == "firewall":
                st = self._overlay_firewall_user_state(st)
                self.history_store.record(
                    module_id="firewall",
                    action="Firewall desativado",
                    reason=(
                        "Regras criadas pela suíte revertidas; regras externas preservadas."
                        if revert_suite_changes
                        else "Regras existentes mantidas no sistema."
                    ),
                    confirmation_state="confirmed",
                    actor="user",
                )
            else:
                self.history_store.record(
                    module_id="browsing",
                    action="Filtro DNS local desativado",
                    reason="Configuração DNS anterior restaurada." if revert_suite_changes else "Filtro pausado.",
                    confirmation_state="confirmed",
                    actor="user",
                )
            self.invalidate_cache(module_id)
            self.log_event("INFO", module_id, f"Módulo desativado: {module_id}", source="controller")
            return st
        st = svc.disable(revert_suite_changes=revert_suite_changes)
        self.invalidate_cache(module_id)
        self.log_event("INFO", module_id, f"Módulo desativado: {module_id}", source="controller")
        return st

    def revoke_firewall_rule(self, rule_id: str) -> bool:
        """Revoga regra gerenciada do firewall roteando pelo serviço root no modo instalado."""
        if self._use_system_bus():
            res = self.dbus_client.revoke_firewall_rule(rule_id, self.firewall)
            ok = bool(res.get("ok", False))
            if ok:
                self.history_store.record(
                    module_id="firewall",
                    action="Regra de firewall revogada",
                    reason=f"Regra {rule_id} removida.",
                    confirmation_state="confirmed",
                    actor="user",
                )
            self.invalidate_cache("firewall")
            self.log_event(
                "INFO" if ok else "WARNING",
                "firewall",
                f"Revogação de regra {rule_id}: {'ok' if ok else 'não encontrada'}",
                source="firewall",
            )
            return ok
        ok = bool(self.firewall.revoke_rule(rule_id))
        self.invalidate_cache("firewall")
        self.log_event(
            "INFO" if ok else "WARNING",
            "firewall",
            f"Revogação de regra {rule_id}: {'ok' if ok else 'não encontrada'}",
            source="firewall",
        )
        return ok

    def allow_firewall_preset(
        self,
        preset_id: str,
        *,
        lan_only: bool | None = None,
        source_cidr: str | None = None,
    ) -> dict[str, Any]:
        """Libera um aplicativo curado (KDE Connect, AudioRelay etc.) pelo serviço de firewall."""
        if self._use_system_bus():
            res = self.dbus_client.allow_firewall_preset(
                preset_id,
                self.firewall,
                lan_only=lan_only,
                source_cidr=source_cidr,
            )
            preset = PRESETS_BY_ID.get(preset_id)
            app_label = preset.name if preset else preset_id
            self.history_store.record(
                module_id="firewall",
                action=f"Aplicativo liberado no firewall: {app_label}",
                reason=f"Exceção aplicada ({res.get('source_cidr') or 'qualquer origem'}).",
                confirmation_state="confirmed",
                actor="user",
                app_name=app_label,
                reversible=True,
                revert_action=f"revoke_preset:{preset_id}",
            )
            if isinstance(res.get("status"), dict):
                res["status"] = self._overlay_firewall_user_state(
                    ModuleStatus.from_dict(res["status"])
                ).to_dict()
            self.invalidate_cache("firewall")
            self.log_event("INFO", "firewall", f"Aplicativo liberado no firewall: {app_label}", source="firewall")
            return res

        res = self.firewall.allow_app_preset(
            preset_id,
            lan_only=lan_only,
            source_cidr=source_cidr,
        )
        if isinstance(res.get("status"), dict):
            res["status"] = self._enrich_firewall_status(
                ModuleStatus.from_dict(res["status"])
            ).to_dict()
        self.invalidate_cache("firewall")
        self.log_event("INFO", "firewall", f"Aplicativo liberado no firewall: {preset_id}", source="firewall")
        return res

    def revoke_firewall_preset(self, preset_id: str) -> dict[str, Any]:
        """Remove todas as regras gerenciadas de um aplicativo predefinido."""
        if self._use_system_bus():
            res = self.dbus_client.revoke_firewall_preset(preset_id, self.firewall)
            preset = PRESETS_BY_ID.get(preset_id)
            app_label = preset.name if preset else preset_id
            if res.get("removed"):
                self.history_store.record(
                    module_id="firewall",
                    action=f"Permissão de firewall removida: {app_label}",
                    reason=f"{res.get('removed', 0)} regra(s) removida(s).",
                    confirmation_state="confirmed",
                    actor="user",
                    app_name=app_label,
                )
            if isinstance(res.get("status"), dict):
                res["status"] = self._overlay_firewall_user_state(
                    ModuleStatus.from_dict(res["status"])
                ).to_dict()
            self.invalidate_cache("firewall")
            return res

        res = self.firewall.revoke_app_preset(preset_id)
        if isinstance(res.get("status"), dict):
            res["status"] = self._enrich_firewall_status(
                ModuleStatus.from_dict(res["status"])
            ).to_dict()
        self.invalidate_cache("firewall")
        self.log_event("INFO", "firewall", f"Permissão de aplicativo removida: {preset_id}", source="firewall")
        return res

    def allow_firewall_custom_ports(
        self,
        *,
        app_name: str,
        ports: list[str],
        direction: str = "in",
        protocol: str = "both",
        lan_only: bool = True,
        source_cidr: str | None = None,
    ) -> dict[str, Any]:
        """Libera portas ou faixas personalizadas para um aplicativo no firewall."""
        if self._use_system_bus():
            res = self.dbus_client.allow_firewall_custom_ports(
                self.firewall,
                app_name=app_name,
                ports=ports,
                direction=direction,
                protocol=protocol,
                lan_only=lan_only,
                source_cidr=source_cidr,
            )
            self.history_store.record(
                module_id="firewall",
                action=f"Porta(s) liberada(s) para {app_name}",
                reason=f"Portas {', '.join(ports)} ({res.get('source_cidr') or 'qualquer origem'}).",
                confirmation_state="confirmed",
                actor="user",
                app_name=app_name,
                reversible=True,
            )
            if isinstance(res.get("status"), dict):
                res["status"] = self._overlay_firewall_user_state(
                    ModuleStatus.from_dict(res["status"])
                ).to_dict()
            self.invalidate_cache("firewall")
            return res

        res = self.firewall.allow_custom_app_ports(
            app_name=app_name,
            ports=ports,
            direction=direction,
            protocol=protocol,
            lan_only=lan_only,
            source_cidr=source_cidr,
        )
        if isinstance(res.get("status"), dict):
            res["status"] = self._enrich_firewall_status(
                ModuleStatus.from_dict(res["status"])
            ).to_dict()
        self.invalidate_cache("firewall")
        return res

    def allow_firewall_ufw_profile(self, profile_name: str) -> dict[str, Any]:
        """Libera perfil oficial do UFW (/etc/ufw/applications.d)."""
        if self._use_system_bus():
            res = self.dbus_client.allow_firewall_ufw_profile(profile_name, self.firewall)
            self.history_store.record(
                module_id="firewall",
                action=f"Perfil UFW liberado: {profile_name}",
                reason="Perfil de aplicativo permitido no firewall.",
                confirmation_state="confirmed",
                actor="user",
                app_name=profile_name,
                reversible=True,
            )
            if isinstance(res.get("status"), dict):
                res["status"] = self._overlay_firewall_user_state(
                    ModuleStatus.from_dict(res["status"])
                ).to_dict()
            self.invalidate_cache("firewall")
            return res

        res = self.firewall.allow_ufw_profile(
            profile_name,
            profiles_dir=self._fw_profiles_dir,
        )
        if isinstance(res.get("status"), dict):
            res["status"] = self._enrich_firewall_status(
                ModuleStatus.from_dict(res["status"])
            ).to_dict()
        self.invalidate_cache("firewall")
        return res

    def update_antimalware_signatures(self) -> dict[str, Any]:
        """Atualiza assinaturas ClamAV com FreshClam via serviço root quando instalado."""
        if self._use_system_bus():
            res = self.dbus_client.update_antimalware_signatures(self.antimalware)
            ok = bool(res.get("ok"))
            if ok:
                am_state = self.antimalware._load_state()
                am_state["last_signature_update_at"] = now_iso()
                self.antimalware._save_state(am_state)
            self.history_store.record(
                module_id="antimalware",
                action="Atualização de assinaturas ClamAV",
                reason=(
                    "FreshClam concluído com sucesso."
                    if ok
                    else f"Falha FreshClam: {str(res.get('stderr') or '').strip()}"
                ),
                confirmation_state="confirmed" if ok else "failed",
                actor="suite",
                evidence=str(res.get("stdout") or "").strip()[:300],
            )
            self.invalidate_cache("antimalware")
            self.log_event(
                "INFO" if ok else "ERROR",
                "antimalware",
                "Atualização de definições ClamAV concluída" if ok else "Falha ao atualizar definições ClamAV",
                details=str(res.get("stderr") or res.get("stdout") or "").strip()[:500],
                source="freshclam",
            )
            return res
        res = self.antimalware.update_signatures()
        ok = bool(res.get("ok"))
        self.invalidate_cache("antimalware")
        self.log_event(
            "INFO" if ok else "ERROR",
            "antimalware",
            "Atualização de definições ClamAV concluída" if ok else "Falha ao atualizar definições ClamAV",
            details=str(res.get("stderr") or res.get("stdout") or "").strip()[:500],
            source="freshclam",
        )
        return res

    def log_event(
        self,
        level: str,
        category: str,
        message: str,
        *,
        details: str = "",
        source: str = "",
    ) -> AppLogEntry:
        """Registra evento operacional visível em Configurações -> Logs."""
        return self.app_log.record(level, category, message, details=details, source=source)

    def list_app_logs(
        self,
        *,
        level: str | None = None,
        query: str = "",
        limit: int = 500,
    ) -> list[AppLogEntry]:
        return self.app_log.list_entries(level=level, query=query, limit=limit)

    def clear_app_logs(self) -> int:
        return self.app_log.clear()

    def execute_post_scan_action(self, action: str) -> dict[str, Any]:
        """Executa ação configurada ao término do scan (nada, suspender ou desligar)."""
        clean = str(action).strip()
        if clean not in VALID_SCAN_POST_ACTIONS:
            raise ValueError(f"Ação pós-scan inválida: {action}")
        if clean == "none":
            return {"ok": True, "action": "none", "method": "noop"}
        self.history_store.record(
            module_id="antimalware",
            action=f"Ação pós-scan: {clean}",
            reason="Executada após término da verificação conforme escolha do usuário.",
            confirmation_state="confirmed",
            actor="user",
        )
        if self._post_scan_executor is not None:
            return dict(self._post_scan_executor(clean))
        if not self.is_live_host_runner:
            return {"ok": True, "action": clean, "method": "simulated"}
        return run_post_scan_power_action(clean, runner=self.runner)

    def get_module_status(
        self,
        module_id: str,
        *,
        use_cache: bool = False,
        max_age_secs: float = 15.0,
    ) -> ModuleStatus:
        """Consulta um módulo específico, usando cache recente quando permitido."""
        if use_cache and self.is_live_host_runner:
            with self._cache_lock:
                if (time.monotonic() - self._status_cache_ts) <= max_age_secs and module_id in self._status_cache:
                    return self._status_cache[module_id]
        st = self._query_module(module_id)
        with self._cache_lock:
            self._status_cache[module_id] = st
            if len(self._status_cache) >= len(self.services) and self._status_cache_ts == 0.0:
                self._status_cache_ts = time.monotonic()
        return st

    def _prime_packages(self) -> None:
        pkgs: list[str] = []
        bin_map: dict[str, list[str]] = {}
        for mid in self.MODULE_ORDER:
            manifest = self.manifests.get(mid)
            if manifest is None:
                continue
            bins = list(manifest.engine.get("binaries", []))
            for pkg in (*manifest.packages, *manifest.optional_packages):
                pkgs.append(pkg)
                bin_map.setdefault(pkg, []).extend(bins)
        extra_bins = {
            "apparmor": ["aa-status"],
            "dnscrypt-proxy": ["dnscrypt-proxy"],
            "dnsmasq": ["dnsmasq"],
            "dnsmasq-base": ["dnsmasq"],
            "opensnitch": ["opensnitchd"],
            "gpgv": ["gpgv"],
            "udisks2": ["udisksctl"],
        }
        for pkg, bins in extra_bins.items():
            pkgs.append(pkg)
            bin_map[pkg] = list(dict.fromkeys([*bin_map.get(pkg, []), *bins]))
        self.package_inspector.prime_cache(pkgs, binaries_by_pkg=bin_map)

    def reload_config(self) -> SuiteConfig:
        cfg = self.config_store.load()
        self.history_store.set_enabled(cfg.history_enabled)
        return cfg

    def all_statuses(
        self,
        *,
        use_cache: bool = False,
        max_age_secs: float = 15.0,
        on_progress: Callable[[int, int, str], None] | None = None,
    ) -> dict[str, ModuleStatus]:
        """Consulta os 7 módulos preservando ordem canônica (com cache/paralelismo no host real)."""
        if use_cache and self.is_live_host_runner:
            cached = self.get_cached_statuses(max_age_secs=max_age_secs)
            if cached is not None:
                if on_progress is not None:
                    total = len(cached)
                    on_progress(total, total, "")
                return cached

        mids = [mid for mid in self.MODULE_ORDER if mid in self.services]
        total = len(mids)
        if self.is_live_host_runner:
            self._prime_packages()
            results: dict[str, ModuleStatus] = {}
            with ThreadPoolExecutor(max_workers=total or 1) as pool:
                future_map = {pool.submit(self._query_module, mid): mid for mid in mids}
                done_cnt = 0
                for fut in as_completed(future_map):
                    mid = future_map[fut]
                    results[mid] = fut.result()
                    done_cnt += 1
                    if on_progress is not None:
                        try:
                            on_progress(done_cnt, total, mid)
                        except Exception:
                            pass
            ordered = {mid: results[mid] for mid in mids}
        else:
            ordered = {}
            for idx, mid in enumerate(mids, start=1):
                ordered[mid] = self._query_module(mid)
                if on_progress is not None:
                    try:
                        on_progress(idx, total, mid)
                    except Exception:
                        pass

        with self._cache_lock:
            self._status_cache = dict(ordered)
            self._status_cache_ts = time.monotonic()
        return ordered

    def refresh_statuses_async(
        self,
        on_done: Callable[[dict[str, ModuleStatus]], None],
        *,
        force: bool = False,
        max_age_secs: float = 15.0,
        on_progress: Callable[[int, int, str], None] | None = None,
    ) -> bool:
        """Agenda atualização em background coalescendo chamadas simultâneas."""
        if not force and self.is_live_host_runner:
            cached = self.get_cached_statuses(max_age_secs=max_age_secs)
            if cached is not None:
                on_done(cached)
                return False

        with self._cache_lock:
            self._refresh_callbacks.append(on_done)
            if force:
                self._refresh_force_queued = True
            if self._refresh_in_flight:
                return False
            self._refresh_in_flight = True

        def _worker() -> None:
            while True:
                with self._cache_lock:
                    run_force = self._refresh_force_queued
                    self._refresh_force_queued = False
                if run_force:
                    self.invalidate_cache(include_packages=True)
                try:
                    statuses = self.all_statuses(
                        use_cache=not run_force,
                        max_age_secs=max_age_secs,
                        on_progress=on_progress,
                    )
                except Exception as exc:  # noqa: BLE001
                    self.log_event(
                        "ERROR",
                        "refresh",
                        "Falha ao atualizar status das proteções",
                        details=str(exc),
                        source="controller",
                    )
                    statuses = {}
                with self._cache_lock:
                    if self._refresh_force_queued:
                        continue
                    callbacks = list(self._refresh_callbacks)
                    self._refresh_callbacks.clear()
                    self._refresh_in_flight = False
                for cb in callbacks:
                    try:
                        cb(statuses)
                    except Exception:
                        pass
                break

        threading.Thread(target=_worker, daemon=True).start()
        return True

    def get_home_verdict(
        self,
        statuses: dict[str, ModuleStatus] | None = None,
        cfg: SuiteConfig | None = None,
        open_pending: list[PendingDecision] | None = None,
    ) -> HomeVerdict:
        """Calcula frase verificável e botão único do escudo conforme Seção 5.1."""
        statuses = statuses or self.all_statuses()
        cfg = cfg or self.config_store.load()
        open_pending = open_pending if open_pending is not None else self.pending_store.list_open()

        # 1. Prioridade máxima: aplicativo pausado aguardando decisão
        paused = [p for p in open_pending if p.kind == "paused_app"]
        if paused:
            target = paused[0]
            return HomeVerdict(
                headline="Um aplicativo está pausado",
                evidence_text=f"{target.app_name or 'Aplicativo'} pausado · {target.evidence}",
                severity="critical",
                primary_cta_label="Revisar aplicativo",
                primary_cta_action="review_pending",
                primary_cta_target=target.pending_id,
            )

        # 2. Outras pendências abertas
        if open_pending:
            first = open_pending[0]
            return HomeVerdict(
                headline=f"Há {len(open_pending)} pendência(s) para revisar",
                evidence_text=f"{first.title} · {first.evidence}",
                severity="warning",
                primary_cta_label="Revisar pendências",
                primary_cta_action="open_pending",
                primary_cta_target=first.pending_id,
            )

        # 3. Primeiro uso ainda não concluído
        if not cfg.first_run_completed:
            return HomeVerdict(
                headline="Escolha suas proteções",
                evidence_text="Revise a configuração recomendada ou escolha os módulos desejados.",
                severity="setup",
                primary_cta_label="Revisar configuração recomendada",
                primary_cta_action="open_first_run",
            )

        # 4. Degradação, indisponibilidade ou verificação incompleta em módulos habilitados
        for mod_id in ("antimalware", "firewall", "recovery"):
            st = statuses[mod_id]
            if st.state == ModuleState.VERIFICACAO_INCOMPLETA:
                return HomeVerdict(
                    headline="Última verificação ficou incompleta",
                    evidence_text=st.evidence,
                    severity="warning",
                    primary_cta_label="Ver itens não verificados",
                    primary_cta_action="open_scans",
                )
            if st.state == ModuleState.INDISPONIVEL:
                return HomeVerdict(
                    headline=f"{st.display_name}: estado indisponível",
                    evidence_text=f"{st.evidence} · {format_confirmed_at(st.last_confirmed_at)}",
                    severity="warning",
                    primary_cta_label="Abrir proteção",
                    primary_cta_action="open_module",
                    primary_cta_target=mod_id,
                )
            if st.state == ModuleState.DEGRADADO:
                cta = "Configurar cópia" if mod_id == "recovery" and st.needs_setup else "Ver detalhes"
                return HomeVerdict(
                    headline=f"{st.display_name} precisa de atenção",
                    evidence_text=st.degraded_reason or st.evidence,
                    severity="warning",
                    primary_cta_label=cta,
                    primary_cta_action="open_module",
                    primary_cta_target=mod_id,
                )

        # 5. Para declarar 'Suas proteções ativas estão em dia', exigir ao menos 1 ativo sem pendências
        active = [st for st in statuses.values() if st.state == ModuleState.ATIVO]
        if active:
            newest_ts = max(
                (st.last_confirmed_at for st in active if st.last_confirmed_at),
                default=now_iso(),
            )
            return HomeVerdict(
                headline="Suas proteções ativas estão em dia",
                evidence_text=f"{len(active)} proteção(ões) ativa(s) · {format_confirmed_at(newest_ts)}",
                severity="ok",
                primary_cta_label=None,
                primary_cta_action=None,
            )

        return HomeVerdict(
            headline="Nenhuma proteção ativa no momento",
            evidence_text="Ative um módulo em Proteções para iniciar a cobertura.",
            severity="setup",
            primary_cta_label="Escolher módulos",
            primary_cta_action="open_protections",
        )

    def home_cards(self, statuses: dict[str, ModuleStatus] | None = None) -> list[dict[str, str]]:
        """Define os três cartões da página inicial preservando posições e regra de substituição."""
        statuses = statuses or self.all_statuses()
        net_status = statuses.get("network")
        iso_status = statuses.get("isolation")

        third_card = {
            "card_id": "network",
            "title": "Minha rede",
            "subtitle": "Ver dispositivos observados na rede local",
            "action": "open_module:network",
            "a11y_name": "Minha rede. Abrir dispositivos observados na rede Wi-Fi local.",
        }
        # Se Minha rede estiver ausente e Navegador isolado disponível, substitui uma única vez
        if (
            net_status is not None
            and net_status.state == ModuleState.AUSENTE
            and iso_status is not None
            and iso_status.state != ModuleState.AUSENTE
        ):
            third_card = {
                "card_id": "isolated_browser",
                "title": "Navegador isolado",
                "subtitle": "Abrir sessão isolada temporária com bubblewrap",
                "action": "open_module:isolation",
                "a11y_name": "Navegador isolado. Abrir detalhes do navegador isolado.",
            }

        return [
            {
                "card_id": "scan",
                "title": "Verificar",
                "subtitle": "Iniciar verificação rápida ou soltar arquivos aqui",
                "action": "quick_scan",
                "a11y_name": "Verificar. Iniciar verificação rápida ou verificar arquivos soltos no cartão.",
            },
            {
                "card_id": "restore",
                "title": "Restaurar arquivos",
                "subtitle": "Abrir versões protegidas e escolher destino",
                "action": "open_recovery_files",
                "a11y_name": "Restaurar arquivos. Abrir versões disponíveis e destinos em Recuperação.",
            },
            third_card,
        ]

    # --- Fluxo de primeiro uso e ações sobre aplicativo pausado ---

    def complete_first_run(
        self,
        *,
        pause_policy: str | None = None,
        enable_antimalware: bool = False,
        enable_firewall: bool = False,
        deferred: bool = False,
    ) -> SuiteConfig:
        """Aplica escolhas iniciais; adiar preserva alertas sem pré-selecionar pausa."""
        cfg = self.config_store.load()
        if not deferred:
            cfg.first_run_completed = True
            if pause_policy in {"alert_only", "auto_pause"}:
                cfg.pause_policy = pause_policy
        else:
            # Adiar mantém apenas alertas (sem habilitar pausa automática)
            if cfg.pause_policy == "unset":
                cfg.pause_policy = "alert_only"
            cfg.first_run_completed = True
        self.config_store.save(cfg)

        if enable_antimalware and self.antimalware.query_status().state != ModuleState.AUSENTE:
            self.enable_module("antimalware")
        if enable_firewall and self._query_module("firewall").state != ModuleState.AUSENTE:
            self.enable_module("firewall", apply_essential_rules=True)
        self.invalidate_cache()
        return cfg

    def apply_paused_app_decision(
        self,
        pending_id: str,
        action: str,
        *,
        service_confirmed: bool = True,
    ) -> PendingDecision | None:
        """Executa decisão em aplicativo pausado atualizando estado só após confirmação."""
        item = self.pending_store.get(pending_id)
        if item is None:
            return None
        if action == "keep_paused":
            # Fechar ou manter pausado preserva a pausa e a pendência aberta no sino
            return item
        if action == "resume":
            if not service_confirmed:
                raise RuntimeError("Serviço não confirmou a retomada do processo.")
            resolved = self.pending_store.resolve(pending_id, resolution="resumed")
            self.history_store.record(
                module_id="recovery",
                action="Aplicativo retomado",
                reason="Usuário autorizou a retomada do aplicativo pausado.",
                confirmation_state="confirmed",
                actor="user",
                app_name=item.app_name,
                evidence=item.evidence,
            )
            return resolved
        if action == "terminate":
            if not service_confirmed:
                raise RuntimeError("Serviço não confirmou o encerramento do processo.")
            resolved = self.pending_store.resolve(pending_id, resolution="terminated")
            self.history_store.record(
                module_id="recovery",
                action=f"Aplicativo {item.app_name} encerrado",
                reason="Encerramento confirmado pelo usuário após aviso de perda de trabalho não salvo.",
                confirmation_state="confirmed",
                actor="user",
                app_name=item.app_name,
                evidence=item.evidence,
            )
            return resolved
        raise ValueError(f"Ação desconhecida para aplicativo pausado: {action}")

    # --- Pausa de proteção, autostart, recomendações e saúde global ---

    def pause_protection(self, *, mode: str, minutes: int | None = None) -> SuiteConfig:
        """Pausa a proteção por duração definida, até reiniciar ou indefinidamente."""
        if mode not in VALID_PAUSE_MODES or mode == "none":
            raise ValueError(f"Modo de pausa inválido: {mode}")
        until_iso: str | None = None
        if mode == "timed":
            mins = int(minutes or 15)
            if mins <= 0:
                raise ValueError("Duração da pausa deve ser positiva.")
            until_iso = (datetime.now().astimezone() + timedelta(minutes=mins)).isoformat(timespec="seconds")
        cfg = self.config_store.update(
            protection_paused=True,
            protection_pause_mode=mode,
            protection_paused_until=until_iso,
        )
        self.history_store.record(
            module_id="suite",
            action="Proteção pausada",
            reason=f"Modo: {mode}" + (f" ({minutes} min)" if mode == "timed" else ""),
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
            revert_action="resume_protection",
        )
        self.log_event(
            "WARNING",
            "protection",
            f"Proteção pausada ({mode})",
            details=f"{minutes} min" if mode == "timed" else "",
            source="controller",
        )
        return cfg

    def resume_protection(self) -> SuiteConfig:
        """Retoma a proteção após pausa temporária ou manual."""
        cfg = self.config_store.update(
            protection_paused=False,
            protection_pause_mode="none",
            protection_paused_until=None,
        )
        self.history_store.record(
            module_id="suite",
            action="Proteção retomada",
            reason="Monitoramento e varreduras periódicas reativados.",
            confirmation_state="confirmed",
            actor="suite",
        )
        self.log_event("INFO", "protection", "Proteção retomada", source="controller")
        return cfg

    def check_pause_expiry(self) -> bool:
        """Retoma automaticamente caso a pausa temporizada tenha expirado."""
        cfg = self.config_store.load()
        if cfg.protection_paused and not cfg.is_protection_paused_now():
            self.resume_protection()
            return True
        return False

    def clear_until_restart_pause_on_startup(self) -> None:
        """Limpa pausa configurada até a reinicialização do aplicativo ao abrir."""
        cfg = self.config_store.load()
        if cfg.protection_paused and cfg.protection_pause_mode == "until_restart":
            self.resume_protection()

    def sync_autostart(self, *, config_home: Path | None = None) -> Path:
        """Sincroniza arquivo .desktop de autostart com SuiteConfig.autostart_enabled."""
        cfg = self.config_store.load()
        return sync_autostart_file(cfg.autostart_enabled, config_home=config_home)

    def ensure_default_automation(self) -> None:
        """Mantém o agendamento periódico rápido alinhado às configurações."""
        cfg = self.config_store.load()
        schedules = self.antimalware.list_schedules()
        existing = next((s for s in schedules if s.get("schedule_id") == "auto_quick"), None)
        if cfg.auto_quick_scan_enabled:
            if (
                existing is None
                or existing.get("scope") != "quick"
                or existing.get("frequency") != cfg.auto_quick_scan_interval
                or not existing.get("active", True)
            ):
                self.antimalware.save_schedule(
                    schedule_id="auto_quick",
                    scope="quick",
                    frequency=cfg.auto_quick_scan_interval,
                    active=True,
                )
        elif existing is not None:
            self.antimalware.remove_schedule("auto_quick")

    def is_auto_scan_due(self, *, now: datetime | None = None) -> bool:
        """Verifica se uma varredura rápida automática periódica já venceu o intervalo."""
        cfg = self.config_store.load()
        if not cfg.auto_quick_scan_enabled or cfg.is_protection_paused_now() or cfg.game_mode:
            return False
        if self.antimalware.runner.which("clamscan") is None:
            return False
        state_data = self.antimalware._load_state()
        last_scan = state_data.get("last_scan") or {}
        finished_raw = last_scan.get("finished_at")
        if not finished_raw:
            return True
        try:
            finished_dt = datetime.fromisoformat(str(finished_raw))
        except ValueError:
            return True
        ref = now or datetime.now(tz=finished_dt.tzinfo)
        if ref.tzinfo is None and finished_dt.tzinfo is not None:
            ref = ref.replace(tzinfo=finished_dt.tzinfo)
        interval_hours = {"6h": 6.0, "12h": 12.0, "daily": 24.0, "weekly": 168.0}[
            cfg.auto_quick_scan_interval
        ]
        return (ref - finished_dt).total_seconds() >= interval_hours * 3600.0

    def ignore_recommendation(self, rec_id: str) -> SuiteConfig:
        """Oculta recomendação ignorável específica na página inicial."""
        cfg = self.config_store.load()
        cur = list(cfg.ignored_recommendations)
        if rec_id not in cur:
            cur.append(rec_id)
            return self.config_store.update(ignored_recommendations=cur)
        return cfg

    def restore_ignored_recommendations(self) -> SuiteConfig:
        """Restaura todas as recomendações previamente ignoradas."""
        return self.config_store.update(ignored_recommendations=[])

    def get_protection_recommendations(
        self,
        *,
        statuses: dict[str, ModuleStatus] | None = None,
        cfg: SuiteConfig | None = None,
        open_pending: list[PendingDecision] | None = None,
    ) -> list[dict[str, Any]]:
        """Retorna lista estruturada e acionável para melhorar ou corrigir a proteção."""
        statuses = statuses or self.all_statuses(use_cache=True)
        cfg = cfg or self.config_store.load()
        open_pending = open_pending if open_pending is not None else self.pending_store.list_open()
        ignored = set(cfg.ignored_recommendations)
        recs: list[dict[str, Any]] = []

        if cfg.is_protection_paused_now():
            recs.append(
                {
                    "rec_id": "protection_paused",
                    "severity": "critical",
                    "ignorable": False,
                    "action": "resume_protection",
                    "target": cfg.protection_pause_mode,
                    "until": cfg.protection_paused_until,
                    "auto_apply": True,
                }
            )

        paused_apps = [p for p in open_pending if p.kind == "paused_app"]
        if paused_apps:
            recs.append(
                {
                    "rec_id": "paused_app",
                    "severity": "critical",
                    "ignorable": False,
                    "action": "review_pending",
                    "target": paused_apps[0].pending_id,
                    "app_name": paused_apps[0].app_name or "",
                    "auto_apply": False,
                }
            )
        elif open_pending:
            recs.append(
                {
                    "rec_id": "pending_alerts",
                    "severity": "critical",
                    "ignorable": False,
                    "action": "open_notifications",
                    "count": len(open_pending),
                    "auto_apply": False,
                }
            )

        am_st = statuses.get("antimalware")
        if am_st is not None and am_st.state != ModuleState.AUSENTE:
            sig = am_st.details.get("signatures", {})
            if not sig.get("available") or sig.get("stale"):
                recs.append(
                    {
                        "rec_id": "db_outdated",
                        "severity": "warning",
                        "ignorable": True,
                        "action": "update_db",
                        "stale": bool(sig.get("available")),
                        "auto_apply": True,
                    }
                )
            if am_st.state == ModuleState.VERIFICACAO_INCOMPLETA:
                recs.append(
                    {
                        "rec_id": "scan_incomplete",
                        "severity": "warning",
                        "ignorable": True,
                        "action": "quick_scan",
                        "auto_apply": True,
                    }
                )
            if am_st.state == ModuleState.DESATIVADO:
                recs.append(
                    {
                        "rec_id": "enable_antimalware",
                        "severity": "warning",
                        "ignorable": True,
                        "action": "auto_enable_antimalware",
                        "auto_apply": True,
                    }
                )

        fw_st = statuses.get("firewall")
        if fw_st is not None and fw_st.state != ModuleState.AUSENTE:
            if fw_st.state == ModuleState.DESATIVADO:
                recs.append(
                    {
                        "rec_id": "enable_firewall",
                        "severity": "warning",
                        "ignorable": True,
                        "action": "auto_enable_firewall",
                        "auto_apply": True,
                    }
                )
            elif fw_st.state == ModuleState.ATIVO:
                allowed_set = set(fw_st.details.get("allowed_presets") or [])
                for preset in fw_st.details.get("app_presets") or []:
                    if (
                        preset.get("detected")
                        and preset.get("auto_allow_on_enable")
                        and preset.get("preset_id") not in allowed_set
                    ):
                        pid = str(preset["preset_id"])
                        recs.append(
                            {
                                "rec_id": f"allow_fw_app:{pid}",
                                "severity": "info",
                                "ignorable": True,
                                "action": f"allow_fw_preset:{pid}",
                                "preset_id": pid,
                                "app_name": str(preset.get("name") or pid),
                                "auto_apply": True,
                            }
                        )

        br_st = statuses.get("browsing")
        if br_st is not None and br_st.state == ModuleState.DESATIVADO:
            recs.append(
                {
                    "rec_id": "enable_browsing",
                    "severity": "info",
                    "ignorable": True,
                    "action": "auto_enable_browsing",
                    "auto_apply": True,
                }
            )

        if am_st is not None and am_st.state != ModuleState.AUSENTE:
            if not cfg.auto_quick_scan_enabled:
                recs.append(
                    {
                        "rec_id": "enable_auto_scan",
                        "severity": "info",
                        "ignorable": True,
                        "action": "enable_auto_scan",
                        "auto_apply": True,
                    }
                )
            last_scan = am_st.details.get("last_scan") or {}
            scan_old = not last_scan.get("finished_at")
            if last_scan.get("finished_at"):
                try:
                    dt = datetime.fromisoformat(str(last_scan["finished_at"]))
                    age = (datetime.now(tz=dt.tzinfo) - dt).total_seconds()
                    scan_old = age > 7 * 86400
                except ValueError:
                    scan_old = True
            if scan_old:
                recs.append(
                    {
                        "rec_id": "run_quick_scan",
                        "severity": "info",
                        "ignorable": True,
                        "action": "quick_scan",
                        "auto_apply": True,
                    }
                )

        rec_st = statuses.get("recovery")
        if rec_st is not None and rec_st.state != ModuleState.AUSENTE and rec_st.needs_setup:
            recs.append(
                {
                    "rec_id": "setup_recovery",
                    "severity": "info",
                    "ignorable": True,
                    "action": "open_recovery",
                    "auto_apply": False,
                }
            )

        return [r for r in recs if not (r["ignorable"] and r["rec_id"] in ignored)]

    def _auto_allow_detected_lan_apps(self) -> list[str]:
        """Libera aplicativos LAN detectados marcados com auto_allow_on_enable ao ativar o firewall."""
        allowed_names: list[str] = []
        presets = detect_app_presets(self.runner, extra_app_dirs=self._extra_fw_app_dirs)
        for preset in presets:
            if preset.get("detected") and preset.get("auto_allow_on_enable"):
                self.allow_firewall_preset(str(preset["preset_id"]))
                allowed_names.append(str(preset["name"]))
        return allowed_names

    def apply_recommendation(
        self,
        rec: dict[str, Any],
        *,
        run_scan_sync: bool = False,
    ) -> dict[str, Any]:
        """Aplica automaticamente uma recomendação acionável pelo app."""
        rid = str(rec.get("rec_id", ""))
        action = str(rec.get("action", ""))
        if action == "resume_protection":
            self.resume_protection()
            self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True}
        if action == "update_db":
            res = self.update_antimalware_signatures()
            if not res.get("ok"):
                err = str(res.get("stderr") or res.get("stdout") or "freshclam failed").strip()
                raise RuntimeError(err)
            self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True}
        if action in {"auto_enable_antimalware", "enable_module:antimalware"}:
            self.enable_module("antimalware")
            self.ensure_default_automation()
            self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True}
        if action in {"auto_enable_firewall", "enable_module:firewall"}:
            self.enable_module("firewall", apply_essential_rules=True)
            allowed_apps = self._auto_allow_detected_lan_apps()
            self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True, "allowed_apps": allowed_apps}
        if action == "auto_enable_browsing":
            self.enable_module("browsing")
            self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True}
        if action.startswith("allow_fw_preset:"):
            pid = action.split(":", 1)[1]
            self.allow_firewall_preset(pid)
            self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True, "preset_id": pid}
        if action == "enable_auto_scan":
            self.config_store.update(auto_quick_scan_enabled=True)
            self.ensure_default_automation()
            self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True}
        if action == "quick_scan":
            if run_scan_sync:
                self.antimalware.run_scan(scope="quick")
                self.invalidate_cache()
            return {"ok": True, "rec_id": rid, "auto_applied": True, "trigger_scan": "quick"}
        return {
            "ok": False,
            "rec_id": rid,
            "auto_applied": False,
            "requires_manual": True,
            "action": action,
            "target": rec.get("target"),
        }

    def apply_all_recommendations(
        self,
        *,
        statuses: dict[str, ModuleStatus] | None = None,
        recs: list[dict[str, Any]] | None = None,
        on_progress: Callable[[int, int, str], None] | None = None,
    ) -> dict[str, Any]:
        """Aplica em ordem segura todas as recomendações automáticas pendentes."""
        target_recs = list(recs) if recs is not None else self.get_protection_recommendations(statuses=statuses)
        ordered = [r for r in target_recs if r.get("action") != "quick_scan"] + [
            r for r in target_recs if r.get("action") == "quick_scan"
        ]
        auto_items = [r for r in ordered if r.get("auto_apply", False)]
        total_auto = len(auto_items)
        auto_done = 0
        applied: list[str] = []
        failed: list[dict[str, str]] = []
        skipped_manual: list[str] = []
        trigger_scan: str | None = None

        for rec in ordered:
            rid = str(rec.get("rec_id", ""))
            if not rec.get("auto_apply", False):
                skipped_manual.append(rid)
                continue
            try:
                res = self.apply_recommendation(rec, run_scan_sync=False)
                if res.get("auto_applied"):
                    applied.append(rid)
                    if res.get("trigger_scan") and trigger_scan is None:
                        trigger_scan = str(res["trigger_scan"])
                else:
                    skipped_manual.append(rid)
            except Exception as exc:  # noqa: BLE001
                failed.append({"rec_id": rid, "error": str(exc)})
                self.log_event(
                    "ERROR",
                    "recommendations",
                    f"Falha ao aplicar recomendação {rid}",
                    details=str(exc),
                    source="controller",
                )
            auto_done += 1
            if on_progress is not None:
                try:
                    on_progress(auto_done, total_auto, rid)
                except Exception:
                    pass

        if applied:
            self.history_store.record(
                module_id="suite",
                action="Recomendações aplicadas automaticamente",
                reason=f"Aplicadas: {', '.join(applied)}.",
                confirmation_state="confirmed" if not failed else "incomplete",
                actor="user",
            )
            self.log_event(
                "INFO" if not failed else "WARNING",
                "recommendations",
                f"Recomendações aplicadas: {len(applied)} (falhas: {len(failed)})",
                details=", ".join(applied),
                source="controller",
            )
        self.invalidate_cache()
        return {
            "ok": len(failed) == 0,
            "applied": applied,
            "failed": failed,
            "skipped_manual": skipped_manual,
            "trigger_scan": trigger_scan,
        }

    def get_overall_health(
        self,
        *,
        statuses: dict[str, ModuleStatus] | None = None,
        cfg: SuiteConfig | None = None,
        open_pending: list[PendingDecision] | None = None,
    ) -> str:
        """Retorna estado consolidado para animação e bandeja ('ok' | 'alert' | 'paused')."""
        cfg = cfg or self.config_store.load()
        if cfg.is_protection_paused_now():
            return "paused"
        statuses = statuses or self.all_statuses(use_cache=True)
        open_pending = open_pending if open_pending is not None else self.pending_store.list_open()
        if open_pending:
            return "alert"
        for st in statuses.values():
            if st.state in (
                ModuleState.DEGRADADO,
                ModuleState.VERIFICACAO_INCOMPLETA,
                ModuleState.INDISPONIVEL,
            ):
                return "alert"
        recs = self.get_protection_recommendations(statuses=statuses, cfg=cfg, open_pending=open_pending)
        if any(r["severity"] in ("critical", "warning") for r in recs):
            return "alert"
        return "ok"
