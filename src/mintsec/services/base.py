"""Contrato base compartilhado pelos serviços modulares da suíte."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import ModuleManifest, ModuleState, ModuleStatus
from mintsec.formatting import now_iso
from mintsec.history import HistoryStore
from mintsec.packaging import PackageInfo, PackageInspector
from mintsec.pending import PendingStore
from mintsec.runner import CommandRunner, SubprocessRunner


class ModuleService(ABC):
    """Classe base para módulos com contrato versionado e reversibilidade."""

    def __init__(
        self,
        *,
        manifest: ModuleManifest,
        config_store: ConfigStore,
        pending_store: PendingStore,
        history_store: HistoryStore,
        package_inspector: PackageInspector | None = None,
        runner: CommandRunner | None = None,
        authorizer: CallerAuthorizer | None = None,
    ) -> None:
        self.manifest = manifest
        self.config_store = config_store
        self.pending_store = pending_store
        self.history_store = history_store
        self.runner = runner or SubprocessRunner()
        self.package_inspector = package_inspector or PackageInspector(self.runner)
        self.authorizer = authorizer or CallerAuthorizer()

    def inspect_primary_packages(self) -> tuple[bool, str | None, str, dict[str, PackageInfo]]:
        """Inspeciona os pacotes declarados no manifesto e retorna versão/origem reais."""
        infos: dict[str, PackageInfo] = {}
        bins = list(self.manifest.engine.get("binaries", []))
        for pkg in self.manifest.packages:
            infos[pkg] = self.package_inspector.inspect_package(pkg, binaries=bins)
        installed_infos = [info for info in infos.values() if info.installed]
        if not installed_infos:
            # Se algum binário existir no PATH mesmo sem dpkg registrado
            any_bin = any(info.binary_present for info in infos.values())
            if not any_bin:
                return False, None, "Não instalado", infos
            return True, "local", "Binário presente no sistema", infos
        primary = installed_infos[0]
        all_installed = len(installed_infos) == len(self.manifest.packages)
        return all_installed or primary.installed, primary.version, primary.origin, infos

    def record_event(
        self,
        *,
        action: str,
        reason: str,
        confirmation_state: str,
        actor: str = "suite",
        evidence: str = "",
        app_name: str = "",
        reversible: bool = False,
        revert_action: str | None = None,
        details: dict[str, Any] | None = None,
    ) -> None:
        """Registra evento no histórico opcional sem falhar caso o histórico esteja desligado."""
        self.history_store.record(
            module_id=self.manifest.module_id,
            action=action,
            reason=reason,
            confirmation_state=confirmation_state,
            actor=actor,
            evidence=evidence,
            app_name=app_name,
            reversible=reversible,
            revert_action=revert_action,
            details=details,
            timestamp=now_iso(),
        )

    def _module_enabled_flag(self, default: bool = False) -> bool:
        cfg = self.config_store.load()
        return bool(cfg.enabled_modules.get(self.manifest.module_id, default))

    def _set_module_enabled_flag(self, enabled: bool) -> None:
        cfg = self.config_store.load()
        cfg.enabled_modules[self.manifest.module_id] = enabled
        self.config_store.save(cfg)

    def build_status(
        self,
        *,
        state: ModuleState,
        installed_version: str | None,
        package_origin: str,
        mode_summary: str,
        evidence: str,
        last_confirmed_at: str | None = None,
        degraded_reason: str | None = None,
        needs_setup: bool = False,
        details: dict[str, Any] | None = None,
    ) -> ModuleStatus:
        """Constrói ModuleStatus padronizado a partir do manifesto."""
        return ModuleStatus(
            module_id=self.manifest.module_id,
            display_name=self.manifest.display_name,
            state=state,
            installed_version=installed_version,
            package_origin=package_origin,
            mode_summary=mode_summary,
            last_confirmed_at=last_confirmed_at,
            evidence=evidence,
            degraded_reason=degraded_reason,
            needs_setup=needs_setup,
            phase=self.manifest.phase,
            experimental=self.manifest.experimental,
            details=details or {},
        )

    @abstractmethod
    def query_status(self) -> ModuleStatus:
        """Consulta o estado real e atual do módulo."""

    @abstractmethod
    def configure(self, **options: Any) -> ModuleStatus:
        """Aplica configurações específicas do módulo."""

    @abstractmethod
    def enable(self, **options: Any) -> ModuleStatus:
        """Ativa o módulo ou suas tarefas agendadas."""

    @abstractmethod
    def disable(self, *, revert_suite_changes: bool = False) -> ModuleStatus:
        """Desativa o módulo preservando cópias, quarentena e regras externas."""
