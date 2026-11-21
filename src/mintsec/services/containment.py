"""Serviço de contenção automática por canários, cgroup exclusivo e reconstrução H6."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from mintsec.config import ConfigStore
from mintsec.contracts import PendingDecision
from mintsec.formatting import now_iso
from mintsec.pending import PendingStore


@dataclass(frozen=True)
class ContainmentEvaluation:
    """Decisão auditável sobre pausa automática ou alerta apenas."""

    should_pause: bool
    reason: str
    alert_only_fallback: bool
    evidence: str


class ContainmentService:
    """Aplica política rigorosa de canário + corroboração + cgroup exclusivo (Seção 3 e H6)."""

    def __init__(
        self,
        *,
        config_store: ConfigStore,
        pending_store: PendingStore,
    ) -> None:
        self.config_store = config_store
        self.pending_store = pending_store

    def evaluate_event(
        self,
        *,
        app_name: str,
        canary_modified: bool,
        corroborating_activity_same_app: bool,
        exclusive_cgroup_verified: bool,
        scope_kind: str,  # 'suite_transient' | 'exclusive_user_unit' | 'verified_exec_scope' | 'shared'
        thread_count: int,
        child_count: int,
        affected_paths: list[str],
        fan_q_overflow: bool = False,
        incident_id: str | None = None,
    ) -> tuple[ContainmentEvaluation, PendingDecision]:
        """Avalia se todas as pré-condições para pausa automática foram satisfeitas."""
        cfg = self.config_store.load()
        scope_eligible = scope_kind in {
            "suite_transient",
            "exclusive_user_unit",
            "verified_exec_scope",
        }
        snapshot_sufficient = not (
            thread_count <= 1 and child_count == 0 and scope_kind != "suite_transient"
        )
        can_pause = (
            cfg.pause_policy == "auto_pause"
            and canary_modified
            and corroborating_activity_same_app
            and exclusive_cgroup_verified
            and scope_eligible
            and snapshot_sufficient
        )

        if can_pause:
            reason = (
                "Canário alterado + atividade corroborante do mesmo aplicativo + cgroup exclusivo comprovado."
            )
            ev = ContainmentEvaluation(
                should_pause=True,
                reason=reason,
                alert_only_fallback=False,
                evidence=f"Escopo {scope_kind} (threads={thread_count}, filhos={child_count})",
            )
            pending = self.pending_store.create(
                kind="paused_app",
                module_id="recovery",
                app_name=app_name,
                title="Um aplicativo está pausado",
                summary=reason,
                evidence=ev.evidence,
                fan_q_overflow=fan_q_overflow,
                affected_paths=affected_paths,
                actions=["keep_paused", "resume", "terminate", "restore"],
                incident_id=incident_id,
                metadata={"scope_kind": scope_kind, "frozen_confirmed": True},
            )
            return ev, pending

        reasons: list[str] = []
        if cfg.pause_policy != "auto_pause":
            reasons.append(f"política atual={cfg.pause_policy}")
        if not canary_modified:
            reasons.append("sem alteração de canário")
        if not corroborating_activity_same_app:
            reasons.append("sem atividade corroborante atribuída ao mesmo aplicativo")
        if not exclusive_cgroup_verified or not scope_eligible:
            reasons.append(f"escopo incerto ou compartilhado ({scope_kind})")
        if not snapshot_sufficient:
            reasons.append("fotografia isolada de 1 thread e 0 filhos é insuficiente")

        reason_str = "Alerta sem pausa automática (" + "; ".join(reasons) + ")."
        ev = ContainmentEvaluation(
            should_pause=False,
            reason=reason_str,
            alert_only_fallback=True,
            evidence=f"Escopo {scope_kind} (threads={thread_count}, filhos={child_count})",
        )
        pending = self.pending_store.create(
            kind="canary_alert",
            module_id="recovery",
            app_name=app_name,
            title=f"Alerta de alteração em {app_name}",
            summary=reason_str,
            evidence=ev.evidence,
            fan_q_overflow=fan_q_overflow,
            affected_paths=affected_paths,
            actions=["review", "open_recovery"],
            incident_id=incident_id,
        )
        return ev, pending

    def reconstruct_after_overflow(
        self,
        *,
        interval_start_epoch: float,
        search_roots: list[Path],
        btrfs_diff_paths: list[str] | None = None,
    ) -> dict[str, Any]:
        """Reconstrói arquivos modificados via ctime + diferenças Btrfs marcando como incompleta."""
        found_ctime: list[str] = []
        for root in search_roots:
            if not root.exists():
                continue
            for dirpath, _, filenames in os.walk(root):
                for fname in filenames:
                    fpath = Path(dirpath) / fname
                    try:
                        st = fpath.stat()
                        if st.st_ctime >= interval_start_epoch:
                            found_ctime.append(str(fpath))
                    except OSError:
                        continue

        combined = sorted(set(found_ctime) | set(btrfs_diff_paths or []))
        return {
            "fan_q_overflow": True,
            "possibly_incomplete": True,
            "warning": "A lista pode estar incompleta devido a FAN_Q_OVERFLOW; use a cópia inteira se necessário.",
            "ctime_candidates": found_ctime,
            "btrfs_diff_candidates": list(btrfs_diff_paths or []),
            "reconstructed_paths": combined,
            "reconstructed_at": now_iso(),
        }

    @staticmethod
    def evaluate_beta_false_positive_gate(
        *,
        false_pauses: int,
        install_weeks: int,
        canary_incidents: int,
    ) -> dict[str, Any]:
        """Critério H6: revisar pausa automática se > 1/1.000 inst.-semana ou > 0,5% dos incidentes."""
        per_1000 = (false_pauses / max(1, install_weeks)) * 1000.0
        pct_incidents = (false_pauses / max(1, canary_incidents)) * 100.0 if canary_incidents else 0.0
        exceeds = per_1000 > 1.0 or pct_incidents > 0.5
        return {
            "false_pauses": false_pauses,
            "per_1000_install_weeks": round(per_1000, 4),
            "percent_canary_incidents": round(pct_incidents, 4),
            "review_required": exceeds,
        }
