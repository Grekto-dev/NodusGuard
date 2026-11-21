"""Armazenamento leve de pendências abertas independente do histórico SQLite."""

from __future__ import annotations

import threading
import uuid
from pathlib import Path
from typing import Any

from mintsec.contracts import PendingDecision, atomic_write_json, read_json_safe, xdg_dir
from mintsec.formatting import now_iso


class PendingStore:
    """Gerencia pendências abertas em JSON atômico para o painel e o agente."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (xdg_dir("XDG_STATE_HOME", ".local/state") / "pending.json")
        self._lock = threading.RLock()
        self._cached_sig: tuple[int, int] | None = None
        self._cached_items: list[dict[str, Any]] | None = None

    def _file_sig(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _load_all(self) -> list[PendingDecision]:
        with self._lock:
            sig = self._file_sig()
            if sig is None:
                self._cached_sig = None
                self._cached_items = None
                return []
            if self._cached_sig == sig and self._cached_items is not None:
                return [PendingDecision.from_dict(item) for item in self._cached_items]
        raw = read_json_safe(self.path, default={"version": 1, "items": []})
        raw_items = list(raw.get("items", []))
        decisions = [PendingDecision.from_dict(item) for item in raw_items]
        with self._lock:
            self._cached_sig = self._file_sig()
            self._cached_items = [d.to_dict() for d in decisions] if self._cached_sig is not None else None
        return decisions

    def _save_all(self, items: list[PendingDecision]) -> None:
        serialized = [item.to_dict() for item in items]
        payload = {
            "version": 1,
            "updated_at": now_iso(),
            "items": serialized,
        }
        atomic_write_json(self.path, payload, mode=0o600)
        with self._lock:
            self._cached_sig = self._file_sig()
            self._cached_items = serialized if self._cached_sig is not None else None

    def add(self, decision: PendingDecision, group_repeated: bool = True) -> PendingDecision:
        """Adiciona uma pendência ou agrupa repetição aberta do mesmo aplicativo."""
        with self._lock:
            items = self._load_all()
            if group_repeated and decision.app_name:
                for existing in items:
                    if (
                        existing.status == "open"
                        and existing.kind == decision.kind
                        and existing.module_id == decision.module_id
                        and existing.app_name == decision.app_name
                    ):
                        existing.occurrences += 1
                        existing.evidence = decision.evidence
                        existing.summary = decision.summary
                        existing.fan_q_overflow = existing.fan_q_overflow or decision.fan_q_overflow
                        for path in decision.affected_paths:
                            if path not in existing.affected_paths:
                                existing.affected_paths.append(path)
                        existing.metadata.update(decision.metadata)
                        self._save_all(items)
                        return existing
            items.append(decision)
            self._save_all(items)
            return decision

    def create(
        self,
        *,
        kind: str,
        module_id: str,
        title: str,
        summary: str,
        evidence: str,
        app_name: str = "",
        fan_q_overflow: bool = False,
        affected_paths: list[str] | None = None,
        actions: list[str] | None = None,
        incident_id: str | None = None,
        metadata: dict | None = None,
        group_repeated: bool = True,
    ) -> PendingDecision:
        """Cria e persiste uma nova decisão pendente."""
        decision = PendingDecision(
            pending_id=str(uuid.uuid4()),
            kind=kind,
            module_id=module_id,
            app_name=app_name,
            title=title,
            summary=summary,
            evidence=evidence,
            created_at=now_iso(),
            status="open",
            fan_q_overflow=fan_q_overflow,
            affected_paths=list(affected_paths or []),
            actions=list(actions or []),
            incident_id=incident_id,
            metadata=dict(metadata or {}),
        )
        return self.add(decision, group_repeated=group_repeated)

    def list_open(self) -> list[PendingDecision]:
        """Retorna todas as pendências ainda em aberto."""
        return [item for item in self._load_all() if item.status == "open"]

    def list_all(self) -> list[PendingDecision]:
        """Retorna todas as pendências registradas."""
        return self._load_all()

    def get(self, pending_id: str) -> PendingDecision | None:
        """Busca uma pendência específica pelo identificador."""
        for item in self._load_all():
            if item.pending_id == pending_id:
                return item
        return None

    def update(self, updated: PendingDecision) -> None:
        """Atualiza uma pendência existente preservando o restante."""
        with self._lock:
            items = self._load_all()
            for idx, item in enumerate(items):
                if item.pending_id == updated.pending_id:
                    items[idx] = updated
                    self._save_all(items)
                    return
            raise KeyError(f"Pendência não encontrada: {updated.pending_id}")

    def resolve(self, pending_id: str, resolution: str = "resolved") -> PendingDecision | None:
        """Marca uma pendência como resolvida ou dispensada."""
        with self._lock:
            items = self._load_all()
            for item in items:
                if item.pending_id == pending_id:
                    item.status = resolution
                    self._save_all(items)
                    return item
            return None

    def count_open(self) -> int:
        """Conta pendências ainda sem decisão final."""
        return len(self.list_open())

    def group_by_app(self) -> dict[str, list[PendingDecision]]:
        """Agrupa pendências abertas por aplicativo para exibição na tela Atividade."""
        grouped: dict[str, list[PendingDecision]] = {}
        for item in self.list_open():
            key = item.app_name or item.module_id
            grouped.setdefault(key, []).append(item)
        return grouped
