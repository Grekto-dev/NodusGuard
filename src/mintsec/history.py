"""Histórico local opcional em SQLite WAL, executando sem capacidades especiais."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from mintsec.contracts import EventRecord, xdg_dir
from mintsec.formatting import now_iso


class HistoryStore:
    """Persistência opcional de eventos em SQLite com journal_mode=WAL."""

    def __init__(self, path: Path | None = None, enabled: bool = True) -> None:
        self.path = path or (xdg_dir("XDG_DATA_HOME", ".local/share") / "history.db")
        self.enabled = enabled
        self._schema_initialized = False
        self._lock = threading.RLock()
        self._query_cache_sig: tuple[int, int, int, int] | None = None
        self._query_cache: dict[tuple[Any, ...], tuple[EventRecord, ...]] = {}
        if self.enabled:
            self._ensure_schema()

    def _db_sig(self) -> tuple[int, int, int, int] | None:
        try:
            db_st = self.path.stat()
        except OSError:
            return None
        wal_path = Path(f"{self.path}-wal")
        try:
            wal_st = wal_path.stat()
            wal_sig = (wal_st.st_mtime_ns, wal_st.st_size)
        except OSError:
            wal_sig = (0, 0)
        return (db_st.st_mtime_ns, db_st.st_size, wal_sig[0], wal_sig[1])

    def _invalidate_query_cache(self) -> None:
        with self._lock:
            self._query_cache_sig = None
            self._query_cache.clear()

    def set_enabled(self, enabled: bool) -> None:
        """Ativa ou desativa o histórico opcional sem afetar pendências."""
        self.enabled = enabled
        if self.enabled:
            self._ensure_schema()

    @contextmanager
    def _connect(self, *, configure_wal: bool = False, readonly: bool = False) -> Iterator[sqlite3.Connection]:
        if self.path.parent.is_symlink():
            raise PermissionError(f"Diretório de histórico não pode ser symlink: {self.path.parent}")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(str(self.path), timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            if configure_wal:
                conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
            conn.execute("PRAGMA foreign_keys=ON;")
            yield conn
            if not readonly:
                conn.commit()
        finally:
            conn.close()

    def _harden_db_permissions(self) -> None:
        for suffix in ("", "-wal", "-shm"):
            p = Path(f"{self.path}{suffix}")
            if p.exists() and not p.is_symlink():
                try:
                    os.chmod(p, 0o600)
                except OSError:
                    pass

    def _ensure_schema(self) -> None:
        if self._schema_initialized and self.path.exists():
            return
        with self._connect(configure_wal=True) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    event_id TEXT PRIMARY KEY,
                    module_id TEXT NOT NULL,
                    action TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    confirmation_state TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    evidence TEXT NOT NULL,
                    app_name TEXT NOT NULL,
                    reversible INTEGER NOT NULL DEFAULT 0,
                    revert_action TEXT,
                    details_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_module_ts ON events(module_id, timestamp DESC)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_events_app_ts ON events(app_name, timestamp DESC)"
            )
        self._harden_db_permissions()
        self._schema_initialized = True

    def journal_mode(self) -> str:
        """Consulta o modo de journal atual do banco SQLite."""
        if not self.path.exists():
            if not self.enabled:
                return "disabled"
            self._ensure_schema()
        with self._connect() as conn:
            row = conn.execute("PRAGMA journal_mode;").fetchone()
            return str(row[0]) if row else "unknown"

    def record(
        self,
        *,
        module_id: str,
        action: str,
        reason: str,
        confirmation_state: str,
        actor: str = "suite",
        evidence: str = "",
        app_name: str = "",
        reversible: bool = False,
        revert_action: str | None = None,
        details: dict | None = None,
        timestamp: str | None = None,
    ) -> EventRecord | None:
        """Registra um evento se o histórico opcional estiver habilitado."""
        if not self.enabled:
            return None
        self._ensure_schema()
        event = EventRecord(
            event_id=str(uuid.uuid4()),
            module_id=module_id,
            action=action,
            reason=reason,
            timestamp=timestamp or now_iso(),
            confirmation_state=confirmation_state,
            actor=actor,
            evidence=evidence,
            app_name=app_name,
            reversible=reversible,
            revert_action=revert_action,
            details=dict(details or {}),
        )
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO events (
                    event_id, module_id, action, reason, timestamp,
                    confirmation_state, actor, evidence, app_name,
                    reversible, revert_action, details_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.event_id,
                    event.module_id,
                    event.action,
                    event.reason,
                    event.timestamp,
                    event.confirmation_state,
                    event.actor,
                    event.evidence,
                    event.app_name,
                    1 if event.reversible else 0,
                    event.revert_action,
                    json.dumps(event.details, ensure_ascii=False),
                ),
            )
        self._invalidate_query_cache()
        return event

    def query(
        self,
        *,
        module_id: str | None = None,
        confirmation_state: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 200,
    ) -> list[EventRecord]:
        """Consulta eventos com filtros por módulo, resultado, período e cache leve por mtime."""
        if not self.path.exists():
            return []
        safe_limit = max(1, min(int(limit), 5000))
        cache_key = (module_id, confirmation_state, since, until, safe_limit)
        sig = self._db_sig()
        if sig is not None:
            with self._lock:
                if self._query_cache_sig == sig:
                    cached = self._query_cache.get(cache_key)
                    if cached is not None:
                        return [
                            EventRecord(
                                event_id=ev.event_id,
                                module_id=ev.module_id,
                                action=ev.action,
                                reason=ev.reason,
                                timestamp=ev.timestamp,
                                confirmation_state=ev.confirmation_state,
                                actor=ev.actor,
                                evidence=ev.evidence,
                                app_name=ev.app_name,
                                reversible=ev.reversible,
                                revert_action=ev.revert_action,
                                details=dict(ev.details),
                            )
                            for ev in cached
                        ]
                else:
                    self._query_cache_sig = sig
                    self._query_cache.clear()

        clauses: list[str] = []
        params: list[object] = []
        if module_id:
            clauses.append("module_id = ?")
            params.append(module_id)
        if confirmation_state:
            clauses.append("confirmation_state = ?")
            params.append(confirmation_state)
        if since:
            clauses.append("timestamp >= ?")
            params.append(since)
        if until:
            clauses.append("timestamp <= ?")
            params.append(until)
        where_sql = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        sql = f"SELECT * FROM events {where_sql} ORDER BY timestamp DESC LIMIT ?"
        params.append(safe_limit)
        with self._connect(readonly=True) as conn:
            rows = conn.execute(sql, params).fetchall()
        records = [
            EventRecord(
                event_id=row["event_id"],
                module_id=row["module_id"],
                action=row["action"],
                reason=row["reason"],
                timestamp=row["timestamp"],
                confirmation_state=row["confirmation_state"],
                actor=row["actor"],
                evidence=row["evidence"],
                app_name=row["app_name"],
                reversible=bool(row["reversible"]),
                revert_action=row["revert_action"],
                details=json.loads(row["details_json"] or "{}"),
            )
            for row in rows
        ]
        if sig is not None:
            with self._lock:
                if len(self._query_cache) >= 32:
                    self._query_cache.clear()
                self._query_cache_sig = sig
                self._query_cache[cache_key] = tuple(
                    EventRecord(
                        event_id=ev.event_id,
                        module_id=ev.module_id,
                        action=ev.action,
                        reason=ev.reason,
                        timestamp=ev.timestamp,
                        confirmation_state=ev.confirmation_state,
                        actor=ev.actor,
                        evidence=ev.evidence,
                        app_name=ev.app_name,
                        reversible=ev.reversible,
                        revert_action=ev.revert_action,
                        details=dict(ev.details),
                    )
                    for ev in records
                )
        return records

    def query_grouped(
        self,
        *,
        module_id: str | None = None,
        confirmation_state: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> list[dict]:
        """Agrupa eventos repetidos por aplicativo/módulo/ação preservando o mais recente."""
        events = self.query(
            module_id=module_id,
            confirmation_state=confirmation_state,
            since=since,
            until=until,
            limit=500,
        )
        groups: dict[tuple[str, str, str, str], dict] = {}
        for ev in events:
            app_key = ev.app_name or ev.module_id
            key = (ev.module_id, app_key, ev.action, ev.confirmation_state)
            if key not in groups:
                groups[key] = {
                    "latest": ev,
                    "count": 1,
                    "events": [ev],
                }
            else:
                groups[key]["count"] += 1
                groups[key]["events"].append(ev)
        return list(groups.values())
