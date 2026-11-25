"""Registro persistente e seguro de logs operacionais do NodusGuard."""

from __future__ import annotations

import json
import os
import stat
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from mintsec.contracts import ensure_private_dir, xdg_dir
from mintsec.formatting import now_iso

VALID_LOG_LEVELS = ("INFO", "WARNING", "ERROR")
_MAX_LOG_BYTES = 2 * 1024 * 1024
_MAX_MESSAGE_LEN = 500
_MAX_DETAILS_LEN = 2000


@dataclass(frozen=True)
class AppLogEntry:
    """Entrada individual de log operacional exibida em Configurações -> Logs."""

    timestamp: str
    level: str
    category: str
    message: str
    details: str = ""
    source: str = ""

    def to_dict(self) -> dict[str, str]:
        return asdict(self)

    @classmethod
    def from_dict(cls, raw: Any) -> AppLogEntry | None:
        if not isinstance(raw, dict):
            return None
        level = str(raw.get("level", "INFO")).strip().upper()
        if level not in VALID_LOG_LEVELS:
            level = "INFO"
        msg = str(raw.get("message", "")).strip()
        if not msg:
            return None
        return cls(
            timestamp=str(raw.get("timestamp", "")).strip() or now_iso(),
            level=level,
            category=str(raw.get("category", "app")).strip()[:48] or "app",
            message=msg[:_MAX_MESSAGE_LEN],
            details=str(raw.get("details", "")).strip()[:_MAX_DETAILS_LEN],
            source=str(raw.get("source", "")).strip()[:80],
        )

    def format_line(self) -> str:
        """Formata entrada legível em texto puro para visualização no painel."""
        ts_clean = self.timestamp.replace("T", " ")
        if "+" in ts_clean:
            ts_clean = ts_clean.split("+", 1)[0]
        src_part = f" · {self.source}" if self.source else ""
        head = f"[{ts_clean}] [{self.level}] [{self.category}{src_part}] {self.message}"
        if self.details:
            return f"{head}\n    {self.details}"
        return head


class AppLogStore:
    """Armazena logs operacionais do aplicativo em JSON Lines com limite rotativo."""

    def __init__(self, path: Path | None = None, *, max_entries: int = 1000) -> None:
        self.path = path or (xdg_dir("XDG_STATE_HOME", ".local/state") / "app.log.jsonl")
        self.max_entries = max(50, int(max_entries))
        self._lock = threading.RLock()

    def _reject_symlink(self, target: Path) -> None:
        try:
            st = os.lstat(target)
        except FileNotFoundError:
            return
        if stat.S_ISLNK(st.st_mode):
            raise PermissionError(f"Arquivo de log não pode ser link simbólico: {target}")

    def _read_all_locked(self) -> list[AppLogEntry]:
        self._reject_symlink(self.path)
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            return []
        if not stat.S_ISREG(st.st_mode) or st.st_size > _MAX_LOG_BYTES:
            return []
        try:
            raw_text = self.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return []
        entries: list[AppLogEntry] = []
        for line in raw_text.splitlines():
            line_s = line.strip()
            if not line_s:
                continue
            try:
                parsed = json.loads(line_s)
            except ValueError:
                continue
            entry = AppLogEntry.from_dict(parsed)
            if entry is not None:
                entries.append(entry)
        return entries

    def _write_all_locked(self, entries: list[AppLogEntry]) -> None:
        ensure_private_dir(self.path.parent, 0o700)
        self._reject_symlink(self.path)
        trimmed = entries[-self.max_entries :]
        payload = "".join(
            json.dumps(item.to_dict(), ensure_ascii=False) + "\n"
            for item in trimmed
        )
        tmp = self.path.with_name(f".{self.path.name}.tmp")
        self._reject_symlink(tmp)
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        try:
            os.write(fd, payload.encode("utf-8"))
        finally:
            os.close(fd)
        os.replace(tmp, self.path)

    def record(
        self,
        level: str,
        category: str,
        message: str,
        *,
        details: str = "",
        source: str = "",
    ) -> AppLogEntry:
        clean_level = str(level or "INFO").strip().upper()
        if clean_level not in VALID_LOG_LEVELS:
            clean_level = "INFO"
        clean_msg = str(message or "").strip()[:_MAX_MESSAGE_LEN] or clean_level
        entry = AppLogEntry(
            timestamp=now_iso(),
            level=clean_level,
            category=str(category or "app").strip()[:48] or "app",
            message=clean_msg,
            details=str(details or "").strip()[:_MAX_DETAILS_LEN],
            source=str(source or "").strip()[:80],
        )
        with self._lock:
            entries = self._read_all_locked()
            entries.append(entry)
            self._write_all_locked(entries)
        return entry

    def list_entries(
        self,
        *,
        level: str | None = None,
        query: str = "",
        limit: int = 500,
    ) -> list[AppLogEntry]:
        with self._lock:
            entries = self._read_all_locked()
        lvl = str(level or "").strip().upper()
        q = str(query or "").strip().lower()
        filtered: list[AppLogEntry] = []
        for entry in reversed(entries):
            if lvl and lvl in VALID_LOG_LEVELS and entry.level != lvl:
                continue
            if q:
                hay = f"{entry.level} {entry.category} {entry.source} {entry.message} {entry.details}".lower()
                if q not in hay:
                    continue
            filtered.append(entry)
            if len(filtered) >= limit:
                break
        return filtered

    def count(self) -> int:
        with self._lock:
            return len(self._read_all_locked())

    def clear(self) -> int:
        with self._lock:
            previous = len(self._read_all_locked())
            self._write_all_locked([])
            return previous
