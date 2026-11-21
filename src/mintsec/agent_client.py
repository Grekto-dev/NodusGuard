"""Cliente D-Bus opcional para o agente de sessão Rust (org.mintsecurity.SessionAgent)."""

from __future__ import annotations

import json
from typing import Any

from mintsec.contracts import PendingDecision
from mintsec.pending import PendingStore

AGENT_BUS_NAME = "org.mintsecurity.SessionAgent"
AGENT_OBJECT_PATH = "/org/mintsecurity/SessionAgent"
AGENT_INTERFACE = "org.mintsecurity.SessionAgent"


class AgentClient:
    """Comunica-se com o agente de sessão Rust via D-Bus de sessão com fallback local."""

    def __init__(self, pending_store: PendingStore | None = None) -> None:
        self.pending_store = pending_store or PendingStore()

    def _get_iface(self) -> Any:
        import dbus

        bus = dbus.SessionBus()
        obj = bus.get_object(AGENT_BUS_NAME, AGENT_OBJECT_PATH)
        return dbus.Interface(obj, AGENT_INTERFACE)

    def notify_alert(self, decision: PendingDecision) -> str:
        """Envia alerta para o agente de sessão ou grava no PendingStore se o agente estiver ausente."""
        payload = json.dumps(decision.to_dict(), ensure_ascii=False)
        try:
            iface = self._get_iface()
            return str(iface.NotifyAlert(payload))
        except Exception:
            saved = self.pending_store.add(decision, group_repeated=True)
            return saved.pending_id

    def get_pending_count(self) -> int:
        try:
            iface = self._get_iface()
            return int(iface.GetPendingCount())
        except Exception:
            return self.pending_store.count_open()

    def resolve_pending(self, pending_id: str, resolution: str = "resolved") -> bool:
        try:
            iface = self._get_iface()
            return bool(iface.ResolvePending(pending_id, resolution))
        except Exception:
            return self.pending_store.resolve(pending_id, resolution=resolution) is not None
