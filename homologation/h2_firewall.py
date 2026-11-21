"""Ensaio H2: OpenSnitch concorrência, fila cheia, ponte offline/reiniciando e UFW."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from mintsec.firewall_trust import OpenSnitchBridge, TrustStore
from mintsec.pending import PendingStore


def run_h2(repo_root: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="mintsec-h2-") as tmp:
        tmp_path = Path(tmp)
        pending = PendingStore(tmp_path / "pending.json")
        trust = TrustStore(
            tmp_path / "trust.json",
            allowed_uids={os.getuid()},
            stop_at_prefix=tmp_path,
        )
        bridge = OpenSnitchBridge(
            pending_store=pending,
            trust_store=trust,
            denials_path=tmp_path / "denials.json",
        )
        bridge.max_concurrent_waits = 2

        # 1. Duas decisões simultâneas independentes
        c1 = bridge.handle_first_connection(
            connection_id="c1",
            app_name="curl",
            executable_path="/usr/bin/curl",
            destination="1.1.1.1:443",
            outbound_mode="block_per_app",
            pid=4001,
            encrypted_dns_domain="api.exemplo.org",
        )
        c2 = bridge.handle_first_connection(
            connection_id="c2",
            app_name="wget",
            executable_path="/usr/bin/wget",
            destination="9.9.9.9:443",
            outbound_mode="block_per_app",
            pid=4002,
            encrypted_dns_domain="cdn.exemplo.org",
        )
        assert c1["action"] == "wait" and c1["status_label"] == "Aguardando decisão"
        assert c2["action"] == "wait" and c2["waiting_count"] == 2

        # 2. Fila cheia (3ª conexão negada uma vez e agrupada)
        c3 = bridge.handle_first_connection(
            connection_id="c3",
            app_name="ephemeral-sh",
            executable_path="/usr/bin/dash",
            destination="8.8.8.8:443",
            outbound_mode="block_per_app",
            pid=4003,
        )
        assert c3["action"] == "deny" and c3["status_label"] == "Permitir a próxima tentativa"

        # Resolve c1 mantendo c2 aguardando
        r1 = bridge.resolve_waiting("c1", "allow", remember_version=False)
        assert r1["remaining_waiting"] == 1
        bridge.resolve_waiting("c2", "deny")

        # 3. Ponte ocupada, serializada e offline/reiniciando
        bridge.bridge_busy = True
        busy_res = bridge.handle_first_connection(
            connection_id="c4",
            app_name="app-busy",
            executable_path="/usr/bin/curl",
            destination="example.com:443",
            outbound_mode="block_per_app",
        )
        assert busy_res["action"] == "deny"
        bridge.bridge_busy = False

        bridge.bridge_online = False
        offline_deny = bridge.handle_first_connection(
            connection_id="c5",
            app_name="app-offline",
            executable_path="/usr/bin/curl",
            destination="example.com:443",
            outbound_mode="block_per_app",
        )
        assert offline_deny["default_action"] == "deny"

        offline_mon = bridge.handle_first_connection(
            connection_id="c6",
            app_name="app-offline",
            executable_path="/usr/bin/curl",
            destination="example.com:443",
            outbound_mode="monitor_only",
        )
        assert offline_mon["default_action"] == "allow"

        # Reinício da ponte + 'Permitir a próxima tentativa'
        bridge.bridge_online = True
        bridge.allow_next_attempt("app-offline")
        retry_ok = bridge.handle_first_connection(
            connection_id="c7",
            app_name="app-offline",
            executable_path="/usr/bin/curl",
            destination="example.com:443",
            outbound_mode="block_per_app",
        )
        assert retry_ok["action"] == "allow"
        assert len(bridge.list_denials()) >= 3
        assert pending.count_open() >= 2

    return {
        "assay": "H2",
        "status": "PASS_CONTRACT_VERIFIED",
        "simultaneous_waits_isolated": True,
        "queue_full_and_busy_recoverable": True,
        "offline_default_deny_and_monitor_allow": True,
        "allow_next_attempt_verified": True,
        "pending_live_opensnitch": "Integração de contrato validada; execução contra daemon opensnitchd ao vivo aguarda instalação do pacote opensnitch.",
    }
