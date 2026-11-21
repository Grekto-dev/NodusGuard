"""Testes do conector OpenSnitch sobre Unix domain socket e wire protobuf."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mintsec.firewall_trust import OpenSnitchBridge, TrustStore
from mintsec.opensnitch_grpc import (
    MockOpenSnitchDaemonServer,
    OpenSnitchGrpcClient,
    decode_wire_envelope,
    encode_wire_envelope,
)
from mintsec.pending import PendingStore


class OpenSnitchWireTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_wire_protobuf_roundtrip_and_socket_reconnect(self) -> None:
        frame = encode_wire_envelope("Ping", {"id": "123", "mode": "block_per_app"})
        op, payload = decode_wire_envelope(frame[4:])
        self.assertEqual(op, "Ping")
        self.assertEqual(payload["mode"], "block_per_app")

        sock_path = self.root / "osui.sock"
        srv = MockOpenSnitchDaemonServer(sock_path)
        srv.start()
        try:
            pend = PendingStore(self.root / "pending.json")
            trust = TrustStore(
                self.root / "trust.json",
                allowed_uids={os.getuid()},
                stop_at_prefix=self.root,
            )
            bridge = OpenSnitchBridge(pending_store=pend, trust_store=trust)
            client = OpenSnitchGrpcClient(bridge=bridge, socket_path=sock_path)

            pong = client.ping()
            self.assertTrue(pong["ok"])
            self.assertEqual(pong["version"], "1.5.8.1")

            cfg_ack = client.set_default_action("block_per_app")
            self.assertEqual(cfg_ack["default_action"], "deny")

            d1 = client.process_ask_rule(
                connection_id="c1",
                app_name="curl",
                executable_path="/usr/bin/curl",
                destination="1.1.1.1:443",
                outbound_mode="block_per_app",
                pid=9001,
            )
            self.assertEqual(d1["action"], "wait")

            # Queda abrupta do daemon -> modo bloqueio aplica DefaultAction=deny e registra pendência recuperável
            srv.stop()
            d_off = client.process_ask_rule(
                connection_id="c2",
                app_name="wget",
                executable_path="/usr/bin/wget",
                destination="9.9.9.9:443",
                outbound_mode="block_per_app",
            )
            self.assertEqual(d_off["default_action"], "deny")
            self.assertEqual(pend.count_open(), 1)

            # Reinício do daemon -> cliente reconecta automaticamente sem perder estado
            srv.start()
            pong2 = client.ping()
            self.assertTrue(pong2["ok"])
            client.send_rule({"name": "allow-curl", "action": "allow"})
            self.assertEqual(len(srv.applied_rules), 1)
            client.close()
        finally:
            srv.stop()


if __name__ == "__main__":
    unittest.main()
