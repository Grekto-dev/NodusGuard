"""Testes unitários das Fases 2 e 3: OpenSnitch/APT trust, DNS/Wi-Fi, contenção, bwrap e resgate."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mintsec.config import ConfigStore
from mintsec.contracts import load_manifests
from mintsec.history import HistoryStore
from mintsec.pending import PendingStore
from mintsec.services.browsing import BrowsingService
from mintsec.services.containment import ContainmentService
from mintsec.services.isolation import IsolationService
from mintsec.services.network import NetworkService
from mintsec.services.rescue import evaluate_block_devices


class Phase2And3UnitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.manifests = load_manifests()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_browsing_doh_detection_and_vpn_domain_protection(self) -> None:
        fake_home = self.root / "home"
        ff_prof = fake_home / ".mozilla/firefox/demo.default"
        ff_prof.mkdir(parents=True)
        (ff_prof / "prefs.js").write_text('user_pref("network.trr.mode", 3);\n', encoding="utf-8")

        browsing = BrowsingService(
            manifest=self.manifests["browsing"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            data_dir=self.root / "data",
        )
        warnings = browsing.detect_browser_doh(home_dir=fake_home)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0]["browser"], "Firefox")

        with self.assertRaises(PermissionError):
            browsing.authorize_external_resolver(
                "db.corp.internal",
                "9.9.9.9",
                vpn_domains=["corp.internal"],
            )

    def test_network_client_isolation_and_home_gate(self) -> None:
        net = NetworkService(
            manifest=self.manifests["network"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            data_dir=self.root / "data",
        )
        net.enable()
        net.ingest_observations(
            [{"mac": "00:11:22:33:44:55", "ip": "10.0.0.5", "interface": "wlan0"}],
            network_id="HotelWiFi",
            alert_on_new=True,
            client_isolation=True,
        )
        self.assertEqual(net.pending_store.count_open(), 1)
        with self.assertRaises(PermissionError):
            net.active_discover("HotelWiFi")

        net.set_network_home("Casa5G", True)
        net.recognize_device("00:11:22:33:44:55", "Notebook")
        self.assertEqual(net.pending_store.count_open(), 0)

    def test_containment_gates_and_bwrap_smoke(self) -> None:
        cfg = ConfigStore(self.root / "settings.json")
        pend = PendingStore(self.root / "pending.json")
        cont = ContainmentService(config_store=cfg, pending_store=pend)

        # Política unset nunca pausa automaticamente
        ev1, _ = cont.evaluate_event(
            app_name="x",
            canary_modified=True,
            corroborating_activity_same_app=True,
            exclusive_cgroup_verified=True,
            scope_kind="suite_transient",
            thread_count=2,
            child_count=1,
            affected_paths=["/tmp/a"],
        )
        self.assertFalse(ev1.should_pause)

        cfg.update(pause_policy="auto_pause")
        ev2, _ = cont.evaluate_event(
            app_name="x",
            canary_modified=True,
            corroborating_activity_same_app=True,
            exclusive_cgroup_verified=False,
            scope_kind="shared",
            thread_count=4,
            child_count=2,
            affected_paths=["/tmp/a"],
        )
        self.assertFalse(ev2.should_pause)

        iso = IsolationService(
            manifest=self.manifests["isolation"],
            config_store=cfg,
            pending_store=pend,
            history_store=HistoryStore(self.root / "history.db"),
            data_dir=self.root / "data",
        )
        smoke = iso.smoke_test_bwrap()
        self.assertTrue(smoke["ok"])

    def test_rescue_refuses_ambiguous_usb_without_serial_or_wwn(self) -> None:
        cands, _ = evaluate_block_devices(
            {
                "blockdevices": [
                    {
                        "name": "sdd",
                        "kname": "sdd",
                        "path": "/dev/sdd",
                        "type": "disk",
                        "size": 8000000000,
                        "model": "Generic",
                        "serial": "",
                        "wwn": "",
                        "tran": "usb",
                        "rm": True,
                    }
                ]
            }
        )
        self.assertEqual(len(cands), 1)
        self.assertFalse(cands[0].safe_for_rescue_write)
        self.assertIn("ambíguo", cands[0].refusal_reason or "")


if __name__ == "__main__":
    unittest.main()
