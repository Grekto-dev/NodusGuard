"""Testes de otimização, caches por mtime, protobuf varint puro e refresh assíncrono."""

from __future__ import annotations

import os
import tempfile
import threading
import time
import unittest
from pathlib import Path

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.firewall_trust import OpenSnitchBridge, TrustStore
from mintsec.history import HistoryStore
from mintsec.opensnitch_grpc import (
    OpenSnitchGrpcClient,
    decode_wire_envelope,
    encode_wire_envelope,
)
from mintsec.packaging import PackageInspector, parse_apt_policy_multi
from mintsec.pending import PendingStore
from mintsec.runner import SubprocessRunner
from mintsec.services.catalog import SuiteController


class PerformanceAndCacheTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="mintsec-perf-test-")
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_subprocess_runner_fast_path_timeout_and_which_cache(self) -> None:
        runner = SubprocessRunner()
        t0 = time.perf_counter()
        for _ in range(5):
            res = runner.run(["true"])
            self.assertEqual(res.returncode, 0)
        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        # Sem sleep artificial de 50 ms, 5 execuções de `true` levam poucos milissegundos
        self.assertLess(elapsed_ms, 150.0)

        missing = runner.run(["mintsec-binario-inexistente-xyz"])
        self.assertEqual(missing.returncode, 127)

        timed = runner.run(["sleep", "2"], timeout=0.05)
        self.assertTrue(timed.timed_out)
        self.assertEqual(timed.returncode, -1)

        p1 = runner.which("sh")
        self.assertIsNotNone(p1)
        self.assertEqual(runner.which("sh"), p1)

    def test_parse_apt_policy_multi_and_prime_cache(self) -> None:
        sample = (
            "ufw:\n"
            "  Instalado: 0.36.2-6\n"
            "  Candidato: 0.36.2-6\n"
            "  Tabela de versão:\n"
            " *** 0.36.2-6 500\n"
            "        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n"
            "        100 /var/lib/dpkg/status\n"
            "timeshift:\n"
            "  Instalado: 25.12.4+zena\n"
            "  Candidato: 25.12.4+zena\n"
            "  Tabela de versão:\n"
            " *** 25.12.4+zena 500\n"
            "        500 http://packages.linuxmint.com zena/backport amd64 Packages\n"
            "        100 /var/lib/dpkg/status\n"
        )
        origins = parse_apt_policy_multi(sample, {"ufw": "0.36.2-6", "timeshift": "25.12.4+zena"})
        self.assertEqual(origins["ufw"], "Ubuntu (noble/main)")
        self.assertEqual(origins["timeshift"], "Linux Mint (zena/backport)")

        inspector = PackageInspector(SubprocessRunner())
        inspector.prime_cache(["bash", "mintsec-pacote-inexistente-xyz"], binaries_by_pkg={"bash": ["bash"]})
        info_bash = inspector.inspect_package("bash", binaries=["bash"])
        info_missing = inspector.inspect_package("mintsec-pacote-inexistente-xyz")
        self.assertTrue(info_bash.installed)
        self.assertTrue(info_bash.binary_present)
        self.assertFalse(info_missing.installed)

        inspector.invalidate_cache()
        info_bash_2 = inspector.inspect_package("bash", binaries=["bash"])
        self.assertEqual(info_bash_2.version, info_bash.version)

    def test_config_and_pending_mtime_cache_return_isolated_copies(self) -> None:
        cfg_store = ConfigStore(self.root / "settings.json")
        cfg_store.update(theme_mode="dark", density="detailed")
        c1 = cfg_store.load()
        c1.enabled_modules["firewall"] = True
        c1.density = "essential"
        # Mutar a cópia retornada não pode corromper o cache em memória
        c2 = cfg_store.load()
        self.assertEqual(c2.density, "detailed")
        self.assertNotIn("firewall", c2.enabled_modules)

        pend_store = PendingStore(self.root / "pending.json")
        created = pend_store.create(
            kind="warning",
            module_id="firewall",
            title="Teste",
            summary="Resumo",
            evidence="Evidência",
            app_name="curl",
        )
        listed = pend_store.list_open()
        self.assertEqual(len(listed), 1)
        listed[0].evidence = "MODIFICADO_EXTERNAMENTE"
        listed_again = pend_store.list_open()
        self.assertEqual(listed_again[0].evidence, "Evidência")
        self.assertIsNotNone(pend_store.resolve(created.pending_id))
        self.assertEqual(pend_store.count_open(), 0)

    def test_controller_cache_and_async_refresh_coalescing(self) -> None:
        ctrl = SuiteController(
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
        )
        t0 = time.perf_counter()
        s1 = ctrl.all_statuses()
        cold_ms = (time.perf_counter() - t0) * 1000.0
        self.assertEqual(len(s1), 7)
        self.assertLess(cold_ms, 1000.0)

        t1 = time.perf_counter()
        s2 = ctrl.all_statuses(use_cache=True)
        hot_ms = (time.perf_counter() - t1) * 1000.0
        self.assertEqual(list(s2.keys()), list(s1.keys()))
        self.assertLess(hot_ms, 5.0)

        ctrl.invalidate_cache("firewall")
        self.assertIsNone(ctrl.get_cached_statuses())

        done_ev = threading.Event()
        received: list[dict] = []

        def _on_done(statuses: dict) -> None:
            received.append(statuses)
            done_ev.set()

        ctrl.refresh_statuses_async(_on_done, force=True)
        self.assertTrue(done_ev.wait(timeout=5.0))
        self.assertEqual(len(received[0]), 7)

    def test_wire_protobuf_multibyte_varint_and_no_socket_leak(self) -> None:
        large_payload = {"entries": [f"192.0.2.{i}:443" for i in range(250)], "mode": "block_per_app"}
        frame = encode_wire_envelope("AskRuleBatch", large_payload)
        self.assertGreater(len(frame), 4096)
        op, decoded = decode_wire_envelope(frame[4:])
        self.assertEqual(op, "AskRuleBatch")
        self.assertEqual(decoded, large_payload)

        pend = PendingStore(self.root / "p.json")
        trust = TrustStore(self.root / "t.json", allowed_uids={os.getuid()}, stop_at_prefix=self.root)
        bridge = OpenSnitchBridge(pending_store=pend, trust_store=trust)
        client = OpenSnitchGrpcClient(bridge=bridge, socket_path=self.root / "missing.sock")
        st = client.probe_daemon_socket()
        self.assertFalse(st.reachable)
        # Conectar a socket ausente deve fechar descritor imediatamente sem vazamento
        with self.assertRaises(ConnectionError):
            client.ping()


if __name__ == "__main__":
    unittest.main()
