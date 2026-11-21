"""Testes de contratos, configuração, histórico SQLite WAL opcional e veredito do Início."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

from mintsec.config import ConfigStore, SuiteConfig
from mintsec.contracts import ModuleState, load_manifests
from mintsec.formatting import format_confirmed_at
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.services.catalog import SuiteController


class ContractsAndHistoryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_all_seven_manifests_validate(self) -> None:
        manifests = load_manifests()
        expected = {
            "antimalware",
            "firewall",
            "recovery",
            "network",
            "browsing",
            "isolation",
            "rescue",
        }
        self.assertEqual(set(manifests.keys()), expected)
        self.assertEqual(ModuleState.AUSENTE.ui_label, "Não instalado")
        self.assertEqual(ModuleState.DESATIVADO.ui_label, "Desativado por você")
        self.assertEqual(ModuleState.VERIFICACAO_INCOMPLETA.ui_label, "Verificação incompleta")
        self.assertEqual(ModuleState.INDISPONIVEL.ui_label, "Estado indisponível")

    def test_config_separates_visual_density_from_decision_policy(self) -> None:
        store = ConfigStore(self.root / "settings.json")
        cfg = SuiteConfig(density="essential", pause_policy="auto_pause", firewall_outbound_mode="block_per_app")
        store.save(cfg)
        updated = store.update(density="detailed", theme_mode="light")
        self.assertEqual(updated.density, "detailed")
        self.assertEqual(updated.pause_policy, "auto_pause")
        self.assertEqual(updated.firewall_outbound_mode, "block_per_app")

    def test_history_uses_wal_and_disabling_preserves_pending_and_incidents(self) -> None:
        hist = HistoryStore(self.root / "history.db", enabled=True)
        self.assertEqual(hist.journal_mode().lower(), "wal")
        hist.record(
            module_id="firewall",
            action="Regra aplicada",
            reason="Teste 1",
            confirmation_state="confirmed",
            app_name="curl",
        )
        hist.record(
            module_id="firewall",
            action="Regra aplicada",
            reason="Teste 2",
            confirmation_state="confirmed",
            app_name="curl",
        )
        grouped = hist.query_grouped(module_id="firewall")
        self.assertEqual(len(grouped), 1)
        self.assertEqual(grouped[0]["count"], 2)

        # Desativar histórico opcional: não grava novos eventos, mas pendências e incidentes seguem normais
        hist.set_enabled(False)
        res = hist.record(
            module_id="antimalware",
            action="Não deve gravar",
            reason="Histórico desligado",
            confirmation_state="confirmed",
        )
        self.assertIsNone(res)
        self.assertEqual(len(hist.query(module_id="antimalware")), 0)

        pending = PendingStore(self.root / "pending.json")
        p1 = pending.create(
            kind="paused_app",
            module_id="recovery",
            app_name="encryptor",
            title="Aplicativo pausado",
            summary="Canário alterado",
            evidence="cgroup exclusivo",
            affected_paths=["/tmp/doc.txt"],
        )
        p2 = pending.create(
            kind="paused_app",
            module_id="recovery",
            app_name="encryptor",
            title="Aplicativo pausado",
            summary="Canário alterado",
            evidence="cgroup exclusivo",
            affected_paths=["/tmp/planilha.ods"],
        )
        self.assertEqual(p1.pending_id, p2.pending_id)
        self.assertEqual(pending.count_open(), 1)
        self.assertEqual(len(pending.get(p1.pending_id).affected_paths), 2)

        inc_mgr = IncidentManager(self.root / "incidents")
        target = self.root / "original.txt"
        restored = self.root / "backup.txt"
        target.write_text("corrompido", encoding="utf-8")
        restored.write_text("limpo", encoding="utf-8")
        inc_mgr.prepare_and_overwrite(target_path=target, restored_source_path=restored, incident_id="inc-wal-off")
        self.assertEqual(target.read_text(encoding="utf-8"), "limpo")
        self.assertEqual(len(inc_mgr.get_report("inc-wal-off").items), 1)

    def test_home_verdict_priorities_and_formatting(self) -> None:
        self.assertIn("Confirmado em ", format_confirmed_at("2026-11-21T14:32:00-03:00"))
        cfg_store = ConfigStore(self.root / "settings.json")
        pending_store = PendingStore(self.root / "pending.json")
        hist_store = HistoryStore(self.root / "history.db", enabled=True)
        inc_mgr = IncidentManager(self.root / "incidents")

        ctrl = SuiteController(
            config_store=cfg_store,
            pending_store=pending_store,
            history_store=hist_store,
            incident_manager=inc_mgr,
            data_dir=self.root / "data",
        )
        verdict_first = ctrl.get_home_verdict()
        self.assertEqual(verdict_first.headline, "Escolha suas proteções")

        pending_store.create(
            kind="paused_app",
            module_id="recovery",
            app_name="suspeito",
            title="Aplicativo pausado",
            summary="Teste",
            evidence="Canário + cgroup",
        )
        verdict_paused = ctrl.get_home_verdict()
        self.assertEqual(verdict_paused.headline, "Um aplicativo está pausado")
        self.assertEqual(verdict_paused.primary_cta_label, "Revisar aplicativo")


if __name__ == "__main__":
    unittest.main()
