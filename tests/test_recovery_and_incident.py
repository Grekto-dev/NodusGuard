"""Testes de Recuperação (Timeshift/restic) e Pasta do Incidente fora de $HOME."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import load_manifests
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager, InsufficientSpaceError
from mintsec.packaging import PackageInspector
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.recovery import RecoveryService


class FakeRecoveryRunner:
    def __init__(self, *, restore_payload: bytes = b"versao limpa recuperada") -> None:
        self.restore_payload = restore_payload
        self.calls: list[list[str]] = []

    def which(self, binary: str) -> str | None:
        return f"/usr/bin/{binary}" if binary in ("restic", "timeshift") else None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        self.calls.append(list(argv))
        if argv[0] == "dpkg-query":
            pkg = argv[-1]
            if pkg in ("restic", "timeshift"):
                return CommandResult(tuple(argv), 0, "install ok installed\t0.16.4-2\n", "")
            return CommandResult(tuple(argv), 1, "", "")
        if argv[0] == "apt-cache":
            return CommandResult(
                tuple(argv),
                0,
                " *** 0.16.4-2 500\n        500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages\n",
                "",
            )
        if argv[0].endswith("timeshift"):
            return CommandResult(
                tuple(argv),
                0,
                "0 > 2026-11-20_18-00-00 O Antes da atualizacao\n",
                "",
            )
        if argv[0].endswith("restic"):
            subcmd = argv[3] if len(argv) > 3 and argv[1] == "-r" else argv[1]
            if subcmd == "snapshots":
                return CommandResult(
                    tuple(argv),
                    0,
                    '[{"id":"abcdef123456","short_id":"abcdef12","time":"2026-11-21T09:00:00-03:00","paths":["/tmp/docs"]}]',
                    "",
                )
            if subcmd == "restore":
                target_idx = argv.index("--target") + 1
                target_root = Path(argv[target_idx])
                include_paths = [
                    argv[i + 1] for i, tok in enumerate(argv) if tok == "--include"
                ]
                if include_paths:
                    for inc in include_paths:
                        rel = Path(inc).relative_to("/") if Path(inc).is_absolute() else Path(inc)
                        out_file = target_root / rel
                        out_file.parent.mkdir(parents=True, exist_ok=True)
                        out_file.write_bytes(self.restore_payload)
                else:
                    sample = target_root / "amostra.txt"
                    sample.parent.mkdir(parents=True, exist_ok=True)
                    sample.write_bytes(self.restore_payload)
                return CommandResult(tuple(argv), 0, '{"message_type":"summary"}', "")
            return CommandResult(tuple(argv), 0, "{}", "")
        return CommandResult(tuple(argv), 0, "", "")


class RecoveryAndIncidentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.manifests = load_manifests()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_service(self, runner: FakeRecoveryRunner) -> RecoveryService:
        inc_mgr = IncidentManager(self.root / "incidents_outside_home")
        return RecoveryService(
            manifest=self.manifests["recovery"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            incident_manager=inc_mgr,
            package_inspector=PackageInspector(runner),
            runner=runner,
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
        )

    def test_backup_and_restore_test_tracked_separately(self) -> None:
        runner = FakeRecoveryRunner()
        svc = self._make_service(runner)
        svc.configure(
            repo_path=str(self.root / "repo"),
            repo_type="removable_offline",
            separate_maintenance_credential=True,
            include_paths=[str(self.root / "docs")],
        )
        svc.enable()

        bk = svc.backup_now(password="segredo")
        self.assertTrue(bk["ok"])
        st1 = svc.query_status()
        cfg1 = st1.details["restic"]["config"]
        self.assertIsNotNone(cfg1["last_backup_at"])
        self.assertIsNone(cfg1["last_restore_test_at"])

        tst = svc.test_restore(password="segredo")
        self.assertTrue(tst["ok"])
        st2 = svc.query_status()
        cfg2 = st2.details["restic"]["config"]
        self.assertIsNotNone(cfg2["last_restore_test_at"])
        self.assertIn("Aprovado", cfg2["last_restore_test_result"])

    def test_incident_folder_outside_home_and_overwrite_protections(self) -> None:
        home_sub = Path.home() / "pasta_proibida_incidente"
        with self.assertRaises(ValueError):
            IncidentManager(home_sub)

        runner = FakeRecoveryRunner(restore_payload=b"conteudo original restaurado")
        svc = self._make_service(runner)
        svc.configure(repo_path=str(self.root / "repo"))

        target_file = self.root / "trabalho" / "relatorio.txt"
        target_file.parent.mkdir(parents=True)
        target_file.write_bytes(b"conteudo cifrado pelo ransomware")

        # Restauração em outra pasta não altera o original
        other_dir = self.root / "outra_pasta"
        svc.restore_files(
            snapshot_id="abcdef12",
            paths=[str(target_file)],
            destination_dir=other_dir,
            password="segredo",
            overwrite_original=False,
        )
        self.assertEqual(target_file.read_bytes(), b"conteudo cifrado pelo ransomware")

        # Sobrescrita durante incidente exige aplicativo pausado/encerrado
        with self.assertRaises(PermissionError):
            svc.restore_files(
                snapshot_id="abcdef12",
                paths=[str(target_file)],
                password="segredo",
                overwrite_original=True,
                incident_id="inc-01",
                app_paused_or_stopped=False,
            )

        # Sobrescrita válida preserva versão alterada fora de $HOME
        out = svc.restore_files(
            snapshot_id="abcdef12",
            paths=[str(target_file)],
            password="segredo",
            overwrite_original=True,
            incident_id="inc-01",
            app_paused_or_stopped=True,
        )
        self.assertTrue(out["ok"])
        self.assertEqual(target_file.read_bytes(), b"conteudo original restaurado")

        rep = svc.incident_manager.get_report("inc-01")
        self.assertEqual(len(rep.items), 1)
        preserved = Path(rep.items[0].preserved_path)
        self.assertTrue(preserved.exists())
        self.assertEqual(preserved.read_bytes(), b"conteudo cifrado pelo ransomware")
        self.assertEqual(preserved.stat().st_mode & 0o777, 0o400)

        with self.assertRaises(PermissionError):
            svc.incident_manager.cleanup_incident("inc-01", confirmed=False)
        freed = svc.incident_manager.cleanup_incident("inc-01", confirmed=True)
        self.assertGreater(freed, 0)
        self.assertFalse(preserved.exists())

    def test_cross_mount_space_check_and_interrupt_safety(self) -> None:
        inc_mgr = IncidentManager(self.root / "incidents_xdev")
        target = self.root / "arquivo.bin"
        restored = self.root / "restaurado.bin"
        target.write_bytes(b"A" * 8192)
        restored.write_bytes(b"B" * 4096)

        # Simula EXDEV no os.rename + espaço insuficiente via statvfs
        class LowSpaceStat:
            f_bavail = 1
            f_frsize = 512

        with mock.patch("os.rename", side_effect=OSError(18, "Invalid cross-device link")), mock.patch(
            "os.statvfs", return_value=LowSpaceStat()
        ):
            with self.assertRaises(InsufficientSpaceError):
                inc_mgr.prepare_and_overwrite(
                    target_path=target,
                    restored_source_path=restored,
                    incident_id="inc-low",
                )
        # Original preservado intacto!
        self.assertEqual(target.read_bytes(), b"A" * 8192)

        # Interrupção após preservar registra estado e caminho preservado
        with self.assertRaises(InterruptedError):
            inc_mgr.prepare_and_overwrite(
                target_path=target,
                restored_source_path=restored,
                incident_id="inc-int",
                simulate_interrupt_after_preserve=True,
            )
        rep = inc_mgr.get_report("inc-int")
        self.assertEqual(len(rep.items), 1)
        self.assertEqual(rep.items[0].status, "preserved_only")
        self.assertTrue(Path(rep.items[0].preserved_path).exists())


if __name__ == "__main__":
    unittest.main()
