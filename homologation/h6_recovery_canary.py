"""Ensaio H6: recuperação independente, colisão em quarentena, FAN_Q_OVERFLOW e limiar beta."""

from __future__ import annotations

import os
import tempfile
import time
from pathlib import Path
from typing import Any

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import load_manifests
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.packaging import PackageInspector
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.antimalware import AntimalwareService, RestoreCollisionError
from mintsec.services.containment import ContainmentService
from mintsec.services.recovery import RecoveryService


class _H6Runner:
    def which(self, binary: str) -> str | None:
        return f"/usr/bin/{binary}" if binary in ("restic", "timeshift", "clamscan") else None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        if argv[0] == "dpkg-query":
            return CommandResult(tuple(argv), 0, "install ok installed\t1.0.0\n", "")
        if argv[0] == "apt-cache":
            return CommandResult(tuple(argv), 0, " *** 1.0.0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n", "")
        if argv[0].endswith("restic") and "restore" in argv:
            t_dir = Path(argv[argv.index("--target") + 1])
            for idx, tok in enumerate(argv):
                if tok == "--include":
                    p = Path(argv[idx + 1])
                    rel = p.relative_to("/") if p.is_absolute() else p
                    out = t_dir / rel
                    out.parent.mkdir(parents=True, exist_ok=True)
                    out.write_bytes(b"dados-limpos-copia-independente")
            return CommandResult(tuple(argv), 0, "{}", "")
        return CommandResult(tuple(argv), 0, "{}", "")


def run_h6(repo_root: Path) -> dict[str, Any]:
    manifests = load_manifests()
    with tempfile.TemporaryDirectory(prefix="mintsec-h6-") as tmp:
        tmp_path = Path(tmp)
        runner = _H6Runner()
        cfg = ConfigStore(tmp_path / "settings.json")
        pend = PendingStore(tmp_path / "pending.json")
        hist = HistoryStore(tmp_path / "history.db")
        inc = IncidentManager(tmp_path / "incidents")
        auth = CallerAuthorizer(test_decision=True)

        # 1. Restauração a partir de cópia independente com preservação fora de $HOME
        rec = RecoveryService(
            manifest=manifests["recovery"],
            config_store=cfg,
            pending_store=pend,
            history_store=hist,
            incident_manager=inc,
            package_inspector=PackageInspector(runner),
            runner=runner,
            authorizer=auth,
            data_dir=tmp_path / "data",
        )
        rec.configure(repo_path=str(tmp_path / "repo"), repo_type="removable_offline")
        victim = tmp_path / "docs/planilha.ods"
        victim.parent.mkdir(parents=True)
        victim.write_bytes(b"conteudo-alterado")

        res = rec.restore_files(
            snapshot_id="snap01",
            paths=[str(victim)],
            password="pw",
            overwrite_original=True,
            incident_id="inc-h6",
            app_paused_or_stopped=True,
        )
        assert res["ok"] and victim.read_bytes() == b"dados-limpos-copia-independente"

        # 2. Colisão na restauração de quarentena
        am = AntimalwareService(
            manifest=manifests["antimalware"],
            config_store=cfg,
            pending_store=pend,
            history_store=hist,
            package_inspector=PackageInspector(runner),
            runner=runner,
            authorizer=auth,
            data_dir=tmp_path / "data",
        )
        q_src = tmp_path / "suspeito.bin"
        q_src.write_bytes(b"payload")
        q_item = am.quarantine_file(q_src, detection_name="Test.Trojan", confirmed=True)
        existing = tmp_path / "destino_ocupado.bin"
        existing.write_bytes(b"original")
        collision_hit = False
        try:
            am.restore_quarantined(q_item.item_id, destination_path=existing, collision_policy="ask")
        except RestoreCollisionError:
            collision_hit = True
        assert collision_hit

        # 3. Reconstrução pós-FAN_Q_OVERFLOW por ctime + diff Btrfs marcada como possivelmente incompleta
        t_start = time.time() - 1.0
        changed_file = tmp_path / "docs/modificado.txt"
        changed_file.write_text("alterado recentemente", encoding="utf-8")
        cont = ContainmentService(config_store=cfg, pending_store=pend)
        recon = cont.reconstruct_after_overflow(
            interval_start_epoch=t_start,
            search_roots=[tmp_path / "docs"],
            btrfs_diff_paths=[str(tmp_path / "docs/btrfs_extra.txt")],
        )
        assert recon["possibly_incomplete"] is True
        assert recon["fan_q_overflow"] is True
        assert str(changed_file) in recon["reconstructed_paths"]
        assert str(tmp_path / "docs/btrfs_extra.txt") in recon["reconstructed_paths"]

        # 4. Critério beta de falsos positivos (<= 1 / 1.000 inst.-semana e <= 0,5%)
        ok_gate = cont.evaluate_beta_false_positive_gate(false_pauses=1, install_weeks=2000, canary_incidents=500)
        bad_gate = cont.evaluate_beta_false_positive_gate(false_pauses=2, install_weeks=1000, canary_incidents=200)
        assert not ok_gate["review_required"] and bad_gate["review_required"]

    return {
        "assay": "H6",
        "status": "PASS",
        "independent_restore_with_incident_preserve_ok": True,
        "quarantine_collision_handled": True,
        "fan_q_overflow_reconstruction_marked_incomplete": True,
        "beta_false_positive_gate_verified": True,
    }
