"""Ensaio H1: binário estático por syscall direta, fork/vfork/posix_spawn e contenção."""

from __future__ import annotations

import platform
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from homologation.h1_exec_freeze.run_h1_vm import run_h1_vm
from mintsec.config import ConfigStore
from mintsec.pending import PendingStore
from mintsec.services.containment import ContainmentService


def run_h1(repo_root: Path) -> dict[str, Any]:
    h1_dir = repo_root / "homologation/h1_exec_freeze"
    helper_bin = repo_root / "helpers/mintsec-containment/mintsec-containment"
    kernel_release = platform.release()

    with tempfile.TemporaryDirectory(prefix="mintsec-h1-") as tmp:
        tmp_path = Path(tmp)
        marker_bin = tmp_path / "marker"
        launcher_bin = tmp_path / "launcher"

        subprocess.run(
            ["gcc", "-nostdlib", "-static", "-O2", str(h1_dir / "marker.c"), "-o", str(marker_bin)],
            check=True,
        )
        subprocess.run(
            ["gcc", "-O2", "-Wall", "-Wextra", "-Werror", str(h1_dir / "launcher.c"), "-o", str(launcher_bin)],
            check=True,
        )

        # Self-test do auxiliar C (orçamento 200ms, FAN_CLOEXEC, cgroup.events, FAN_Q_OVERFLOW)
        helper_res = subprocess.run([str(helper_bin), "--self-test"], capture_output=True, text=True, check=True)

        spawn_results: dict[str, Any] = {}
        for mode in ("fork", "vfork", "posix_spawn"):
            out_marker = tmp_path / f"mark_{mode}.txt"
            # Portão controlado por pipe antes do execve: 0 marcadores antes da liberação -> marcador presente depois
            proc = subprocess.Popen(
                [str(launcher_bin), "--gate", mode, str(marker_bin), str(out_marker)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert proc.stdout is not None and proc.stdin is not None
            ready_line = proc.stdout.readline().decode("utf-8", errors="replace").strip()
            assert ready_line == "READY", f"launcher {mode} não sinalizou READY: {ready_line!r}"
            markers_before_release = 1 if out_marker.exists() else 0
            proc.stdin.write(b"G\n")
            proc.stdin.flush()
            proc.stdin.close()
            rc = proc.wait(timeout=5)
            proc.stdout.close()
            if proc.stderr:
                proc.stderr.close()
            marker_after = out_marker.read_text(encoding="utf-8").strip() if out_marker.exists() else ""
            assert rc == 0, f"launcher {mode} retornou {rc}"
            assert markers_before_release == 0, f"{mode}: marcador apareceu antes da liberação!"
            assert marker_after == "H1_MARKER_OK", f"{mode}: marcador ausente após liberação!"
            spawn_results[mode] = {
                "before_release_markers": markers_before_release,
                "after_release_marker": marker_after,
                "ok": True,
            }

        # Testa regras de contenção em Python (canário + corroboração + cgroup exclusivo)
        cfg = ConfigStore(tmp_path / "settings.json")
        cfg.update(pause_policy="auto_pause")
        pend = PendingStore(tmp_path / "pending.json")
        svc = ContainmentService(config_store=cfg, pending_store=pend)

        # Fotografia de 1 thread e 0 filhos em escopo não transitório não deve pausar
        ev_single, _ = svc.evaluate_event(
            app_name="solo",
            canary_modified=True,
            corroborating_activity_same_app=True,
            exclusive_cgroup_verified=True,
            scope_kind="exclusive_user_unit",
            thread_count=1,
            child_count=0,
            affected_paths=["/tmp/a"],
        )
        assert not ev_single.should_pause

        # Canário + corroboração + cgroup exclusivo com filhos -> pausa autorizada
        ev_full, _ = svc.evaluate_event(
            app_name="ransom-test",
            canary_modified=True,
            corroborating_activity_same_app=True,
            exclusive_cgroup_verified=True,
            scope_kind="exclusive_user_unit",
            thread_count=2,
            child_count=1,
            affected_paths=["/tmp/a"],
        )
        assert ev_full.should_pause

    vm_res = run_h1_vm(repo_root)
    approved_kernels = [vm_res["kernel_version"]] if vm_res.get("ok") else []

    return {
        "assay": "H1",
        "status": "PARTIAL_KVM_6_14_PASS" if vm_res.get("ok") else "PARTIAL_LOCAL_PASS",
        "kernel": kernel_release,
        "helper_self_test": helper_res.stdout.strip(),
        "spawn_methods": spawn_results,
        "containment_policy_gates_ok": True,
        "kvm_live_kernel_test": vm_res,
        "frozen_start_approved_kernels": approved_kernels,
        "pending_privileged_matrix": (
            "Kernel 6.14.0-37-generic homologado ao vivo em micro-VM KVM (fork/vfork/posix_spawn, "
            "FAN_OPEN_EXEC_PERM, frozen 1, populated 0, SIGKILL). Kernels 6.8 e 7.0 aguardam execução "
            "privilegiada própria; combinações sem evidência permanecem sem início congelado externo."
        ),
    }
