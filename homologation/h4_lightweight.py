"""Ensaio H4: medição de PSS, ociosidade, FDs e ciclo modular sem mutação do sistema."""

from __future__ import annotations

import os
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from mintsec.config import ConfigStore
from mintsec.contracts import ModuleState
from mintsec.history import HistoryStore
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController


def _read_pss_kib(pid: int) -> int | None:
    smaps = Path(f"/proc/{pid}/smaps_rollup")
    if smaps.exists():
        for line in smaps.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1])
    status = Path(f"/proc/{pid}/status")
    if status.exists():
        for line in status.read_text(encoding="utf-8", errors="replace").splitlines():
            if line.startswith("VmRSS:"):
                return int(line.split()[1])
    return None


class _CycleFakeRunner:
    def __init__(self) -> None:
        self.installed = {"ufw", "timeshift"}

    def which(self, binary: str) -> str | None:
        if binary in self.installed:
            return f"/usr/bin/{binary}"
        if binary in ("clamscan", "freshclam") and "clamav" in self.installed:
            return f"/usr/bin/{binary}"
        return None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        if argv[0] == "dpkg-query":
            pkg = argv[-1]
            if pkg in self.installed or (pkg == "clamav-freshclam" and "clamav" in self.installed):
                return CommandResult(tuple(argv), 0, "install ok installed\t1.0.0\n", "")
            return CommandResult(tuple(argv), 1, "", "not installed")
        if argv[0] == "apt-cache":
            return CommandResult(tuple(argv), 0, " *** 1.0.0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n", "")
        if argv[0].endswith("clamscan"):
            if cancel_event is not None:
                cancel_event.set()
            return CommandResult(tuple(argv), -15, "", "", cancelled=True)
        return CommandResult(tuple(argv), 0, "", "")


def run_h4(repo_root: Path) -> dict[str, Any]:
    agent_bin = repo_root / "agent/target/release/mint-security-agent"
    agent_pss_kib: int | None = None
    agent_fds: int | None = None

    with tempfile.TemporaryDirectory(prefix="mintsec-h4-") as tmp:
        tmp_path = Path(tmp)
        env = dict(os.environ)
        env["XDG_STATE_HOME"] = str(tmp_path / "state")
        # Mede PSS e FDs reais do agente Rust em sessão D-Bus isolada
        if agent_bin.is_file():
            proc = subprocess.Popen(
                ["dbus-run-session", "--", str(agent_bin)],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                env=env,
            )
            try:
                time.sleep(0.5)
                # Localiza o filho mint-security-agent dentro da sessão dbus-run-session
                child_pid = proc.pid
                for p in Path("/proc").iterdir():
                    if not p.name.isdigit():
                        continue
                    try:
                        comm = (p / "comm").read_text(encoding="utf-8").strip()
                        stat_ppid = int((p / "stat").read_text(encoding="utf-8").split()[3])
                        if stat_ppid == proc.pid or comm == "mint-security-a":
                            child_pid = int(p.name)
                            break
                    except Exception:
                        continue
                agent_pss_kib = _read_pss_kib(child_pid)
                fd_dir = Path(f"/proc/{child_pid}/fd")
                if fd_dir.is_dir():
                    agent_fds = len(list(fd_dir.iterdir()))
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

        # Mede ciclo modular instalar -> ativar -> desativar -> remover -> reinstalar + trabalho interrompido
        runner = _CycleFakeRunner()
        ctrl = SuiteController(
            config_store=ConfigStore(tmp_path / "settings.json"),
            pending_store=PendingStore(tmp_path / "pending.json"),
            history_store=HistoryStore(tmp_path / "history.db"),
            runner=runner,
            data_dir=tmp_path / "data",
        )
        assert ctrl.antimalware.query_status().state == ModuleState.AUSENTE
        runner.installed.add("clamav")
        assert ctrl.antimalware.query_status().state == ModuleState.DESATIVADO
        ctrl.antimalware.enable()
        scan_res = ctrl.antimalware.run_scan(scope="custom", paths=[str(tmp_path)], cancel_event=threading.Event())
        assert scan_res.incomplete and ctrl.antimalware.query_status().state == ModuleState.VERIFICACAO_INCOMPLETA
        ctrl.antimalware.disable(revert_suite_changes=True)
        runner.installed.remove("clamav")
        assert ctrl.antimalware.query_status().state == ModuleState.AUSENTE
        runner.installed.add("clamav")
        assert ctrl.antimalware.query_status().state == ModuleState.DESATIVADO

    self_pss_kib = _read_pss_kib(os.getpid())
    return {
        "assay": "H4",
        "status": "PARTIAL_LOCAL_PASS",
        "agent_pss_kib": agent_pss_kib,
        "agent_open_fds": agent_fds,
        "python_controller_pss_kib": self_pss_kib,
        "modular_lifecycle_and_interrupted_incomplete_ok": True,
        "pending_hardware_matrix": "Medição de 2 e 4 GiB em HDD físico com backup inicial/incremental restic aguarda VM/hardware dedicado.",
    }
