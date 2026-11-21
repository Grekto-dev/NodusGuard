"""Módulo 6: Prevenção de exploração, Navegador Isolado (bubblewrap) e Modo Banco."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Any

from mintsec.contracts import (
    ModuleManifest,
    ModuleState,
    ModuleStatus,
    atomic_write_json,
    read_json_safe,
    xdg_dir,
)
from mintsec.formatting import now_iso
from mintsec.runner import SubprocessRunner
from mintsec.services.base import ModuleService

X11_WARNING = (
    "Aviso do modelo de segurança do X11: na mesma sessão gráfica X11, outros "
    "aplicativos do mesmo usuário podem observar eventos de teclado e janela. "
    "Para isolamento de sessão gráfica separada, o Modo Banco permanece experimental até H7."
)


class IsolationService(ModuleService):
    """Gerencia atualizações do Mint, AppArmor, Navegador Isolado (bwrap) e Modo Banco."""

    def __init__(
        self,
        *,
        manifest: ModuleManifest,
        config_store: Any,
        pending_store: Any,
        history_store: Any,
        package_inspector: Any = None,
        runner: Any = None,
        authorizer: Any = None,
        data_dir: Path | None = None,
        apparmor_profiles_path: Path | None = None,
    ) -> None:
        super().__init__(
            manifest=manifest,
            config_store=config_store,
            pending_store=pending_store,
            history_store=history_store,
            package_inspector=package_inspector,
            runner=runner,
            authorizer=authorizer,
        )
        self.data_dir = data_dir or xdg_dir("XDG_DATA_HOME", ".local/share")
        self.state_path = self.data_dir / "isolation_state.json"
        self.apparmor_profiles_path = apparmor_profiles_path or Path(
            "/sys/kernel/security/apparmor/profiles"
        )

    def _load_state(self) -> dict[str, Any]:
        return read_json_safe(
            self.state_path,
            default={
                "enabled": False,
                "last_confirmed_at": None,
                "bank_mode_approved_h7": False,
            },
        )

    def _save_state(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.state_path, data, mode=0o600)

    def read_apparmor_enforcing(self) -> dict[str, Any]:
        """Lê perfis AppArmor em aplicação a partir do kernel ou aa-status."""
        if self.apparmor_profiles_path.exists():
            try:
                lines = self.apparmor_profiles_path.read_text(encoding="utf-8", errors="replace").splitlines()
                enforce = sum(1 for ln in lines if ln.strip().endswith("(enforce)"))
                complain = sum(1 for ln in lines if ln.strip().endswith("(complain)"))
                return {
                    "available": True,
                    "enforce_count": enforce,
                    "complain_count": complain,
                    "total": len(lines),
                }
            except OSError:
                pass
        if isinstance(self.runner, SubprocessRunner) and os.geteuid() != 0:
            return {"available": False, "enforce_count": 0, "complain_count": 0, "total": 0}
        aa_bin = self.runner.which("aa-status")
        if aa_bin:
            res = self.runner.run([aa_bin, "--json"], timeout=5.0)
            if res.returncode == 0 and res.stdout.strip():
                return {"available": True, "raw": res.stdout[:400], "enforce_count": None}
        return {"available": False, "enforce_count": 0, "complain_count": 0, "total": 0}

    def check_mint_updates(self) -> dict[str, Any]:
        """Consulta atualizações pendentes do Linux Mint sem alterar pacotes."""
        cli = self.runner.which("mintupdate-cli")
        if not cli:
            return {"available": False, "pending_count": None, "security_count": None}
        res = self.runner.run([cli, "list"], timeout=15.0)
        if res.returncode != 0:
            return {"available": False, "pending_count": None, "error": res.stderr.strip()}
        lines = [ln for ln in res.stdout.splitlines() if ln.strip()]
        sec = sum(1 for ln in lines if "security" in ln.lower() or "segurança" in ln.lower())
        return {"available": True, "pending_count": len(lines), "security_count": sec}

    def detect_browser_command(self) -> list[str] | None:
        """Identifica navegador instalado para execução com bubblewrap."""
        for candidate in ("firefox", "chromium", "chromium-browser", "google-chrome", "brave-browser"):
            found = self.runner.which(candidate)
            if found:
                if candidate == "firefox":
                    return [found, "--no-remote"]
                return [found]
        return None

    def build_bwrap_command(
        self,
        *,
        browser_cmd: list[str],
        profile_dir: Path,
        allow_x11: bool = True,
    ) -> list[str]:
        """Monta linha de comando bubblewrap com perfil temporário e isolamento de PID/sessão."""
        bwrap_bin = self.runner.which("bwrap") or "/usr/bin/bwrap"
        cmd = [
            bwrap_bin,
            "--unshare-pid",
            "--unshare-uts",
            "--unshare-ipc",
            "--cap-drop",
            "ALL",
            "--new-session",
            "--die-with-parent",
            "--ro-bind", "/usr", "/usr",
            "--ro-bind", "/etc", "/etc",
            "--symlink", "usr/lib", "/lib",
            "--symlink", "usr/bin", "/bin",
            "--symlink", "usr/sbin", "/sbin",
            "--dev", "/dev",
            "--proc", "/proc",
            "--tmpfs", "/tmp",
            "--tmpfs", "/run",
            "--dir", str(profile_dir),
            "--bind", str(profile_dir), str(profile_dir),
            "--setenv", "HOME", str(profile_dir),
        ]
        if Path("/lib64").exists():
            cmd.extend(["--symlink", "usr/lib64", "/lib64"])
        if allow_x11 and os.environ.get("DISPLAY"):
            cmd.extend([
                "--ro-bind-try", "/tmp/.X11-unix", "/tmp/.X11-unix",
                "--setenv", "DISPLAY", os.environ["DISPLAY"],
            ])
        cmd.append("--")
        cmd.extend(browser_cmd)
        if browser_cmd and "firefox" in Path(browser_cmd[0]).name:
            cmd.extend(["--profile", str(profile_dir)])
        elif browser_cmd and ("chrom" in Path(browser_cmd[0]).name or "brave" in Path(browser_cmd[0]).name):
            cmd.append(f"--user-data-dir={profile_dir}")
        return cmd

    def smoke_test_bwrap(self) -> dict[str, Any]:
        """Executa smoke test real e inofensivo com bubblewrap sem privilégios."""
        bwrap_bin = self.runner.which("bwrap")
        if not bwrap_bin:
            return {"ok": False, "error": "bubblewrap não instalado."}
        with tempfile.TemporaryDirectory(prefix="mintsec-bwrap-smoke-") as tmp_prof:
            prof = Path(tmp_prof)
            cmd = self.build_bwrap_command(
                browser_cmd=["/bin/sh", "-c", "echo bwrap_ok && ls / >/dev/null"],
                profile_dir=prof,
                allow_x11=False,
            )
            res = self.runner.run(cmd, timeout=10.0)
            return {
                "ok": res.returncode == 0 and "bwrap_ok" in res.stdout,
                "returncode": res.returncode,
                "stdout": res.stdout.strip(),
                "stderr": res.stderr.strip(),
            }

    def build_bank_mode_spec(self, *, origin_vt: int = 7, bank_vt: int = 8) -> dict[str, Any]:
        """Especificação de Modo Banco em conta/servidor gráfico separados (experimental até H7)."""
        state = self._load_state()
        return {
            "experimental": not bool(state.get("bank_mode_approved_h7", False)),
            "separate_user": "mintsec-bank",
            "launcher": "mint-security-bank-mode",
            "origin_vt": origin_vt,
            "bank_vt": bank_vt,
            "gpu_drivers_matrix": ["intel-legacy", "nouveau", "modesetting"],
            "audio_isolation": "pulse/pipewire-isolated-socket",
            "return_command": ["chvt", str(origin_vt)],
            "status_note": "Permanece experimental até conclusão da homologação gráfica H7.",
        }

    def run_bank_mode_nested_test(self) -> dict[str, Any]:
        """Executa validação aninhada real do lançador do Modo Banco via Xephyr."""
        repo_bin = Path(__file__).resolve().parents[3] / "bin/mint-security-bank-mode"
        launcher = str(repo_bin) if repo_bin.is_file() else (self.runner.which("mint-security-bank-mode") or "")
        if not launcher:
            return {"ok": False, "error": "Lançador mint-security-bank-mode não encontrado."}
        res = self.runner.run([launcher, "--test-nested"], timeout=20.0)
        return {
            "ok": res.returncode == 0 and "BANK_NESTED_OK" in res.stdout,
            "stdout": res.stdout.strip(),
            "stderr": res.stderr.strip(),
        }

    def query_status(self) -> ModuleStatus:
        bwrap_info = self.package_inspector.inspect_package("bubblewrap", binaries=["bwrap"])
        aa_info = self.package_inspector.inspect_package("apparmor", binaries=["aa-status"])
        aa_runtime = self.read_apparmor_enforcing()
        state = self._load_state()
        browser_cmd = self.detect_browser_command()

        if not bwrap_info.installed:
            return self.build_status(
                state=ModuleState.AUSENTE,
                installed_version=None,
                package_origin="Não instalado",
                mode_summary="bubblewrap não instalado",
                evidence="Instale bubblewrap para habilitar o Navegador Isolado.",
                details={
                    "x11_warning": X11_WARNING,
                    "apparmor": aa_runtime,
                    "bank_mode": self.build_bank_mode_spec(),
                },
            )

        enabled = bool(state.get("enabled", False)) or self._module_enabled_flag(False)
        mod_state = ModuleState.ATIVO if enabled else ModuleState.DESATIVADO
        enforce_n = aa_runtime.get("enforce_count")
        aa_txt = f"{enforce_n} perfis AppArmor em aplicação" if enforce_n is not None else "AppArmor presente"

        return self.build_status(
            state=mod_state,
            installed_version=bwrap_info.version,
            package_origin=bwrap_info.origin,
            mode_summary=f"Navegador Isolado pronto · {aa_txt} · Modo Banco experimental",
            evidence=X11_WARNING,
            last_confirmed_at=state.get("last_confirmed_at"),
            details={
                "x11_warning": X11_WARNING,
                "apparmor": aa_runtime,
                "apparmor_package_origin": aa_info.origin,
                "browser_available": browser_cmd is not None,
                "browser_cmd": browser_cmd,
                "bank_mode": self.build_bank_mode_spec(),
            },
        )

    def configure(self, **options: Any) -> ModuleStatus:
        return self.query_status()

    def enable(self, **options: Any) -> ModuleStatus:
        state = self._load_state()
        state["enabled"] = True
        state["last_confirmed_at"] = now_iso()
        self._save_state(state)
        self._set_module_enabled_flag(True)
        return self.query_status()

    def disable(self, *, revert_suite_changes: bool = False) -> ModuleStatus:
        state = self._load_state()
        state["enabled"] = False
        self._save_state(state)
        self._set_module_enabled_flag(False)
        return self.query_status()
