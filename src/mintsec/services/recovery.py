"""Módulo 3: Ransomware e recuperação (Timeshift, restic e incidentes)."""

from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from dataclasses import asdict, dataclass
from datetime import datetime
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
from mintsec.formatting import now_iso, parse_timestamp
from mintsec.incident import IncidentManager, PreservedItem
from mintsec.runner import SubprocessRunner
from mintsec.services.base import ModuleService

VALID_REPO_TYPES = {"local", "removable_offline", "append_only_remote"}
_SNAPSHOT_ID_RE = re.compile(r"^[0-9a-fA-F]{6,64}$")


def _validate_repo_path(repo_path: str) -> str:
    clean = str(repo_path).strip()
    if not clean or clean.startswith("-") or "\r" in clean or "\n" in clean or "\0" in clean:
        raise ValueError(f"Caminho de repositório restic inválido: {repo_path}")
    return clean


def _validate_snapshot_id(snapshot_id: str) -> str:
    clean = str(snapshot_id).strip()
    if clean != "latest" and not _SNAPSHOT_ID_RE.match(clean):
        raise ValueError(f"Identificador de instantâneo restic inválido: {snapshot_id}")
    return clean


@dataclass
class TimeshiftSnapshot:
    """Ponto de restauração do sistema identificado no Timeshift."""

    name: str
    created_at: str
    tags: str
    comments: str
    mode: str  # 'btrfs' | 'rsync'

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class ResticSnapshot:
    """Instantâneo cifrado de arquivos pessoais em repositório restic."""

    snapshot_id: str
    short_id: str
    created_at: str
    paths: list[str]
    hostname: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class RecoveryService(ModuleService):
    """Gerencia pontos do sistema Timeshift, cópias cifradas restic e restauração segura."""

    def __init__(
        self,
        *,
        manifest: ModuleManifest,
        config_store: Any,
        pending_store: Any,
        history_store: Any,
        incident_manager: IncidentManager | None = None,
        package_inspector: Any = None,
        runner: Any = None,
        authorizer: Any = None,
        data_dir: Path | None = None,
        timeshift_conf_path: Path | None = None,
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
        self.state_path = self.data_dir / "recovery_state.json"
        self.timeshift_conf_path = timeshift_conf_path or Path("/etc/timeshift/timeshift.json")
        self.incident_manager = incident_manager or IncidentManager()

    def _load_state(self) -> dict[str, Any]:
        return read_json_safe(
            self.state_path,
            default={
                "enabled": False,
                "repo_path": "",
                "repo_type": "removable_offline",
                "separate_maintenance_credential": False,
                "include_paths": [],
                "schedule_days": 7,
                "last_backup_at": None,
                "last_restore_test_at": None,
                "last_restore_test_result": None,
            },
        )

    def _save_state(self, data: dict[str, Any]) -> None:
        atomic_write_json(self.state_path, data, mode=0o600)

    def _restic_env(self, password: str | None) -> dict[str, str]:
        env = dict(os.environ)
        if password is not None:
            env["RESTIC_PASSWORD"] = password
        return env

    def _inspect_timeshift(self) -> dict[str, Any]:
        ts_info = self.package_inspector.inspect_package("timeshift", binaries=["timeshift"])
        mode = "desconhecido"
        configured = False
        if self.timeshift_conf_path.exists():
            try:
                raw = json.loads(self.timeshift_conf_path.read_text(encoding="utf-8"))
                configured = True
                mode = "btrfs" if raw.get("btrfs_mode", "false") == "true" else "rsync"
            except Exception:
                pass

        snapshots: list[TimeshiftSnapshot] = []
        ts_bin = self.runner.which("timeshift")
        # timeshift --list exige root no host real; evita subprocesso fadado a erro sem elevação
        if ts_bin and ts_info.installed and not (isinstance(self.runner, SubprocessRunner) and os.geteuid() != 0):
            res = self.runner.run([ts_bin, "--list"], timeout=10.0)
            if res.returncode == 0:
                snapshots = self._parse_timeshift_list(res.stdout, mode)

        return {
            "installed": ts_info.installed,
            "version": ts_info.version,
            "origin": ts_info.origin,
            "configured": configured,
            "mode": mode,
            "snapshots": [s.to_dict() for s in snapshots],
        }

    @staticmethod
    def _parse_timeshift_list(output: str, mode: str) -> list[TimeshiftSnapshot]:
        snapshots: list[TimeshiftSnapshot] = []
        pattern = re.compile(r"^\d+\s+>\s+(\S+)\s+(\S+)\s*(.*)$")
        for line in output.splitlines():
            match = pattern.match(line.strip())
            if not match:
                continue
            name, tags, comments = match.groups()
            snapshots.append(
                TimeshiftSnapshot(
                    name=name,
                    created_at=name,
                    tags=tags,
                    comments=comments.strip(),
                    mode=mode,
                )
            )
        return snapshots

    def is_backup_overdue(self, state_data: dict[str, Any] | None = None) -> bool:
        """Indica se a última cópia ultrapassou a agenda configurada."""
        data = state_data or self._load_state()
        repo_path = str(data.get("repo_path", "")).strip()
        if not repo_path:
            return True
        last_dt = parse_timestamp(data.get("last_backup_at"))
        if last_dt is None:
            return True
        schedule_days = max(1, int(data.get("schedule_days", 7)))
        elapsed_days = (datetime.now().astimezone() - last_dt).total_seconds() / 86400.0
        return elapsed_days > schedule_days

    def query_status(self) -> ModuleStatus:
        timeshift_data = self._inspect_timeshift()
        restic_info = self.package_inspector.inspect_package("restic", binaries=["restic"])
        state_data = self._load_state()
        repo_path = str(state_data.get("repo_path", "")).strip()
        needs_setup = not bool(repo_path)

        installed_any = timeshift_data["installed"] or restic_info.installed
        if not installed_any:
            return self.build_status(
                state=ModuleState.AUSENTE,
                installed_version=None,
                package_origin="Não instalado",
                mode_summary="Timeshift e restic não instalados",
                evidence="Pacotes timeshift e restic ausentes.",
                needs_setup=True,
                details={
                    "timeshift": timeshift_data,
                    "restic": {
                        "installed": False,
                        "version": None,
                        "origin": "Não instalado",
                        "config": state_data,
                    },
                },
            )

        version_parts = []
        if timeshift_data["installed"]:
            version_parts.append(f"Timeshift {timeshift_data['version']}")
        if restic_info.installed:
            version_parts.append(f"restic {restic_info.version}")
        combined_version = " · ".join(version_parts)
        origin = restic_info.origin if restic_info.installed else timeshift_data["origin"]

        enabled = bool(state_data.get("enabled", False)) or self._module_enabled_flag(False)
        if not enabled and needs_setup:
            mod_state = ModuleState.DESATIVADO
            mode_summary = "Cópia pessoal ainda precisa de destino"
            evidence = "Escolha o destino das cópias pessoais em Recuperação."
        elif not enabled:
            mod_state = ModuleState.DESATIVADO
            mode_summary = "Cópias automáticas desativadas pelo usuário"
            evidence = "Repositório configurado, rotina automática desabilitada."
        elif not restic_info.installed:
            mod_state = ModuleState.DEGRADADO
            mode_summary = "Timeshift presente, restic ausente"
            evidence = "Instale o pacote restic para habilitar cópias pessoais cifradas."
        elif needs_setup:
            mod_state = ModuleState.DEGRADADO
            mode_summary = "Configurar destino de cópia"
            evidence = "Nenhum destino configurado para as cópias pessoais."
        elif self.is_backup_overdue(state_data):
            mod_state = ModuleState.DEGRADADO
            mode_summary = "Cópia pessoal atrasada"
            evidence = "Última cópia fora do intervalo da agenda configurada."
        else:
            mod_state = ModuleState.ATIVO
            mode_summary = f"Cópia restic em dia ({state_data.get('repo_type')})"
            evidence = "Cópia pessoal recente disponível para restauração."

        return self.build_status(
            state=mod_state,
            installed_version=combined_version,
            package_origin=origin,
            mode_summary=mode_summary,
            evidence=evidence,
            last_confirmed_at=state_data.get("last_backup_at"),
            degraded_reason=evidence if mod_state == ModuleState.DEGRADADO else None,
            needs_setup=needs_setup,
            details={
                "timeshift": timeshift_data,
                "restic": {
                    "installed": restic_info.installed,
                    "version": restic_info.version,
                    "origin": restic_info.origin,
                    "config": state_data,
                    "overdue": self.is_backup_overdue(state_data),
                },
            },
        )

    def configure(self, **options: Any) -> ModuleStatus:
        state_data = self._load_state()
        if "repo_path" in options:
            raw_repo = str(options["repo_path"]).strip()
            state_data["repo_path"] = _validate_repo_path(raw_repo) if raw_repo else ""
        if "repo_type" in options:
            rtype = str(options["repo_type"])
            if rtype not in VALID_REPO_TYPES:
                raise ValueError(f"Tipo de destino inválido: {rtype}")
            state_data["repo_type"] = rtype
        if "separate_maintenance_credential" in options:
            state_data["separate_maintenance_credential"] = bool(options["separate_maintenance_credential"])
        if "include_paths" in options:
            state_data["include_paths"] = [str(p) for p in options["include_paths"]]
        if "schedule_days" in options:
            state_data["schedule_days"] = max(1, int(options["schedule_days"]))
        self._save_state(state_data)
        self.record_event(
            action="Política de cópias atualizada",
            reason=f"Destino {state_data.get('repo_path') or 'não definido'} ({state_data.get('repo_type')}).",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
        )
        return self.query_status()

    def enable(self, **options: Any) -> ModuleStatus:
        if options:
            self.configure(**options)
        state_data = self._load_state()
        state_data["enabled"] = True
        self._save_state(state_data)
        self._set_module_enabled_flag(True)
        self.record_event(
            action="Proteção de cópias habilitada",
            reason="Agenda e política de recuperação ativadas.",
            confirmation_state="confirmed",
            actor="user",
            reversible=True,
        )
        return self.query_status()

    def disable(self, *, revert_suite_changes: bool = False) -> ModuleStatus:
        state_data = self._load_state()
        state_data["enabled"] = False
        # Preservar sempre as cópias existentes e histórico do repositório!
        if revert_suite_changes:
            state_data["schedule_days"] = 7
        self._save_state(state_data)
        self._set_module_enabled_flag(False)
        self.record_event(
            action="Agendamento de cópias desativado",
            reason="Cópias existentes no repositório foram preservadas.",
            confirmation_state="confirmed",
            actor="user",
        )
        return self.query_status()

    def _require_restic(self) -> tuple[str, dict[str, Any]]:
        restic_bin = self.runner.which("restic")
        if not restic_bin:
            raise FileNotFoundError("Binário restic não encontrado no sistema.")
        state_data = self._load_state()
        raw_repo = str(state_data.get("repo_path", "")).strip()
        if not raw_repo:
            raise ValueError("Configure o destino do repositório restic antes de executar esta operação.")
        state_data["repo_path"] = _validate_repo_path(raw_repo)
        return restic_bin, state_data

    def init_repository(self, *, password: str) -> dict[str, Any]:
        """Inicializa repositório restic cifrado."""
        restic_bin, state_data = self._require_restic()
        res = self.runner.run(
            [restic_bin, "-r", state_data["repo_path"], "init"],
            env=self._restic_env(password),
            timeout=60.0,
        )
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao inicializar repositório restic: {res.stderr.strip()}")
        self.record_event(
            action="Repositório restic inicializado",
            reason=f"Destino {state_data['repo_path']} preparado com cifra.",
            confirmation_state="confirmed",
            actor="user",
        )
        return {"ok": True, "repo_path": state_data["repo_path"]}

    def backup_now(self, *, password: str) -> dict[str, Any]:
        """Executa cópia pessoal restic agora, atualizando apenas last_backup_at."""
        restic_bin, state_data = self._require_restic()
        paths = state_data.get("include_paths") or [str(Path.home() / "Documents")]
        argv = [restic_bin, "-r", state_data["repo_path"], "backup", "--json", "--", *paths]
        res = self.runner.run(argv, env=self._restic_env(password), timeout=600.0)
        if res.returncode != 0:
            self.record_event(
                action="Falha na cópia pessoal",
                reason=res.stderr.strip() or "Erro ao executar restic backup.",
                confirmation_state="failed",
                actor="user",
            )
            raise RuntimeError(f"Falha na cópia restic: {res.stderr.strip()}")

        completed_at = now_iso()
        state_data["last_backup_at"] = completed_at
        self._save_state(state_data)
        self.record_event(
            action="Cópia pessoal concluída",
            reason=f"Arquivos salvos em {state_data['repo_path']}.",
            confirmation_state="confirmed",
            actor="user",
            evidence=f"Incluídos: {', '.join(paths)}",
        )
        return {"ok": True, "completed_at": completed_at, "stdout": res.stdout}

    def list_snapshots(self, *, password: str) -> list[ResticSnapshot]:
        """Lista instantâneos disponíveis no repositório restic."""
        restic_bin, state_data = self._require_restic()
        res = self.runner.run(
            [restic_bin, "-r", state_data["repo_path"], "snapshots", "--json"],
            env=self._restic_env(password),
            timeout=30.0,
        )
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao listar cópias: {res.stderr.strip()}")
        raw_items = json.loads(res.stdout or "[]")
        return [
            ResticSnapshot(
                snapshot_id=str(item.get("id", "")),
                short_id=str(item.get("short_id", str(item.get("id", ""))[:8])),
                created_at=str(item.get("time", "")),
                paths=list(item.get("paths", [])),
                hostname=str(item.get("hostname", "")),
            )
            for item in raw_items
        ]

    def list_snapshot_files(self, snapshot_id: str, *, password: str) -> list[str]:
        """Lista arquivos contidos em um instantâneo específico."""
        clean_id = _validate_snapshot_id(snapshot_id)
        restic_bin, state_data = self._require_restic()
        res = self.runner.run(
            [restic_bin, "-r", state_data["repo_path"], "ls", "--json", clean_id],
            env=self._restic_env(password),
            timeout=30.0,
        )
        if res.returncode != 0:
            raise RuntimeError(f"Falha ao listar arquivos do instantâneo: {res.stderr.strip()}")
        files: list[str] = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            if obj.get("type") == "file" and obj.get("path"):
                files.append(str(obj["path"]))
        return files

    def test_restore(self, *, password: str, sample_path: str | None = None) -> dict[str, Any]:
        """Executa restic check e restaura uma amostra temporária, atualizando last_restore_test_at."""
        restic_bin, state_data = self._require_restic()
        env = self._restic_env(password)

        check_res = self.runner.run(
            [restic_bin, "-r", state_data["repo_path"], "check"],
            env=env,
            timeout=120.0,
        )
        if check_res.returncode != 0:
            state_data["last_restore_test_at"] = now_iso()
            state_data["last_restore_test_result"] = f"Falha na verificação: {check_res.stderr.strip()}"
            self._save_state(state_data)
            raise RuntimeError(state_data["last_restore_test_result"])

        snapshots = self.list_snapshots(password=password)
        if not snapshots:
            raise RuntimeError("Nenhuma cópia disponível para testar a restauração.")
        latest = snapshots[-1]
        snap_id = _validate_snapshot_id(latest.snapshot_id)

        with tempfile.TemporaryDirectory(prefix="mintsec-restore-test-") as tmpdir:
            argv = [
                restic_bin,
                "-r",
                state_data["repo_path"],
                "restore",
                snap_id,
                "--target",
                tmpdir,
            ]
            if sample_path:
                argv.extend(["--include", sample_path])
            restore_res = self.runner.run(argv, env=env, timeout=120.0)
            if restore_res.returncode != 0:
                raise RuntimeError(f"Falha ao testar restauração: {restore_res.stderr.strip()}")

            restored_files = [p for p in Path(tmpdir).rglob("*") if p.is_file()]
            if not restored_files:
                raise RuntimeError("Teste de restauração concluiu sem arquivos restaurados.")
            # Confirma leitura do arquivo restaurado
            with restored_files[0].open("rb") as handle:
                handle.read(64)

        tested_at = now_iso()
        state_data["last_restore_test_at"] = tested_at
        state_data["last_restore_test_result"] = f"Aprovado ({len(restored_files)} arquivo(s) conferido(s))"
        self._save_state(state_data)
        self.record_event(
            action="Teste de restauração concluído",
            reason=state_data["last_restore_test_result"],
            confirmation_state="confirmed",
            actor="user",
            evidence=f"Instantâneo {latest.short_id}",
        )
        return {
            "ok": True,
            "tested_at": tested_at,
            "snapshot_id": latest.snapshot_id,
            "files_verified": len(restored_files),
            "result": state_data["last_restore_test_result"],
        }

    def restore_files(
        self,
        *,
        snapshot_id: str,
        paths: list[str],
        destination_dir: Path | None = None,
        password: str,
        overwrite_original: bool = False,
        incident_id: str | None = None,
        app_paused_or_stopped: bool = False,
        caller_uid: int | None = None,
        simulate_interrupt: bool = False,
    ) -> dict[str, Any]:
        """Restaura arquivos em outra pasta ou sobrescreve originais após preservar fora de $HOME."""
        if not paths:
            raise ValueError("Selecione ao menos um arquivo para restaurar.")
        clean_snap_id = _validate_snapshot_id(snapshot_id)
        for item_path in paths:
            raw_p = str(item_path)
            if not raw_p or "\r" in raw_p or "\n" in raw_p or "\0" in raw_p or ".." in Path(raw_p).parts:
                raise ValueError(f"Caminho inválido para restauração: {item_path}")
        restic_bin, state_data = self._require_restic()
        env = self._restic_env(password)

        if not overwrite_original:
            if destination_dir is None:
                raise ValueError("Informe a pasta de destino para restauração separada.")
            dest = Path(destination_dir)
            dest.mkdir(parents=True, exist_ok=True)
            argv = [restic_bin, "-r", state_data["repo_path"], "restore", clean_snap_id, "--target", str(dest)]
            for item_path in paths:
                argv.extend(["--include", item_path])
            res = self.runner.run(argv, env=env, timeout=300.0)
            if res.returncode != 0:
                raise RuntimeError(f"Falha ao restaurar arquivos: {res.stderr.strip()}")
            self.record_event(
                action="Arquivos restaurados em pasta separada",
                reason=f"Destino escolhido: {dest}",
                confirmation_state="confirmed",
                actor="user",
                evidence=f"Instantâneo {clean_snap_id[:8]} · {len(paths)} caminho(s)",
            )
            return {
                "ok": True,
                "mode": "separate_folder",
                "destination_dir": str(dest),
                "paths": paths,
            }

        # Sobrescrita durante incidente exige pausa/encerramento do aplicativo afetado + confirmação
        if not app_paused_or_stopped:
            raise PermissionError(
                "Para sobrescrever arquivos originais durante um incidente, confirme que o aplicativo "
                "está pausado ou encerrado."
            )
        if not incident_id:
            raise ValueError("Identificador do incidente é obrigatório para preservar originais antes da sobrescrita.")

        self.authorizer.require("org.mintsecurity.recovery.overwrite", caller_uid=caller_uid)

        preserved_items: list[PreservedItem] = []
        with tempfile.TemporaryDirectory(prefix="mintsec-stage-") as stage_dir:
            argv = [restic_bin, "-r", state_data["repo_path"], "restore", clean_snap_id, "--target", stage_dir]
            for item_path in paths:
                argv.extend(["--include", item_path])
            res = self.runner.run(argv, env=env, timeout=300.0)
            if res.returncode != 0:
                raise RuntimeError(f"Falha ao preparar versão restaurada: {res.stderr.strip()}")

            stage_root = Path(stage_dir)
            stage_root_res = stage_root.resolve()
            for orig_str in paths:
                orig_path = Path(orig_str)
                rel = orig_path.relative_to("/") if orig_path.is_absolute() else orig_path
                staged_file = stage_root / rel
                staged_res = staged_file.resolve()
                if not staged_res.is_relative_to(stage_root_res):
                    raise PermissionError(f"Caminho escapa do diretório de preparo: {orig_str}")
                if not staged_file.exists():
                    raise FileNotFoundError(f"Arquivo esperado ausente no estágio de restauração: {staged_file}")
                if orig_path.is_symlink():
                    raise PermissionError(f"Destino de restauração não pode ser symlink: {orig_path}")
                if orig_path.exists():
                    item = self.incident_manager.prepare_and_overwrite(
                        target_path=orig_path,
                        restored_source_path=staged_file,
                        incident_id=incident_id,
                        simulate_interrupt_after_preserve=simulate_interrupt,
                    )
                    preserved_items.append(item)
                else:
                    orig_path.parent.mkdir(parents=True, exist_ok=True)
                    fd, tmp_name = tempfile.mkstemp(prefix=".mintsec-restore-", suffix=".tmp", dir=str(orig_path.parent))
                    tmp_dest = Path(tmp_name)
                    try:
                        with staged_file.open("rb") as src_h, os.fdopen(fd, "wb") as dst_h:
                            shutil.copyfileobj(src_h, dst_h, length=65536)
                            dst_h.flush()
                            os.fsync(dst_h.fileno())
                        os.chmod(tmp_dest, 0o600)
                        os.replace(tmp_dest, orig_path)
                    except Exception:
                        tmp_dest.unlink(missing_ok=True)
                        raise

        self.record_event(
            action="Originais substituídos com preservação de incidente",
            reason=f"Versões anteriores preservadas fora de $HOME no incidente {incident_id}.",
            confirmation_state="confirmed",
            actor="user",
            evidence=f"{len(preserved_items)} arquivo(s) preservado(s)",
        )
        return {
            "ok": True,
            "mode": "overwrite_with_incident_preserve",
            "incident_id": incident_id,
            "preserved_items": [item.to_dict() for item in preserved_items],
        }
