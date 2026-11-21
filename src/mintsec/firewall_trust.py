"""Confiança pós-atualização, cache SHA-256, hooks APT e ponte OpenSnitch."""

from __future__ import annotations

import hashlib
import io
import os
import stat
import subprocess
import tarfile
import uuid
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from mintsec.contracts import atomic_write_json, read_json_safe, xdg_dir
from mintsec.formatting import now_iso
from mintsec.pending import PendingStore
from mintsec.runner import CommandRunner, SubprocessRunner


@dataclass(frozen=True)
class PathChainResult:
    """Resultado da validação da cadeia de diretórios até /."""

    safe: bool
    resolved_path: str
    reason: str


def verify_root_owned_path_chain(
    path: str | Path,
    *,
    allowed_uids: set[int] | None = None,
    stop_at_prefix: Path | None = None,
    _depth: int = 0,
    _expect_regular: bool = True,
) -> PathChainResult:
    """Confere que o executável e todos os diretórios até / pertencem a root e não são graváveis."""
    if _depth > 8:
        return PathChainResult(False, str(path), "Profundidade excessiva de links simbólicos.")

    raw = Path(path)
    if not raw.is_absolute():
        return PathChainResult(False, str(raw), "Caminho não é absoluto.")

    valid_uids = allowed_uids if allowed_uids is not None else {0}
    parts = raw.parts
    cur = Path("/")

    # Verifica '/' primeiro (a menos que um prefixo de teste isole /tmp)
    if stop_at_prefix is None:
        root_st = os.lstat(cur)
        if root_st.st_uid not in valid_uids or (root_st.st_mode & 0o022) != 0:
            return PathChainResult(False, str(raw), "Diretório raiz / não protegido contra escrita.")

    for idx in range(1, len(parts)):
        cur = cur / parts[idx]
        if stop_at_prefix is not None:
            # Em testes isolados dentro de /tmp, não exigir que / e /tmp (1777) passem check de grupo/outros
            try:
                cur.relative_to(stop_at_prefix)
                in_scope = True
            except ValueError:
                in_scope = False
            if not in_scope:
                continue

        try:
            st = os.lstat(cur)
        except OSError as exc:
            return PathChainResult(False, str(cur), f"Caminho inacessível: {exc}")

        if st.st_uid not in valid_uids:
            return PathChainResult(
                False,
                str(cur),
                f"Componente '{cur}' pertence ao UID {st.st_uid} (esperado root).",
            )
        if stat.S_ISLNK(st.st_mode):
            target = Path(os.path.realpath(cur))
            if not target.exists():
                return PathChainResult(False, str(cur), f"Symlink quebrado em '{cur}'.")
            target_st = os.lstat(target)
            if target_st.st_uid not in valid_uids or (target_st.st_mode & 0o022) != 0:
                return PathChainResult(
                    False,
                    str(target),
                    f"Destino do symlink '{cur}' -> '{target}' não está protegido.",
                )
            # Revalida toda a cadeia de diretórios do destino resolvido do symlink
            target_chain = verify_root_owned_path_chain(
                target,
                allowed_uids=allowed_uids,
                stop_at_prefix=stop_at_prefix,
                _depth=_depth + 1,
                _expect_regular=(idx == len(parts) - 1 and _expect_regular),
            )
            if not target_chain.safe:
                return target_chain
            continue

        if (st.st_mode & 0o022) != 0:
            return PathChainResult(
                False,
                str(cur),
                f"Componente '{cur}' possui permissão de escrita por grupo/outros ({oct(st.st_mode & 0o777)}).",
            )

    resolved = Path(os.path.realpath(raw))
    try:
        final_st = os.stat(resolved)
    except OSError as exc:
        return PathChainResult(False, str(resolved), f"Arquivo final inacessível: {exc}")

    if _expect_regular and not stat.S_ISREG(final_st.st_mode):
        return PathChainResult(False, str(resolved), "Alvo final não é um arquivo regular.")
    if final_st.st_uid not in valid_uids or (final_st.st_mode & 0o022) != 0:
        return PathChainResult(
            False,
            str(resolved),
            "Executável final não pertence a root ou é gravável por terceiros.",
        )

    return PathChainResult(True, str(resolved), "Cadeia até / protegida e pertencente a root.")


def is_dynamic_or_unverifiable(path: str | Path) -> bool:
    """Identifica código dinâmico, memfd, deletado ou script sem identidade binária estável."""
    raw_str = str(path)
    if not raw_str or "(deleted)" in raw_str or raw_str.startswith("/memfd:") or raw_str.startswith("memfd:"):
        return True
    p = Path(raw_str)
    if not p.is_file():
        return True
    try:
        with p.open("rb") as handle:
            head = handle.read(4)
    except OSError:
        return True
    if head.startswith(b"#!"):
        return True
    # Exige cabeçalho ELF para executáveis nativos com identidade verificável
    return head != b"\x7fELF"


class ExecutableIdentityCache:
    """Cache de SHA-256 indexado por (dev, ino, ctime_ns, size) para decisões < 5 ms."""

    def __init__(self) -> None:
        self._entries: dict[str, tuple[tuple[int, int, int, int], str]] = {}

    @staticmethod
    def stat_key(path: Path) -> tuple[int, int, int, int]:
        st = os.stat(path)
        return (int(st.st_dev), int(st.st_ino), int(st.st_ctime_ns), int(st.st_size))

    @staticmethod
    def compute_sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(65536):
                digest.update(chunk)
        return digest.hexdigest()

    def get_identity(self, path: str | Path) -> tuple[str, tuple[int, int, int, int], bool]:
        """Retorna (sha256, stat_key, cache_hit) evitando releitura em cache quente."""
        p = Path(path)
        key = self.stat_key(p)
        cached = self._entries.get(str(p))
        if cached is not None and cached[0] == key:
            return cached[1], key, True
        sha = self.compute_sha256(p)
        self._entries[str(p)] = (key, sha)
        return sha, key, False

    def invalidate(self, path: str | Path) -> None:
        self._entries.pop(str(path), None)

    def check_periodic_statx(self) -> list[str]:
        """Verificação periódica complementar por stat: lista caminhos alterados ou ausentes."""
        changed: list[str] = []
        for raw_path, (old_key, _sha) in list(self._entries.items()):
            try:
                cur_key = self.stat_key(Path(raw_path))
                if cur_key != old_key:
                    changed.append(raw_path)
            except OSError:
                changed.append(raw_path)
        return changed


@dataclass
class TrustRule:
    """Regra de confiança de aplicativo (por versão SHA-256 ou atualizações autenticadas)."""

    rule_id: str
    executable_path: str
    sha256: str
    stat_key: list[int]
    trust_mode: str  # 'version' | 'package_updates'
    approved_destinations: list[str]
    package_name: str | None = None
    package_origin: str | None = None
    active: bool = True
    revalidation_required: bool = False
    invalidated_reason: str | None = None
    created_at: str = field(default_factory=now_iso)
    updated_at: str = field(default_factory=now_iso)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> TrustRule:
        return cls(**data)


class TrustStore:
    """Armazena e valida regras de confiança vinculadas a SHA-256 e origem APT."""

    def __init__(
        self,
        path: Path | None = None,
        *,
        allowed_uids: set[int] | None = None,
        stop_at_prefix: Path | None = None,
        runner: CommandRunner | None = None,
    ) -> None:
        self.path = path or (xdg_dir("XDG_DATA_HOME", ".local/share") / "firewall_trust.json")
        self.allowed_uids = allowed_uids
        self.stop_at_prefix = stop_at_prefix
        self.runner = runner or SubprocessRunner()
        self.cache = ExecutableIdentityCache()
        self._rules_sig: tuple[int, int] | None = None
        self._rules_cache: list[dict[str, Any]] | None = None

    def _file_sig(self) -> tuple[int, int] | None:
        try:
            st = self.path.stat()
            return (st.st_mtime_ns, st.st_size)
        except OSError:
            return None

    def _load(self) -> list[TrustRule]:
        sig = self._file_sig()
        if sig is None:
            self._rules_sig = None
            self._rules_cache = None
            return []
        if self._rules_sig == sig and self._rules_cache is not None:
            return [TrustRule.from_dict(dict(r)) for r in self._rules_cache]
        raw = read_json_safe(self.path, default={"rules": []})
        raw_rules = [dict(r) for r in raw.get("rules", [])]
        self._rules_sig = sig
        self._rules_cache = raw_rules
        return [TrustRule.from_dict(r) for r in raw_rules]

    def _save(self, rules: list[TrustRule]) -> None:
        serialized = [r.to_dict() for r in rules]
        atomic_write_json(
            self.path,
            {"rules": serialized},
            mode=0o600,
        )
        self._rules_sig = self._file_sig()
        self._rules_cache = serialized if self._rules_sig is not None else None

    def list_rules(self) -> list[TrustRule]:
        return self._load()

    def remember_version(
        self,
        *,
        executable_path: str | Path,
        approved_destinations: list[str],
        trust_package_updates: bool = False,
        package_name: str | None = None,
        package_origin: str | None = None,
    ) -> TrustRule:
        """Registra 'Lembrar esta versão' e opcionalmente 'Confiar também nas atualizações deste pacote'."""
        p = Path(executable_path)
        chain = verify_root_owned_path_chain(
            p,
            allowed_uids=self.allowed_uids,
            stop_at_prefix=self.stop_at_prefix,
        )
        if not chain.safe:
            raise PermissionError(f"Caminho não seguro para persistir regra: {chain.reason}")
        if is_dynamic_or_unverifiable(p):
            raise ValueError("Código dinâmico ou script sem identidade ELF estática só admite decisão pontual.")
        if trust_package_updates and (not package_name or not package_origin):
            raise ValueError(
                "Confiar nas atualizações exige pacote e origem autenticada identificados."
            )

        sha, key, _ = self.cache.get_identity(p)
        mode = "package_updates" if trust_package_updates else "version"
        rule = TrustRule(
            rule_id=f"trust-{uuid.uuid4().hex[:8]}",
            executable_path=str(p),
            sha256=sha,
            stat_key=list(key),
            trust_mode=mode,
            approved_destinations=list(approved_destinations),
            package_name=package_name,
            package_origin=package_origin,
            active=True,
            revalidation_required=False,
        )
        rules = [r for r in self._load() if r.executable_path != str(p)]
        rules.append(rule)
        self._save(rules)
        return rule

    def evaluate_connection(self, executable_path: str | Path, destination: str) -> dict[str, Any]:
        """Decide conexão em cache quente validando SHA-256, cadeia até / e destino."""
        p = Path(executable_path)
        if is_dynamic_or_unverifiable(p):
            return {
                "decision": "prompt_once",
                "reason": "Código dinâmico sem identidade verificável só admite decisão pontual.",
                "cache_hit": False,
            }

        chain = verify_root_owned_path_chain(
            p,
            allowed_uids=self.allowed_uids,
            stop_at_prefix=self.stop_at_prefix,
        )
        if not chain.safe:
            return {
                "decision": "revalidate",
                "reason": chain.reason,
                "cache_hit": False,
            }

        rules = self._load()
        rule = next((r for r in rules if r.executable_path == str(p)), None)
        if rule is None:
            return {"decision": "prompt", "reason": "Sem regra salva para este executável.", "cache_hit": False}

        if not rule.active or rule.revalidation_required:
            return {
                "decision": "revalidate",
                "reason": rule.invalidated_reason or "Regra aguarda revalidação após atualização.",
                "cache_hit": False,
                "rule_id": rule.rule_id,
            }

        sha, _key, cache_hit = self.cache.get_identity(p)
        if sha != rule.sha256:
            # Troca externa ao APT ou divergência invalida imediatamente na primeira conexão
            rule.active = False
            rule.revalidation_required = True
            rule.invalidated_reason = "SHA-256 do executável mudou fora do fluxo esperado."
            rule.updated_at = now_iso()
            self._save(rules)
            return {
                "decision": "revalidate",
                "reason": rule.invalidated_reason,
                "cache_hit": cache_hit,
                "rule_id": rule.rule_id,
            }

        if "*" not in rule.approved_destinations and destination not in rule.approved_destinations:
            return {
                "decision": "prompt",
                "reason": f"Destino {destination} fora dos destinos aprovados ({rule.approved_destinations}).",
                "cache_hit": cache_hit,
                "rule_id": rule.rule_id,
            }

        return {
            "decision": "allow",
            "reason": f"Autorizado por regra '{rule.trust_mode}' com SHA-256 conferido.",
            "cache_hit": cache_hit,
            "rule_id": rule.rule_id,
        }

    def dpkg_verify_diagnostic(self, package_name: str) -> dict[str, Any]:
        """Executa dpkg --verify exclusivamente para diagnóstico."""
        res = self.runner.run(["dpkg", "--verify", package_name], timeout=10.0)
        issues = [line.strip() for line in res.stdout.splitlines() if line.strip()]
        return {"package": package_name, "ok": res.returncode == 0 and not issues, "issues": issues}


class AptTrustHookProcessor:
    """Implementa DPkg::Pre-Install-Pkgs e DPkg::Post-Invoke para confiança pós-atualização."""

    def __init__(
        self,
        trust_store: TrustStore,
        *,
        hook_state_path: Path | None = None,
    ) -> None:
        self.trust_store = trust_store
        self.hook_state_path = hook_state_path or (
            trust_store.path.parent / "apt_hook_expectations.json"
        )

    def _extract_deb_metadata_and_hashes(
        self, deb_path: Path, target_paths: list[str]
    ) -> tuple[str | None, dict[str, str]]:
        pkg_res = subprocess.run(
            ["dpkg-deb", "-f", "--", str(deb_path), "Package"],
            capture_output=True,
            text=True,
            timeout=15.0,
            check=False,
        )
        pkg_name = pkg_res.stdout.strip() if pkg_res.returncode == 0 else None
        if not pkg_name:
            return None, {}

        fsys_res = subprocess.run(
            ["dpkg-deb", "--fsys-tarfile", "--", str(deb_path)],
            capture_output=True,
            timeout=30.0,
            check=False,
        )
        if fsys_res.returncode != 0:
            return pkg_name, {}

        normalized_targets: dict[str, str] = {}
        stop_prefix = self.trust_store.stop_at_prefix
        for tp in target_paths:
            if stop_prefix is not None:
                try:
                    stripped = str(Path(tp).relative_to(stop_prefix)).lstrip("/")
                except ValueError:
                    stripped = tp.lstrip("/")
            else:
                stripped = tp.lstrip("/")
            normalized_targets[stripped] = tp
            if stripped.startswith("usr/"):
                normalized_targets[stripped[4:]] = tp
            elif stripped.startswith(("bin/", "sbin/")):
                normalized_targets[f"usr/{stripped}"] = tp

        found: dict[str, str] = {}
        with tarfile.open(fileobj=io.BytesIO(fsys_res.stdout), mode="r:*") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                clean = member.name.removeprefix("./").lstrip("/")
                if clean in normalized_targets:
                    extracted = tf.extractfile(member)
                    if extracted is not None:
                        h = hashlib.sha256()
                        while chunk := extracted.read(65536):
                            h.update(chunk)
                        found[normalized_targets[clean]] = h.hexdigest()
        return pkg_name, found

    def pre_install_pkgs(
        self,
        deb_paths: list[str | Path],
        *,
        authenticated_origins: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Retira regras antigas antes da troca e extrai hashes esperados dos .deb autenticados."""
        rules = self.trust_store._load()
        expectations: dict[str, dict[str, Any]] = {}
        suspended_ids: list[str] = []

        deb_list = [Path(p) for p in deb_paths if Path(p).is_file()]
        pkg_rules = [r for r in rules if r.trust_mode == "package_updates" and r.package_name]

        for deb in deb_list:
            pkg_name, hashes = self._extract_deb_metadata_and_hashes(
                deb,
                [r.executable_path for r in pkg_rules],
            )
            if not pkg_name:
                continue
            for rule in rules:
                if rule.package_name != pkg_name:
                    continue
                # Retira a regra antiga antes da troca do pacote
                rule.active = False
                rule.revalidation_required = True
                rule.invalidated_reason = "Atualização de pacote em andamento (Pre-Install-Pkgs)."
                rule.updated_at = now_iso()
                suspended_ids.append(rule.rule_id)

                if rule.trust_mode == "package_updates" and rule.executable_path in hashes:
                    origin = (authenticated_origins or {}).get(pkg_name, rule.package_origin or "")
                    expectations[rule.rule_id] = {
                        "package_name": pkg_name,
                        "executable_path": rule.executable_path,
                        "expected_sha256": hashes[rule.executable_path],
                        "authenticated_origin": origin,
                    }

        self.trust_store._save(rules)
        atomic_write_json(self.hook_state_path, {"expectations": expectations}, mode=0o600)
        return {"suspended": suspended_ids, "expectations": expectations}

    def post_invoke(self) -> dict[str, Any]:
        """Reativa apenas se o executável instalado bater com o SHA-256 e origem esperados."""
        raw_exp = read_json_safe(self.hook_state_path, default={"expectations": {}})
        expectations = raw_exp.get("expectations", {})
        rules = self.trust_store._load()
        reactivated: list[str] = []
        kept_disabled: list[str] = []

        for rule in rules:
            exp = expectations.get(rule.rule_id)
            if exp is None:
                if not rule.active:
                    kept_disabled.append(rule.rule_id)
                continue

            p = Path(rule.executable_path)
            chain = verify_root_owned_path_chain(
                p,
                allowed_uids=self.trust_store.allowed_uids,
                stop_at_prefix=self.trust_store.stop_at_prefix,
            )
            if not chain.safe or is_dynamic_or_unverifiable(p):
                rule.active = False
                rule.revalidation_required = True
                rule.invalidated_reason = f"Falha de segurança pós-atualização: {chain.reason}"
                kept_disabled.append(rule.rule_id)
                continue

            self.trust_store.cache.invalidate(p)
            actual_sha, new_key, _ = self.trust_store.cache.get_identity(p)
            origin_ok = bool(exp.get("authenticated_origin")) and (
                exp.get("authenticated_origin") == rule.package_origin
            )
            if actual_sha == exp.get("expected_sha256") and origin_ok:
                rule.sha256 = actual_sha
                rule.stat_key = list(new_key)
                rule.active = True
                rule.revalidation_required = False
                rule.invalidated_reason = None
                rule.updated_at = now_iso()
                reactivated.append(rule.rule_id)
            else:
                rule.active = False
                rule.revalidation_required = True
                rule.invalidated_reason = (
                    "Divergência de SHA-256 ou origem na verificação Post-Invoke; "
                    "revalidação exigida na primeira conexão."
                )
                rule.updated_at = now_iso()
                kept_disabled.append(rule.rule_id)

        self.trust_store._save(rules)
        atomic_write_json(self.hook_state_path, {"expectations": {}}, mode=0o600)
        return {"reactivated": reactivated, "kept_disabled": kept_disabled}


class OpenSnitchBridge:
    """Contrato de primeira conexão e recuperação de negações (Seção 3 e H2)."""

    def __init__(
        self,
        *,
        pending_store: PendingStore,
        trust_store: TrustStore,
        denials_path: Path | None = None,
    ) -> None:
        self.pending_store = pending_store
        self.trust_store = trust_store
        self.denials_path = denials_path or (
            trust_store.path.parent / "firewall_denials.json"
        )
        self.bridge_online = True
        self.bridge_busy = False
        self.queue_full = False
        self.concurrent_capable = True
        self.max_concurrent_waits = 4
        self._waiting_connections: dict[str, dict[str, Any]] = {}
        self._next_attempt_allowed: set[str] = set()

    def _record_denial(
        self,
        *,
        app_name: str,
        executable_path: str,
        destination: str,
        reason: str,
    ) -> dict[str, Any]:
        entry = {
            "denial_id": str(uuid.uuid4()),
            "app_name": app_name,
            "executable_path": executable_path,
            "destination": destination,
            "reason": reason,
            "timestamp": now_iso(),
            "recoverable": True,
        }
        raw = read_json_safe(self.denials_path, default={"items": []})
        raw["items"].append(entry)
        atomic_write_json(self.denials_path, raw, mode=0o600)

        self.pending_store.create(
            kind="firewall_connection",
            module_id="firewall",
            app_name=app_name,
            title=f"Conexão negada de {app_name}",
            summary=(
                f"{app_name} tentou conectar a {destination}. "
                "Oferecendo 'Permitir a próxima tentativa' quando o aplicativo tentar novamente."
            ),
            evidence=reason,
            actions=["allow_next_attempt", "remember_version"],
            metadata={
                "executable_path": executable_path,
                "destination": destination,
                "label": "Permitir a próxima tentativa",
            },
            group_repeated=True,
        )
        return entry

    def list_denials(self) -> list[dict[str, Any]]:
        raw = read_json_safe(self.denials_path, default={"items": []})
        return list(raw.get("items", []))

    def allow_next_attempt(self, app_name: str) -> None:
        """Habilita a próxima tentativa originada pelo próprio aplicativo."""
        self._next_attempt_allowed.add(app_name)

    def handle_first_connection(
        self,
        *,
        connection_id: str,
        app_name: str,
        executable_path: str,
        destination: str,
        outbound_mode: str,
        pid: int | None = None,
        encrypted_dns_domain: str | None = None,
    ) -> dict[str, Any]:
        """Aplica política da primeira conexão conforme estado da ponte e modo escolhido."""
        # Verifica confiança existente primeiro
        if os.path.exists(executable_path):
            eval_res = self.trust_store.evaluate_connection(executable_path, destination)
            if eval_res["decision"] == "allow":
                return {
                    "action": "allow",
                    "status_label": "Permitido por regra confiável",
                    "connection_id": connection_id,
                    "pid": pid,
                    "domain": encrypted_dns_domain,
                    "cache_hit": eval_res["cache_hit"],
                }

        # Usuário autorizou a próxima tentativa originada do aplicativo
        if app_name in self._next_attempt_allowed:
            self._next_attempt_allowed.remove(app_name)
            return {
                "action": "allow",
                "status_label": "Permitida a próxima tentativa",
                "connection_id": connection_id,
                "pid": pid,
                "domain": encrypted_dns_domain,
            }

        # Modo só monitorar aplica allow mesmo com ponte fora
        if outbound_mode == "monitor_only":
            return {
                "action": "allow",
                "default_action": "allow",
                "status_label": "Monitorado (permitido)",
                "connection_id": connection_id,
                "pid": pid,
                "domain": encrypted_dns_domain,
            }

        # Modo bloqueio: ponte indisponível ou fila cheia -> DefaultAction=deny e registro recuperável
        if not self.bridge_online:
            denial = self._record_denial(
                app_name=app_name,
                executable_path=executable_path,
                destination=destination,
                reason="Ponte indisponível em modo bloqueio (DefaultAction=deny).",
            )
            return {
                "action": "deny",
                "default_action": "deny",
                "status_label": "Permitir a próxima tentativa",
                "denial": denial,
                "connection_id": connection_id,
            }

        if (
            not self.concurrent_capable
            or self.bridge_busy
            or self.queue_full
            or len(self._waiting_connections) >= self.max_concurrent_waits
        ):
            reason = (
                "Fila cheia ou serializada na ponte OpenSnitch; conexão negada uma vez."
            )
            denial = self._record_denial(
                app_name=app_name,
                executable_path=executable_path,
                destination=destination,
                reason=reason,
            )
            return {
                "action": "deny",
                "default_action": "deny",
                "status_label": "Permitir a próxima tentativa",
                "denial": denial,
                "connection_id": connection_id,
            }

        # Retém somente a conexão afetada aguardando decisão independente
        self._waiting_connections[connection_id] = {
            "app_name": app_name,
            "executable_path": executable_path,
            "destination": destination,
            "pid": pid,
            "domain": encrypted_dns_domain,
            "created_at": now_iso(),
        }
        return {
            "action": "wait",
            "status_label": "Aguardando decisão",
            "connection_id": connection_id,
            "waiting_count": len(self._waiting_connections),
        }

    def resolve_waiting(
        self,
        connection_id: str,
        decision: str,
        *,
        remember_version: bool = False,
        trust_package_updates: bool = False,
        package_name: str | None = None,
        package_origin: str | None = None,
    ) -> dict[str, Any]:
        """Resolve uma conexão retida sem interferir em outras conexões simultâneas."""
        entry = self._waiting_connections.pop(connection_id, None)
        if entry is None:
            raise KeyError(f"Conexão não encontrada na fila: {connection_id}")
        if decision == "allow" and remember_version:
            self.trust_store.remember_version(
                executable_path=entry["executable_path"],
                approved_destinations=[entry["destination"]],
                trust_package_updates=trust_package_updates,
                package_name=package_name,
                package_origin=package_origin,
            )
        if decision == "deny":
            self._record_denial(
                app_name=entry["app_name"],
                executable_path=entry["executable_path"],
                destination=entry["destination"],
                reason="Recusado explicitamente pelo usuário.",
            )
        return {"connection_id": connection_id, "decision": decision, "remaining_waiting": len(self._waiting_connections)}
