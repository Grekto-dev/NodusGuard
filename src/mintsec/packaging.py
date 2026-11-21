"""Inspeção real de pacotes (versão/origem) e instalação modular via aptkit."""

from __future__ import annotations

import os
import re
import threading
from dataclasses import dataclass, replace
from typing import Callable

from mintsec.runner import CommandRunner, SubprocessRunner


def _stat_sig(path: str) -> tuple[int, int]:
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return (0, 0)


def _apt_sig() -> tuple[tuple[int, int], tuple[int, int]]:
    return (_stat_sig("/var/lib/dpkg/status"), _stat_sig("/var/cache/apt/pkgcache.bin"))


_PKG_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9+.-]{0,127}$")


def _validate_pkg_name(package_name: str) -> str:
    clean = str(package_name).strip()
    if not _PKG_NAME_RE.match(clean):
        raise ValueError(f"Nome de pacote Debian inválido: {package_name}")
    return clean


@dataclass(frozen=True)
class PackageInfo:
    """Situação real e origem de um pacote Debian/Ubuntu/Mint no sistema."""

    package_name: str
    installed: bool
    version: str | None
    origin: str
    binary_present: bool


class PackageInspector:
    """Consulta dpkg-query e apt-cache policy para identificar versão e origem reais."""

    def __init__(self, runner: CommandRunner | None = None) -> None:
        self.runner = runner or SubprocessRunner()
        self._lock = threading.Lock()
        self._cache: dict[str, PackageInfo] = {}
        self._cache_sig: tuple[tuple[int, int], tuple[int, int]] | None = None

    def _cache_enabled(self) -> bool:
        return isinstance(self.runner, SubprocessRunner)

    def invalidate_cache(self) -> None:
        """Invalida cache de pacotes e resolução de PATH no runner."""
        with self._lock:
            self._cache.clear()
            self._cache_sig = None
        if isinstance(self.runner, SubprocessRunner):
            self.runner.clear_which_cache()

    def _ensure_cache_fresh(self) -> tuple[tuple[int, int], tuple[int, int]] | None:
        if not self._cache_enabled():
            return None
        sig = _apt_sig()
        with self._lock:
            if self._cache_sig != sig:
                self._cache.clear()
                self._cache_sig = sig
        return sig

    def prime_cache(
        self,
        packages: list[str],
        binaries_by_pkg: dict[str, list[str]] | None = None,
    ) -> None:
        """Pré-carrega múltiplos pacotes em 1 dpkg-query + 1 apt-cache policy."""
        if not packages or not self._cache_enabled():
            return
        sig = self._ensure_cache_fresh()
        unique_pkgs = [_validate_pkg_name(p) for p in dict.fromkeys(packages)]
        with self._lock:
            missing = [p for p in unique_pkgs if p not in self._cache]
        if not missing:
            return

        dpkg_res = self.runner.run(
            ["dpkg-query", "-W", "-f=${Package}\t${Status}\t${Version}\n", "--", *missing],
            timeout=5.0,
        )
        parsed: dict[str, tuple[bool, str | None]] = {}
        for line in dpkg_res.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) < 3:
                continue
            pkg_name, status, ver = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if "install ok installed" in status:
                parsed[pkg_name] = (True, ver)

        installed_pkgs = [p for p in missing if parsed.get(p, (False, None))[0]]
        origins: dict[str, str] = {}
        if installed_pkgs:
            pol_res = self.runner.run(["apt-cache", "policy", "--", *installed_pkgs], timeout=8.0)
            if pol_res.returncode == 0 and pol_res.stdout:
                versions = {p: (parsed[p][1] or "") for p in installed_pkgs}
                origins = parse_apt_policy_multi(pol_res.stdout, versions)

        new_entries: dict[str, PackageInfo] = {}
        bin_map = binaries_by_pkg or {}
        for pkg in missing:
            bins = bin_map.get(pkg, [])
            binary_present = any(self.runner.which(b) is not None for b in bins) if bins else False
            is_inst, ver = parsed.get(pkg, (False, None))
            if not is_inst:
                new_entries[pkg] = PackageInfo(
                    package_name=pkg,
                    installed=False,
                    version=None,
                    origin="Não instalado",
                    binary_present=binary_present,
                )
            else:
                origin = origins.get(pkg) or (f"Pacote local ({ver})" if ver else "Pacote instalado localmente")
                new_entries[pkg] = PackageInfo(
                    package_name=pkg,
                    installed=True,
                    version=ver,
                    origin=origin,
                    binary_present=binary_present,
                )

        with self._lock:
            if self._cache_sig == sig:
                self._cache.update(new_entries)

    def inspect_package(self, package_name: str, binaries: list[str] | None = None) -> PackageInfo:
        """Verifica se o pacote está instalado, sua versão e origem real do repositório."""
        package_name = _validate_pkg_name(package_name)
        sig = self._ensure_cache_fresh()
        if sig is not None:
            with self._lock:
                cached = self._cache.get(package_name)
            if cached is not None:
                if binaries and not cached.binary_present:
                    bin_now = any(self.runner.which(b) is not None for b in binaries)
                    if bin_now:
                        updated = replace(cached, binary_present=True)
                        with self._lock:
                            if self._cache_sig == sig:
                                self._cache[package_name] = updated
                        return updated
                return cached

        binary_present = False
        if binaries:
            binary_present = any(self.runner.which(b) is not None for b in binaries)

        dpkg_res = self.runner.run(
            ["dpkg-query", "-W", "-f=${Status}\t${Version}\n", "--", package_name],
            timeout=5.0,
        )
        installed = False
        version: str | None = None
        if dpkg_res.returncode == 0:
            line = dpkg_res.stdout.strip()
            if "\t" in line:
                status, ver = line.split("\t", 1)
                if "install ok installed" in status:
                    installed = True
                    version = ver.strip()

        if not installed:
            info = PackageInfo(
                package_name=package_name,
                installed=False,
                version=None,
                origin="Não instalado",
                binary_present=binary_present,
            )
        else:
            origin = self._resolve_origin(package_name, version or "")
            info = PackageInfo(
                package_name=package_name,
                installed=True,
                version=version,
                origin=origin,
                binary_present=binary_present,
            )

        if sig is not None:
            with self._lock:
                if self._cache_sig == sig:
                    self._cache[package_name] = info
        return info

    def _resolve_origin(self, package_name: str, installed_version: str) -> str:
        res = self.runner.run(["apt-cache", "policy", "--", package_name], timeout=5.0)
        if res.returncode != 0 or not res.stdout:
            return "Pacote instalado localmente"
        return parse_apt_policy_origin(res.stdout, installed_version)


def parse_apt_policy_multi(policy_output: str, versions_by_pkg: dict[str, str] | None = None) -> dict[str, str]:
    """Divide saída multi-pacote de `apt-cache policy` e extrai a origem de cada pacote."""
    sections: dict[str, list[str]] = {}
    current_pkg: str | None = None
    for line in policy_output.splitlines():
        if line and not line[0].isspace() and line.rstrip().endswith(":"):
            current_pkg = line.rstrip()[:-1].strip()
            sections[current_pkg] = []
        elif current_pkg is not None:
            sections[current_pkg].append(line)

    versions = versions_by_pkg or {}
    return {
        pkg: parse_apt_policy_origin("\n".join(sec_lines), versions.get(pkg, ""))
        for pkg, sec_lines in sections.items()
    }


def parse_apt_policy_origin(policy_output: str, installed_version: str) -> str:
    """Extrai a origem real da versão instalada a partir de `apt-cache policy`."""
    lines = policy_output.splitlines()
    capture_sources = False
    for line in lines:
        stripped = line.strip()
        if line.startswith(" *** "):
            capture_sources = True
            continue
        if capture_sources:
            if not line.startswith("        "):
                break
            if "/var/lib/dpkg/status" in stripped:
                continue
            # Exemplo: 500 http://archive.ubuntu.com/ubuntu noble/universe amd64 Packages
            # ou:      700 http://packages.linuxmint.com zena/backport amd64 Packages
            match = re.search(r"https?://([^/\s]+)(?:/[^\s]*)?\s+([^\s]+)\s+\S+\s+Packages", stripped)
            if match:
                host, suite = match.group(1), match.group(2)
                if "linuxmint" in host:
                    return f"Linux Mint ({suite})"
                if "ubuntu" in host:
                    return f"Ubuntu ({suite})"
                if "debian" in host:
                    return f"Debian ({suite})"
                return f"{host} ({suite})"
            return stripped
    return f"Pacote local ({installed_version})" if installed_version else "Pacote local"


class AptKitInstaller:
    """Instala ou remove pacotes de módulos individuais usando aptkit."""

    def __init__(self, dry_run: bool = False) -> None:
        self.dry_run = dry_run

    def is_available(self) -> bool:
        try:
            import aptkit.client  # noqa: F401
            return True
        except Exception:
            return False

    def install_packages(
        self,
        packages: list[str],
        on_progress: Callable[[int, str], None] | None = None,
    ) -> dict[str, object]:
        """Agenda instalação via aptkit.client.AptClient (ou simula em dry_run)."""
        if not packages:
            return {"ok": True, "packages": [], "message": "Nenhum pacote necessário."}
        if self.dry_run:
            if on_progress:
                on_progress(100, f"Simulação: {', '.join(packages)}")
            return {"ok": True, "dry_run": True, "packages": packages, "message": "Simulação concluída."}

        from aptkit import client as apt_client
        from gi.repository import GLib

        loop = GLib.MainLoop()
        result: dict[str, object] = {"ok": False, "packages": packages}
        apt = apt_client.AptClient()

        def _on_reply(trans: object) -> None:
            def _on_progress(_trans: object, percent: int) -> None:
                if on_progress:
                    on_progress(int(percent), f"Instalando {', '.join(packages)}…")

            def _on_finished(_trans: object, exit_state: object) -> None:
                result["ok"] = str(exit_state).endswith("success") or str(exit_state) == "exit-success"
                result["exit_state"] = str(exit_state)
                loop.quit()

            trans.connect("progress-changed", _on_progress)  # type: ignore[attr-defined]
            trans.connect("finished", _on_finished)  # type: ignore[attr-defined]
            trans.run()  # type: ignore[attr-defined]

        def _on_error(error: Exception) -> None:
            result["ok"] = False
            result["error"] = str(error)
            loop.quit()

        apt.install_packages(packages, reply_handler=_on_reply, error_handler=_on_error)
        loop.run()
        return result

    def remove_packages(self, packages: list[str]) -> dict[str, object]:
        """Remove pacotes de módulo individual via aptkit."""
        if not packages:
            return {"ok": True, "packages": []}
        if self.dry_run:
            return {"ok": True, "dry_run": True, "packages": packages}

        from aptkit import client as apt_client
        from gi.repository import GLib

        loop = GLib.MainLoop()
        result: dict[str, object] = {"ok": False, "packages": packages}
        apt = apt_client.AptClient()

        def _on_reply(trans: object) -> None:
            def _on_finished(_trans: object, exit_state: object) -> None:
                result["ok"] = str(exit_state).endswith("success") or str(exit_state) == "exit-success"
                result["exit_state"] = str(exit_state)
                loop.quit()

            trans.connect("finished", _on_finished)  # type: ignore[attr-defined]
            trans.run()  # type: ignore[attr-defined]

        def _on_error(error: Exception) -> None:
            result["ok"] = False
            result["error"] = str(error)
            loop.quit()

        apt.remove_packages(packages, reply_handler=_on_reply, error_handler=_on_error)
        loop.run()
        return result
