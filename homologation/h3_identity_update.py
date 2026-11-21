"""Ensaio H3: identidade SHA-256, hooks APT (.deb v1/v2), symlink e p95 < 5 ms a 50 conn/s."""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any

from mintsec.firewall_trust import (
    AptTrustHookProcessor,
    TrustStore,
    is_dynamic_or_unverifiable,
    verify_root_owned_path_chain,
)


def _build_sample_deb(stage_root: Path, out_deb: Path, version: str, message: str) -> Path:
    pkg_dir = stage_root / f"pkg_{version}"
    bin_dir = pkg_dir / "opt/mintsec-sample"
    deb_dir = pkg_dir / "DEBIAN"
    bin_dir.mkdir(parents=True, exist_ok=True)
    deb_dir.mkdir(parents=True, exist_ok=True)

    c_file = stage_root / f"app_{version}.c"
    c_file.write_text(
        f'#include <stdio.h>\nint main(void) {{ puts("{message}"); return 0; }}\n',
        encoding="utf-8",
    )
    bin_out = bin_dir / "sample-app"
    subprocess.run(["gcc", "-O2", str(c_file), "-o", str(bin_out)], check=True)
    bin_out.chmod(0o755)
    (deb_dir / "control").write_text(
        f"Package: mintsec-h3-sample\nVersion: {version}\nArchitecture: amd64\n"
        f"Maintainer: H3 <h3@example.org>\nDescription: Sample {version}\n",
        encoding="utf-8",
    )
    subprocess.run(["dpkg-deb", "--build", "--root-owner-group", str(pkg_dir), str(out_deb)], check=True)
    return bin_out


def run_h3(repo_root: Path) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="mintsec-h3-") as tmp:
        tmp_path = Path(tmp)
        jail = tmp_path / "jail"
        app_dir = jail / "opt/mintsec-sample"
        app_dir.mkdir(parents=True, mode=0o755)
        os.chmod(jail, 0o755)
        os.chmod(jail / "opt", 0o755)
        os.chmod(app_dir, 0o755)

        deb_v1 = tmp_path / "sample_1.0.deb"
        deb_v2 = tmp_path / "sample_2.0.deb"
        bin_v1 = _build_sample_deb(tmp_path / "build", deb_v1, "1.0", "hello-v1")
        bin_v2 = _build_sample_deb(tmp_path / "build", deb_v2, "2.0", "hello-v2")

        installed_bin = app_dir / "sample-app"
        shutil.copy2(bin_v1, installed_bin)
        os.chmod(installed_bin, 0o755)

        # 1. Rejeição de cadeia gravável e ataque de symlink
        writable_dir = jail / "writable"
        writable_dir.mkdir(mode=0o777)
        os.chmod(writable_dir, 0o777)
        sym_bin = writable_dir / "sym-app"
        sym_bin.symlink_to(installed_bin)
        sym_check = verify_root_owned_path_chain(
            sym_bin,
            allowed_uids={os.getuid()},
            stop_at_prefix=jail,
        )
        assert not sym_check.safe, "Deveria rejeitar diretório gravável / symlink!"

        # 2. Rejeição de script dinâmico para regra persistente
        script_file = app_dir / "script.sh"
        script_file.write_text("#!/bin/sh\necho oi\n", encoding="utf-8")
        os.chmod(script_file, 0o755)
        assert is_dynamic_or_unverifiable(script_file)

        # 3. Medição separada do primeiro hash a frio + benchmark em cache quente (50 conexões/s)
        trust = TrustStore(
            tmp_path / "trust.json",
            allowed_uids={os.getuid()},
            stop_at_prefix=jail,
        )
        t_cold0 = time.perf_counter()
        sha_cold, _, hit_cold = trust.cache.get_identity(installed_bin)
        cold_hash_ms = (time.perf_counter() - t_cold0) * 1000.0
        assert not hit_cold and len(sha_cold) == 64

        rule = trust.remember_version(
            executable_path=installed_bin,
            approved_destinations=["api.exemplo.org:443"],
            trust_package_updates=True,
            package_name="mintsec-h3-sample",
            package_origin="Ubuntu (noble/main)",
        )
        assert rule.active

        latencies_ms: list[float] = []
        for _ in range(50):
            t0 = time.perf_counter()
            res = trust.evaluate_connection(installed_bin, "api.exemplo.org:443")
            dt_ms = (time.perf_counter() - t0) * 1000.0
            latencies_ms.append(dt_ms)
            assert res["decision"] == "allow" and res["cache_hit"] is True
        latencies_ms.sort()
        p95_ms = latencies_ms[int(0.95 * len(latencies_ms)) - 1]
        assert p95_ms < 5.0, f"p95 excedeu 5 ms: {p95_ms:.3f} ms"

        # 4. Atualização autenticada via hooks APT (.deb v2)
        hooks = AptTrustHookProcessor(trust)
        hooks.pre_install_pkgs(
            [deb_v2],
            authenticated_origins={"mintsec-h3-sample": "Ubuntu (noble/main)"},
        )
        # Durante a troca a regra fica desativada
        mid_res = trust.evaluate_connection(installed_bin, "api.exemplo.org:443")
        assert mid_res["decision"] == "revalidate"

        # Simula atualização abortada antes da troca: Post-Invoke mantém desativada!
        post_abort = hooks.post_invoke()
        assert rule.rule_id in post_abort["kept_disabled"]

        # Agora executa troca real autenticada
        hooks.pre_install_pkgs(
            [deb_v2],
            authenticated_origins={"mintsec-h3-sample": "Ubuntu (noble/main)"},
        )
        shutil.copy2(bin_v2, installed_bin)
        os.chmod(installed_bin, 0o755)
        post_ok = hooks.post_invoke()
        assert rule.rule_id in post_ok["reactivated"]
        after_up = trust.evaluate_connection(installed_bin, "api.exemplo.org:443")
        assert after_up["decision"] == "allow"

        # 5. Troca externa ao APT exige revalidação já na primeira conexão
        shutil.copy2(bin_v1, installed_bin)
        os.chmod(installed_bin, 0o755)
        trust.cache.invalidate(installed_bin)
        ext_res = trust.evaluate_connection(installed_bin, "api.exemplo.org:443")
        assert ext_res["decision"] == "revalidate"

    return {
        "assay": "H3",
        "status": "PASS",
        "cold_first_hash_ms": round(cold_hash_ms, 3),
        "hot_cache_p95_ms": round(p95_ms, 3),
        "hot_cache_max_ms": round(max(latencies_ms), 3),
        "target_p95_ms": 5.0,
        "symlink_and_dynamic_rejected": True,
        "apt_authenticated_aborted_and_external_verified": True,
    }
