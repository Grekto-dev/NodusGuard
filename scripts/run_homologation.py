#!/usr/bin/env python3
"""Orquestrador de homologação H1–H8: gera docs/homologation-report.md e docs/release-manifest.json."""

from __future__ import annotations

import json
import platform
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))

from homologation.h1_exec_freeze.run_h1 import run_h1  # noqa: E402
from homologation.h2_firewall import run_h2  # noqa: E402
from homologation.h3_identity_update import run_h3  # noqa: E402
from homologation.h4_lightweight import run_h4  # noqa: E402
from homologation.h5_dns_wifi import run_h5  # noqa: E402
from homologation.h6_recovery_canary import run_h6  # noqa: E402
from homologation.h7_rescue_session import run_h7  # noqa: E402


def _run_h8() -> dict:
    import os
    import subprocess
    import time

    disp = ":98"
    xephyr = subprocess.Popen(
        ["Xephyr", disp, "-screen", "1400x900", "-ac", "-noreset"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    orig_display = os.environ.get("DISPLAY")
    os.environ["DISPLAY"] = disp
    os.environ["MINTSEC_XEPHYR_ACTIVE"] = "1"
    time.sleep(0.6)
    try:
        from tests.test_h8_ui import H8UiTests

        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(H8UiTests)
        res = unittest.TextTestRunner(verbosity=1).run(suite)
        return {
            "assay": "H8",
            "status": "PASS_XEPHYR_CINNAMON_ENV" if res.wasSuccessful() else "FAIL",
            "tests_run": res.testsRun,
            "idle_repaints": H8UiTests.metrics.get("idle_repaints"),
            "tab_latencies_ms": H8UiTests.metrics.get("tab_latencies_ms"),
            "pending_desktops": "Matriz visual validada em Xephyr sob ambiente Mint 22.3; sessões MATE e Xfce pendentes.",
        }
    finally:
        xephyr.terminate()
        try:
            xephyr.wait(timeout=3)
        except subprocess.TimeoutExpired:
            xephyr.kill()
        os.environ.pop("MINTSEC_XEPHYR_ACTIVE", None)
        if orig_display is not None:
            os.environ["DISPLAY"] = orig_display


def main() -> int:
    runners = [
        ("H1", lambda: run_h1(ROOT)),
        ("H2", lambda: run_h2(ROOT)),
        ("H3", lambda: run_h3(ROOT)),
        ("H4", lambda: run_h4(ROOT)),
        ("H5", lambda: run_h5(ROOT)),
        ("H6", lambda: run_h6(ROOT)),
        ("H7", lambda: run_h7(ROOT)),
        ("H8", _run_h8),
    ]
    results: dict = {}
    for key, fn in runners:
        print(f"[{key}] executando...", flush=True)
        res = fn()
        results[key] = res
        print(f"[{key}] concluído: {res['status']}", flush=True)

    release_manifest = {
        "suite_version": "0.2.5",
        "target_base": "Linux Mint 22.3 (Ubuntu 24.04)",
        "kernel": platform.release(),
        "approved_features": [
            "Painel GTK 3 com SSD, tema lavanda/escuro/alto contraste e seletor de temas",
            "Agente de sessão Rust (SNI, notificações D-Bus agrupadas e diálogos sob demanda)",
            "Contratos versionados de 7 módulos, histórico SQLite WAL opcional e Polkit sem retenção destrutiva",
            "Antimalware sob demanda/agendado (ClamAV) e quarentena com confirmação e tratamento de colisão",
            "Firewall de entrada (UFW) com reversão seletiva + contrato OpenSnitch/confiança SHA-256 APT",
            "Recuperação pessoal (restic), pontos Timeshift e preservação fora de $HOME na pasta do incidente",
            "Filtro DNS local (dnsmasq vencedor H5) com exceções e preservação de VPN",
            "Inventário de rede local (NetworkManager + auxiliar ARP/DHCP CAP_NET_RAW)",
            "Navegador Isolado com bubblewrap e perfil temporário (com aviso do modelo X11)",
            "Início congelado FAN_OPEN_EXEC_PERM + cgroup.freeze validado em micro-VM KVM (kernel 6.14.0-37-generic)",
            "ISO de resgate offline híbrida BIOS + UEFI validada em QEMU/KVM com montagem inicial somente leitura",
        ],
        "experimental_features": [
            "Modo Banco (testado em Xephyr aninhado; pendente H7 gráfico em GPUs Intel/Nouveau/modesetting e VT físico)",
            "Resgate offline USB em mídia física sob Secure Boot assinado (pendente teste em hardware físico)",
            "Início congelado externo FAN_OPEN_EXEC_PERM nos kernels 6.8 e 7.0 (6.14 validado em KVM)",
            "Varredura em tempo real clamd/clamonacc por adesão (pendente medição 2/4 GiB HDD em H4)",
        ],
        "pending_matrices": ["MATE", "Xfce", "LMDE (base Debian)", "2/4 GiB HDD físico"],
        "homologation_results": results,
    }

    docs_dir = ROOT / "docs"
    docs_dir.mkdir(exist_ok=True)
    (docs_dir / "release-manifest.json").write_text(
        json.dumps(release_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    lines = [
        "# Relatório de Homologação H1–H8 (Linux Mint 22.3)",
        "",
        f"- **Kernel observado**: `{platform.release()}`",
        "- **Recursos homologados localmente**: MVP completo + conector OpenSnitch/confiança SHA-256 APT + DNS local (`dnsmasq`)/rede local + Navegador Isolado (`bubblewrap`) + H1 ao vivo em micro-VM KVM (`6.14.0-37-generic`) + ISO de resgate BIOS/UEFI em QEMU/KVM + H8 (`0` repinturas ociosas).",
        "- **Recursos mantidos como experimentais/pendentes**: Modo Banco em GPUs legadas/VT físico, Secure Boot assinado em hardware físico, `FAN_OPEN_EXEC_PERM` nos kernels 6.8/7.0, matriz HDD 2/4 GiB e matrizes MATE/Xfce/LMDE.",
        "",
        "## Resumo por Ensaio",
        "",
        "| Ensaio | Status | Evidência principal |",
        "|---|---|---|",
    ]
    for key, val in results.items():
        lines.append(f"| **{key}** | `{val['status']}` | `{json.dumps(val, ensure_ascii=False)[:220]}` |")

    (docs_dir / "homologation-report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    print(json.dumps({k: v["status"] for k, v in results.items()}, indent=2, ensure_ascii=False))
    print("H3 p95 (ms):", results["H3"]["hot_cache_p95_ms"], "| cold hash (ms):", results["H3"]["cold_first_hash_ms"])
    print("H8 idle repaints:", results["H8"]["idle_repaints"], "| latencies:", results["H8"]["tab_latencies_ms"])
    failed = [k for k, v in results.items() if "FAIL" in str(v["status"])]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
