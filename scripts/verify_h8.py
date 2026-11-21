#!/usr/bin/env python3
"""Executor dedicado do ensaio H8 em Xephyr com relatório objetivo."""

from __future__ import annotations

import os
import subprocess
import sys
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "src"))


def main() -> int:
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
        if xephyr.poll() is not None:
            print("FAIL: Xephyr não iniciou no display", disp)
            return 1
        from tests.test_h8_ui import H8UiTests

        loader = unittest.TestLoader()
        suite = loader.loadTestsFromTestCase(H8UiTests)
        runner = unittest.TextTestRunner(verbosity=2)
        result = runner.run(suite)

        print("\n=== RESUMO H8 (Xephyr) ===")
        print("Display isolado:", disp)
        print("Repinturas ociosas (3s):", H8UiTests.metrics.get("idle_repaints", "n/a"))
        print("Latência troca de página (ms):", H8UiTests.metrics.get("tab_latencies_ms", {}))
        print("Status:", "PASS" if result.wasSuccessful() else "FAIL")
        return 0 if result.wasSuccessful() else 1
    finally:
        xephyr.terminate()
        try:
            xephyr.wait(timeout=3)
        except subprocess.TimeoutExpired:
            xephyr.kill()
        os.environ.pop("MINTSEC_XEPHYR_ACTIVE", None)
        if orig_display is not None:
            os.environ["DISPLAY"] = orig_display


if __name__ == "__main__":
    sys.exit(main())
