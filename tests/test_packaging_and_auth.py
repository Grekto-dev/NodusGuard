"""Testes de origem real de pacotes (Mint 22.3), autorização Polkit e política sem retenção."""

from __future__ import annotations

import shutil
import unittest
from pathlib import Path

from mintsec.auth import AuthorizationError, CallerAuthorizer, validate_polkit_policy
from mintsec.packaging import PackageInspector, parse_apt_policy_origin


class PackagingAndAuthTests(unittest.TestCase):
    def test_real_host_package_inspection_matches_mint_system(self) -> None:
        inspector = PackageInspector()
        ufw_info = inspector.inspect_package("ufw", binaries=["ufw"])
        self.assertTrue(ufw_info.installed)
        self.assertIsNotNone(ufw_info.version)
        self.assertNotEqual(ufw_info.origin, "Não instalado")

        os_release = Path("/etc/os-release")
        os_text = os_release.read_text(encoding="utf-8", errors="ignore").lower() if os_release.is_file() else ""
        if "linuxmint" in os_text and "zena" in os_text:
            ts_info = inspector.inspect_package("timeshift", binaries=["timeshift"])
            self.assertTrue(ts_info.installed)
            self.assertIn("zena", ts_info.version or "")
        elif shutil.which("timeshift"):
            ts_info = inspector.inspect_package("timeshift", binaries=["timeshift"])
            self.assertTrue(ts_info.installed)

        absent_info = inspector.inspect_package("pacote-inexistente-mintsec-xyz")
        self.assertFalse(absent_info.installed)
        self.assertIsNone(absent_info.version)
        self.assertEqual(absent_info.origin, "Não instalado")

    def test_parse_apt_policy_origin_variants(self) -> None:
        ubuntu_out = (
            "ufw:\n"
            "  Instalado: 0.36.2-6\n"
            " *** 0.36.2-6 500\n"
            "        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n"
            "        100 /var/lib/dpkg/status\n"
        )
        self.assertEqual(parse_apt_policy_origin(ubuntu_out, "0.36.2-6"), "Ubuntu (noble/main)")

        mint_out = (
            "timeshift:\n"
            " *** 25.12.4+zena 700\n"
            "        700 http://packages.linuxmint.com zena/backport amd64 Packages\n"
            "        100 /var/lib/dpkg/status\n"
        )
        self.assertEqual(parse_apt_policy_origin(mint_out, "25.12.4+zena"), "Linux Mint (zena/backport)")

    def test_polkit_policy_destructive_actions_have_no_retention(self) -> None:
        policy_file = Path(__file__).resolve().parents[1] / "polkit" / "org.mintsecurity.suite.policy"
        errors = validate_polkit_policy(policy_file)
        self.assertEqual(errors, [])

    def test_authorizer_enforces_uid_and_decision(self) -> None:
        deny_auth = CallerAuthorizer(test_decision=False)
        with self.assertRaises(AuthorizationError):
            deny_auth.require("org.mintsecurity.recovery.overwrite", caller_uid=1000)

        uid_restricted = CallerAuthorizer(test_decision=True, allowed_uids={0})
        with self.assertRaises(AuthorizationError):
            uid_restricted.require("org.mintsecurity.module.toggle", caller_uid=1000)
        res = uid_restricted.require("org.mintsecurity.module.toggle", caller_uid=0)
        self.assertTrue(res.authorized)


if __name__ == "__main__":
    unittest.main()
