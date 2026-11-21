"""Testes do módulo Firewall: UFW entrada, regras essenciais, reversão seletiva e contrato."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import ModuleState, load_manifests
from mintsec.history import HistoryStore
from mintsec.packaging import PackageInspector
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.firewall import FirewallService


class FakeUfwRunner:
    def __init__(self, *, active: bool = False, deny_status: bool = False) -> None:
        self.active = active
        self.deny_status = deny_status
        self.commands: list[list[str]] = []
        self.rules: list[str] = ["22/tcp                     ALLOW IN    Anywhere"]

    def which(self, binary: str) -> str | None:
        return "/usr/sbin/ufw" if binary == "ufw" else None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None) -> CommandResult:
        self.commands.append(list(argv))
        if argv[0] == "dpkg-query":
            pkg = argv[-1]
            if pkg == "ufw":
                return CommandResult(tuple(argv), 0, "install ok installed\t0.36.2-6\n", "")
            return CommandResult(tuple(argv), 1, "", "not installed")
        if argv[0] == "apt-cache":
            return CommandResult(
                tuple(argv),
                0,
                " *** 0.36.2-6 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n",
                "",
            )
        if argv[1:] == ["status", "numbered"]:
            if self.deny_status:
                return CommandResult(tuple(argv), 1, "", "ERROR: You need to be root to run this script")
            status_line = "Status: active" if self.active else "Status: inactive"
            body = [status_line, "", "     To                         Action      From", "     --                         ------      ----"]
            for idx, r in enumerate(self.rules, start=1):
                body.append(f"[{idx:2d}] {r}")
            return CommandResult(tuple(argv), 0, "\n".join(body) + "\n", "")
        if argv[1:] == ["--force", "enable"]:
            self.active = True
            return CommandResult(tuple(argv), 0, "Firewall is active and enabled on system startup\n", "")
        if argv[1:] == ["disable"]:
            self.active = False
            return CommandResult(tuple(argv), 0, "Firewall stopped and disabled on system startup\n", "")
        if argv[1] == "allow":
            if argv[2] == "out":
                self.rules.append(f"{argv[3]:26s} ALLOW OUT   Anywhere")
            else:
                self.rules.append(f"{argv[2]:26s} ALLOW IN    Anywhere")
            return CommandResult(tuple(argv), 0, "Rule added\n", "")
        if argv[1] == "delete":
            target = argv[-1]
            self.rules = [r for r in self.rules if not r.startswith(target)]
            return CommandResult(tuple(argv), 0, "Rule deleted\n", "")
        return CommandResult(tuple(argv), 0, "", "")


class FirewallTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.ufw_conf = self.root / "ufw.conf"
        self.ufw_conf.write_text("ENABLED=no\n", encoding="utf-8")
        self.manifests = load_manifests()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_service(self, runner: FakeUfwRunner) -> FirewallService:
        return FirewallService(
            manifest=self.manifests["firewall"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            package_inspector=PackageInspector(runner),
            runner=runner,
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
            ufw_conf_path=self.ufw_conf,
        )

    def test_enable_revert_preserves_external_rules_and_revokes_rule(self) -> None:
        runner = FakeUfwRunner(active=False)
        svc = self._make_service(runner)

        preview = svc.preview_essential_rules()
        self.assertTrue(any("DNS" in item["title"] for item in preview))

        st_enabled = svc.enable(apply_essential_rules=True)
        self.assertEqual(st_enabled.state, ModuleState.ATIVO)
        self.assertEqual(len(runner.rules), 3)  # externa 22/tcp + 53 + 68/udp

        custom_rule = svc.add_rule(direction="in", target="8080/tcp", action="ALLOW", scope="Servidor local")
        self.assertEqual(len(runner.rules), 4)
        self.assertTrue(svc.revoke_rule(custom_rule.rule_id))
        self.assertEqual(len(runner.rules), 3)

        st_disabled = svc.disable(revert_suite_changes=True)
        self.assertEqual(st_disabled.state, ModuleState.DESATIVADO)
        # Regra externa 22/tcp preservada, apenas regras da suíte removidas!
        self.assertEqual(len(runner.rules), 1)
        self.assertTrue(runner.rules[0].startswith("22/tcp"))

    def test_unreadable_ufw_reports_unavailable(self) -> None:
        missing_conf = self.root / "missing.conf"
        runner = FakeUfwRunner(deny_status=True)
        svc = FirewallService(
            manifest=self.manifests["firewall"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            package_inspector=PackageInspector(runner),
            runner=runner,
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
            ufw_conf_path=missing_conf,
        )
        st = svc.query_status()
        self.assertEqual(st.state, ModuleState.INDISPONIVEL)
        self.assertEqual(st.state.ui_label, "Estado indisponível")


if __name__ == "__main__":
    unittest.main()
