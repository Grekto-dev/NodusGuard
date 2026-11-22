"""Testes de fiação de produção: SystemBus D-Bus, Modo Banco nested, UDisks2 e maintainer scripts .deb."""

from __future__ import annotations

import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import load_manifests
from mintsec.dbus_client import SystemModuleClient, is_system_bus_mode
from mintsec.history import HistoryStore
from mintsec.pending import PendingStore
from mintsec.services.isolation import IsolationService
from mintsec.services.rescue import BlockDeviceCandidate, RescueService


class _FakeBusObj:
    pass


class _FakeBus:
    def get_object(self, bus_name: str, obj_path: str) -> object:
        return (bus_name, obj_path)


class ProductionWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.manifests = load_manifests()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def test_system_module_client_dispatch_and_local_fallback(self) -> None:
        fake_iface = mock.MagicMock()
        fake_iface.QueryStatus.return_value = '{"state":"ativo","module_id":"firewall"}'
        client = SystemModuleClient(self.manifests, bus=_FakeBus())

        old_env = os.environ.get("MINTSEC_USE_SYSTEM_BUS")
        try:
            os.environ["MINTSEC_USE_SYSTEM_BUS"] = "1"
            self.assertTrue(is_system_bus_mode())
            with mock.patch("dbus.Interface", return_value=fake_iface):
                out = client.query_status("firewall", local_service=mock.MagicMock())
            self.assertEqual(out["state"], "ativo")
            fake_iface.QueryStatus.assert_called_once()

            os.environ["MINTSEC_USE_SYSTEM_BUS"] = "0"
            self.assertFalse(is_system_bus_mode())
            local_svc = mock.MagicMock()
            local_svc.query_status.return_value.to_dict.return_value = {"state": "desativado"}
            out_local = client.query_status("firewall", local_service=local_svc)
            self.assertEqual(out_local["state"], "desativado")
        finally:
            if old_env is None:
                os.environ.pop("MINTSEC_USE_SYSTEM_BUS", None)
            else:
                os.environ["MINTSEC_USE_SYSTEM_BUS"] = old_env

    def test_bank_mode_nested_xephyr_launcher(self) -> None:
        iso = IsolationService(
            manifest=self.manifests["isolation"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            data_dir=self.root / "data",
        )
        res = iso.run_bank_mode_nested_test()
        self.assertTrue(res["ok"], f"Falha no Modo Banco nested: {res}")
        self.assertIn("BANK_NESTED_OK", res["stdout"])

    def test_udisks2_exclusive_open_checks_capacity_and_writes_verified_fd(self) -> None:
        rescue = RescueService(
            manifest=self.manifests["rescue"],
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "data",
        )
        img = self.root / "sample.iso"
        img.write_bytes(b"ISO_PAYLOAD_" * 1024)
        out_file = self.root / "usb_target.raw"

        fd = os.open(out_file, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            written, digest = rescue.write_to_fd_verified(image_path=img, fd=fd)
        finally:
            os.close(fd)
        self.assertEqual(written, img.stat().st_size)
        self.assertEqual(len(digest), 64)

        cand = BlockDeviceCandidate(
            path="/dev/sde",
            name="sde",
            model="USB Test",
            size_bytes=16_000_000_000,
            serial="SER-1",
            wwn="0x5000",
            transport="usb",
            removable=True,
            safe_for_rescue_write=True,
        )
        fake_proxy = mock.MagicMock()
        fake_size = mock.MagicMock()
        fake_size.unpack.return_value = 999  # Divergência proposital
        fake_proxy.get_cached_property.return_value = fake_size

        with mock.patch("gi.repository.Gio.bus_get_sync", return_value=mock.MagicMock()), mock.patch(
            "gi.repository.Gio.DBusProxy.new_sync", return_value=fake_proxy
        ):
            with self.assertRaises(RuntimeError):
                rescue.open_device_exclusive_udisks2(device_path="/dev/sde", expected_identity=cand)

    def test_built_core_deb_contains_maintainer_scripts_and_all_dbus_services(self) -> None:
        from mintsec import __version__

        repo_root = Path(__file__).resolve().parents[1]
        subprocess.run(["python3", str(repo_root / "scripts/build_debs.py")], check=True, stdout=subprocess.DEVNULL)
        core_deb = repo_root / f"dist/mint-security-suite-core_{__version__}_amd64.deb"
        self.assertTrue(core_deb.is_file())

        ctrl_dir = self.root / "ctrl"
        subprocess.run(["dpkg-deb", "--control", str(core_deb), str(ctrl_dir)], check=True)
        for script in ("postinst", "prerm", "postrm"):
            sp = ctrl_dir / script
            self.assertTrue(sp.is_file(), f"Script Debian ausente: {script}")
            self.assertTrue(os.access(sp, os.X_OK), f"Script Debian sem permissão +x: {script}")

        contents = subprocess.run(
            ["dpkg-deb", "--contents", str(core_deb)],
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        self.assertIn("org.mintsecurity.Network.service", contents)
        self.assertIn("org.mintsecurity.Browsing.service", contents)
        self.assertIn("org.mintsecurity.Isolation.service", contents)
        self.assertIn("org.mintsecurity.Rescue.service", contents)
        self.assertIn("mint-security-bank-mode", contents)


if __name__ == "__main__":
    unittest.main()
