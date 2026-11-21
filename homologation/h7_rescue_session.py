"""Ensaio H7: proteção de disco sistema/LUKS/LVM/RAID, mídia trocada, GPG e Modo Banco."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import load_manifests
from mintsec.history import HistoryStore
from mintsec.pending import PendingStore
from mintsec.runner import SubprocessRunner
from mintsec.services.isolation import IsolationService
from mintsec.services.rescue import RescueService, evaluate_block_devices
from scripts.build_rescue_iso import build_bootable_rescue_iso, build_rescue_bundle


def run_h7(repo_root: Path) -> dict[str, Any]:
    manifests = load_manifests()
    with tempfile.TemporaryDirectory(prefix="mintsec-h7-") as tmp:
        tmp_path = Path(tmp)
        runner = SubprocessRunner()
        common = dict(
            config_store=ConfigStore(tmp_path / "settings.json"),
            pending_store=PendingStore(tmp_path / "pending.json"),
            history_store=HistoryStore(tmp_path / "history.db"),
            runner=runner,
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=tmp_path / "data",
        )
        rescue = RescueService(manifest=manifests["rescue"], **common)
        isolation = IsolationService(manifest=manifests["isolation"], **common)

        # 1. Valida árvore real do host: nenhum disco de sistema deve ser elegível
        host_candidates, host_protected = rescue.list_block_candidates()
        assert len(host_protected) >= 1
        for cand in host_candidates:
            if cand.name in host_protected:
                assert not cand.safe_for_rescue_write

        # 2. Valida topologia complexa LUKS + LVM + RAID + swap + mídia segura
        mock_lsblk = {
            "blockdevices": [
                {
                    "name": "sda",
                    "kname": "sda",
                    "path": "/dev/sda",
                    "type": "disk",
                    "size": 500107862016,
                    "model": "DiskA",
                    "serial": "S1",
                    "wwn": "W1",
                    "tran": "sata",
                    "rm": False,
                    "children": [
                        {
                            "name": "sda1",
                            "kname": "sda1",
                            "type": "part",
                            "pkname": "sda",
                            "children": [
                                {
                                    "name": "md0",
                                    "kname": "md0",
                                    "type": "raid1",
                                    "pkname": "sda1",
                                    "children": [
                                        {
                                            "name": "luks-root",
                                            "kname": "dm-0",
                                            "type": "crypt",
                                            "pkname": "md0",
                                            "children": [
                                                {
                                                    "name": "vg-root",
                                                    "kname": "dm-1",
                                                    "type": "lvm",
                                                    "pkname": "dm-0",
                                                    "mountpoint": "/",
                                                },
                                                {
                                                    "name": "vg-swap",
                                                    "kname": "dm-2",
                                                    "type": "lvm",
                                                    "pkname": "dm-0",
                                                    "fstype": "swap",
                                                    "mountpoint": "[SWAP]",
                                                },
                                            ],
                                        }
                                    ],
                                }
                            ],
                        }
                    ],
                },
                {
                    "name": "sdb",
                    "kname": "sdb",
                    "path": "/dev/sdb",
                    "type": "disk",
                    "size": 500107862016,
                    "model": "DiskB",
                    "serial": "S2",
                    "wwn": "W2",
                    "tran": "sata",
                    "rm": False,
                    "children": [
                        {
                            "name": "sdb1",
                            "kname": "sdb1",
                            "type": "part",
                            "pkname": "sdb",
                            "children": [
                                {"name": "md0", "kname": "md0", "type": "raid1", "pkname": "sdb1"}
                            ],
                        }
                    ],
                },
                {
                    "name": "sdc",
                    "kname": "sdc",
                    "path": "/dev/sdc",
                    "type": "disk",
                    "size": 16000000000,
                    "model": "USB Rescue",
                    "serial": "USB-999",
                    "wwn": "0x5000usb",
                    "tran": "usb",
                    "rm": True,
                },
            ]
        }
        cands, prot = evaluate_block_devices(mock_lsblk)
        by_name = {c.name: c for c in cands}
        assert not by_name["sda"].safe_for_rescue_write and "sda" in prot
        assert not by_name["sdb"].safe_for_rescue_write and "sdb" in prot
        assert by_name["sdc"].safe_for_rescue_write

        # 3. Gera imagem live real, assina com chave GPG efêmera, verifica com gpgv e grava/confere bytes
        gnupg_home = tmp_path / "gnupg"
        gnupg_home.mkdir(mode=0o700)
        gpg_env = dict(os.environ)
        gpg_env["GNUPGHOME"] = str(gnupg_home)
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--pinentry-mode",
                "loopback",
                "--no-tty",
                "--passphrase",
                "",
                "--quick-generate-key",
                "MintSec H7 <h7@example.org>",
                "default",
                "default",
                "never",
            ],
            env=gpg_env,
            check=True,
            timeout=15,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        bundle = build_rescue_bundle(tmp_path / "rescue_out")
        sig_path = tmp_path / "rescue_out/mintsec-rescue-live.img.sig"
        subprocess.run(
            [
                "gpg",
                "--batch",
                "--yes",
                "--pinentry-mode",
                "loopback",
                "--no-tty",
                "--passphrase",
                "",
                "--detach-sign",
                "-o",
                str(sig_path),
                str(bundle["image"]),
            ],
            env=gpg_env,
            check=True,
            timeout=15,
        )
        keyring_kbx = tmp_path / "pub.gpg"
        subprocess.run(
            ["gpg", "--batch", "--no-tty", "--export", "-o", str(keyring_kbx)],
            env=gpg_env,
            check=True,
            timeout=15,
        )
        sig_res = rescue.verify_image_signature(
            image_path=bundle["image"],
            signature_path=sig_path,
            keyring_path=keyring_kbx,
        )
        assert sig_res["ok"]

        # Rejeição de mídia trocada (serial divergente na reabertura)
        fake_usb_target = tmp_path / "usb_block.img"
        swapped = type(by_name["sdc"])(**{**by_name["sdc"].to_dict(), "serial": "OUTRO-SERIAL"})
        swapped_refused = False
        try:
            rescue.validate_and_write_image(
                image_path=bundle["image"],
                target_path=fake_usb_target,
                expected_identity=by_name["sdc"],
                reopened_identity=swapped,
                confirmed=True,
            )
        except RuntimeError:
            swapped_refused = True
        assert swapped_refused

        # Gravação válida com conferência integral de bytes SHA-256
        write_res = rescue.validate_and_write_image(
            image_path=bundle["image"],
            target_path=fake_usb_target,
            expected_identity=by_name["sdc"],
            reopened_identity=by_name["sdc"],
            confirmed=True,
        )
        assert write_res["ok"] and write_res["bytes_written"] == bundle["image"].stat().st_size

        # 4. Boot real em QEMU/KVM (BIOS e UEFI) da ISO híbrida + montagem inicial somente leitura
        iso_path = tmp_path / "mintsec-rescue-selftest.iso"
        build_bootable_rescue_iso(iso_path, selftest_boot=True)
        disk_src = tmp_path / "probe_disk_src"
        disk_src.mkdir()
        (disk_src / "amostra_resgate.txt").write_text("protegido", encoding="utf-8")
        probe_disk = tmp_path / "probe_disk.ext4"
        subprocess.run(["/sbin/mkfs.ext4", "-q", "-d", str(disk_src), str(probe_disk), "16M"], check=True)

        kvm_args = ["-enable-kvm", "-cpu", "host"] if Path("/dev/kvm").exists() else []
        bios_res = subprocess.run(
            [
                "qemu-system-x86_64",
                *kvm_args,
                "-m",
                "256M",
                "-cdrom",
                str(iso_path),
                "-drive",
                f"file={probe_disk},format=raw,if=virtio",
                "-display",
                "none",
                "-monitor",
                "none",
                "-no-reboot",
                "-serial",
                "stdio",
            ],
            capture_output=True,
            text=True,
            timeout=35,
            check=True,
        )
        assert "RESCUE_BOOT_MODE=BIOS" in bios_res.stdout
        assert "INITIAL_MOUNT=READ_ONLY_VERIFIED" in bios_res.stdout
        assert "RESCUE_ENV_READY" in bios_res.stdout

        uefi_ok = False
        ovmf_code = Path("/usr/share/OVMF/OVMF_CODE_4M.fd")
        ovmf_vars_src = Path("/usr/share/OVMF/OVMF_VARS_4M.fd")
        if ovmf_code.is_file() and ovmf_vars_src.is_file():
            ovmf_vars = tmp_path / "OVMF_VARS.fd"
            ovmf_vars.write_bytes(ovmf_vars_src.read_bytes())
            uefi_res = subprocess.run(
                [
                    "qemu-system-x86_64",
                    *kvm_args,
                    "-m",
                    "256M",
                    "-drive",
                    f"if=pflash,format=raw,readonly=on,file={ovmf_code}",
                    "-drive",
                    f"if=pflash,format=raw,file={ovmf_vars}",
                    "-cdrom",
                    str(iso_path),
                    "-drive",
                    f"file={probe_disk},format=raw,if=virtio",
                    "-display",
                    "none",
                    "-monitor",
                    "none",
                    "-no-reboot",
                    "-serial",
                    "stdio",
                ],
                capture_output=True,
                text=True,
                timeout=35,
                check=True,
            )
            assert "RESCUE_BOOT_MODE=UEFI" in uefi_res.stdout
            assert "INITIAL_MOUNT=READ_ONLY_VERIFIED" in uefi_res.stdout
            assert "RESCUE_ENV_READY" in uefi_res.stdout
            uefi_ok = True

        # 5. Navegador Isolado (bwrap) + Modo Banco aninhado Xephyr
        bwrap_smoke = isolation.smoke_test_bwrap()
        assert bwrap_smoke["ok"]
        bank_nested = isolation.run_bank_mode_nested_test()
        assert bank_nested["ok"]
        bank_spec = isolation.build_bank_mode_spec()
        assert bank_spec["experimental"] is True

    return {
        "assay": "H7",
        "status": "EXPERIMENTAL_PENDING_HARDWARE",
        "host_protected_block_nodes": len(host_protected),
        "luks_lvm_raid_refusal_verified": True,
        "swapped_media_refused": True,
        "gpgv_signature_and_byte_readback_verified": True,
        "qemu_bios_boot_ro_verified": True,
        "qemu_uefi_boot_ro_verified": uefi_ok,
        "bwrap_unprivileged_smoke_ok": True,
        "bank_mode_nested_xephyr_ok": True,
        "bank_mode_status": "experimental",
        "pending_hardware": (
            "Boot físico em mídia USB sob Secure Boot assinado e matriz gráfica do Modo Banco "
            "(Intel antiga, Nouveau, modesetting, áudio e retorno ao VT físico) pendentes de hardware dedicado."
        ),
    }
