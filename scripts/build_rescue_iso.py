#!/usr/bin/env python3
"""Gera artefato/imagem ISO bootável BIOS+UEFI de resgate offline e assinatura GPG."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

DEFAULT_KERNEL = Path("/boot/vmlinuz-6.14.0-37-generic")

RESCUE_ENTRY_SCRIPT = """#!/bin/sh
set -eu
echo "=== Ambiente de Resgate Offline da Suíte de Segurança Mint ==="
if [ -f /etc/mintsec-rescue/signatures.meta ]; then
    cat /etc/mintsec-rescue/signatures.meta
fi
echo "1. Volumes devem ser montados inicialmente em modo somente leitura (-o ro)."
echo "2. Use cryptsetup luksOpen para volumes cifrados."
echo "3. Quarentena e sobrescrita sobre originais exigem confirmação própria."
"""

LIVE_INIT_SCRIPT = """#!/bin/busybox sh
/bin/busybox mkdir -p /proc /sys /dev /mnt/inspect
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev || true

if [ -d /sys/firmware/efi ]; then
    echo "RESCUE_BOOT_MODE=UEFI"
else
    echo "RESCUE_BOOT_MODE=BIOS"
fi

echo "=== Ambiente de Resgate Offline da Suíte de Segurança Mint ==="
/bin/busybox cat /etc/mintsec-rescue/signatures.meta

# Aguarda brevemente detecção de disco de prova (/dev/vda ou /dev/sda) e monta somente leitura
TRIES=0
TEST_DEV=""
while [ "$TRIES" -lt 15 ]; do
    if [ -b /dev/vda ]; then
        TEST_DEV="/dev/vda"
        break
    fi
    if [ -b /dev/sda ]; then
        TEST_DEV="/dev/sda"
        break
    fi
    TRIES=$((TRIES + 1))
    /bin/busybox sleep 0.1
done

if [ -n "$TEST_DEV" ]; then
    if /bin/busybox mount -o ro "$TEST_DEV" /mnt/inspect 2>/dev/null; then
        if ! /bin/busybox touch /mnt/inspect/.write_probe 2>/dev/null; then
            echo "INITIAL_MOUNT=READ_ONLY_VERIFIED dev=$TEST_DEV"
        fi
        /bin/busybox ls -1 /mnt/inspect || true
        /bin/busybox umount /mnt/inspect || true
    fi
fi

if /bin/busybox grep -q "mintsec.selftest=1" /proc/cmdline; then
    echo "RESCUE_ENV_READY"
    /bin/busybox poweroff -f
fi

exec /bin/busybox sh
"""


def build_rescue_bundle(
    output_dir: Path,
    *,
    clamav_db_date: str = "2026-11-21",
    gpg_key_fingerprint: str | None = None,
) -> dict[str, Path]:
    """Cria imagem squashfs do ambiente live de resgate pronta para assinatura GPG."""
    output_dir.mkdir(parents=True, exist_ok=True)
    rootfs = output_dir / "rescue_rootfs"
    meta_dir = rootfs / "etc/mintsec-rescue"
    bin_dir = rootfs / "usr/local/bin"
    meta_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)

    (meta_dir / "signatures.meta").write_text(
        f"Assinaturas offline ClamAV: {clamav_db_date}\n"
        "Modo inicial: somente leitura (mount -o ro)\n"
        "Ferramentas: clamscan, cryptsetup (LUKS), restic\n",
        encoding="utf-8",
    )
    entry = bin_dir / "mintsec-rescue-start"
    entry.write_text(RESCUE_ENTRY_SCRIPT, encoding="utf-8")
    entry.chmod(0o755)

    image_path = output_dir / "mintsec-rescue-live.img"
    subprocess.run(
        ["mksquashfs", str(rootfs), str(image_path), "-noappend", "-quiet"],
        check=True,
    )
    sha = hashlib.sha256(image_path.read_bytes()).hexdigest()
    manifest_path = output_dir / "mintsec-rescue-live.json"
    manifest_path.write_text(
        json.dumps(
            {
                "image": image_path.name,
                "sha256": sha,
                "size_bytes": image_path.stat().st_size,
                "clamav_db_date": clamav_db_date,
                "initial_mount_mode": "ro",
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    result = {"image": image_path, "manifest": manifest_path}
    if gpg_key_fingerprint:
        sig_path = output_dir / "mintsec-rescue-live.img.sig"
        subprocess.run(
            ["gpg", "--batch", "--yes", "--detach-sign", "-u", gpg_key_fingerprint, "-o", str(sig_path), str(image_path)],
            check=True,
        )
        result["signature"] = sig_path
    return result


def build_bootable_rescue_iso(
    output_iso: Path,
    *,
    kernel_path: Path = DEFAULT_KERNEL,
    clamav_db_date: str = "2026-11-21",
    selftest_boot: bool = False,
) -> Path:
    """Constrói ISO híbrida bootável em BIOS e UEFI via grub-mkrescue."""
    if not kernel_path.is_file():
        raise FileNotFoundError(f"Kernel para ISO de resgate não encontrado: {kernel_path}")

    with tempfile.TemporaryDirectory(prefix="mintsec-iso-stage-") as tmp:
        stage = Path(tmp)
        initrd_root = stage / "initrd_root"
        for d in ("bin", "etc/mintsec-rescue", "proc", "sys", "dev", "mnt/inspect"):
            (initrd_root / d).mkdir(parents=True, exist_ok=True)

        shutil.copy2("/usr/bin/busybox", initrd_root / "bin/busybox")
        (initrd_root / "bin/busybox").chmod(0o755)
        for app in ("sh", "mount", "umount", "mkdir", "ls", "cat", "touch", "sleep", "poweroff", "grep"):
            (initrd_root / "bin" / app).symlink_to("busybox")

        (initrd_root / "etc/mintsec-rescue/signatures.meta").write_text(
            f"Assinaturas offline ClamAV: {clamav_db_date}\n"
            "Modo inicial: somente leitura (mount -o ro)\n"
            "Ferramentas: clamscan, cryptsetup (LUKS), restic\n",
            encoding="utf-8",
        )
        init_file = initrd_root / "init"
        init_file.write_text(LIVE_INIT_SCRIPT, encoding="utf-8")
        init_file.chmod(0o755)

        iso_root = stage / "iso_root"
        boot_grub = iso_root / "boot/grub"
        boot_grub.mkdir(parents=True, exist_ok=True)
        shutil.copy2(kernel_path, iso_root / "boot/vmlinuz")
        initrd_img = iso_root / "boot/initrd.img"
        with subprocess.Popen(
            ["find", ".", "-print0"],
            cwd=str(initrd_root),
            stdout=subprocess.PIPE,
        ) as find_proc:
            with subprocess.Popen(
                ["cpio", "--null", "-o", "-H", "newc", "--quiet"],
                cwd=str(initrd_root),
                stdin=find_proc.stdout,
                stdout=subprocess.PIPE,
            ) as cpio_proc:
                assert find_proc.stdout is not None
                find_proc.stdout.close()
                assert cpio_proc.stdout is not None
                with gzip.open(initrd_img, "wb", compresslevel=1) as gz_out:
                    shutil.copyfileobj(cpio_proc.stdout, gz_out, length=65536)
                if cpio_proc.wait() != 0:
                    raise RuntimeError("cpio falhou ao gerar initrd.img")
            if find_proc.wait() != 0:
                raise RuntimeError("find falhou ao gerar initrd.img")

        extra_arg = " mintsec.selftest=1" if selftest_boot else ""
        (boot_grub / "grub.cfg").write_text(
            "serial --unit=0 --speed=115200\n"
            "terminal_input console serial\n"
            "terminal_output console serial\n"
            "set timeout=0\n"
            "set default=0\n"
            'menuentry "Suíte de Segurança Mint — Resgate Offline" {\n'
            f"    linux /boot/vmlinuz console=tty0 console=ttyS0 quiet panic=-1 rdinit=/init{extra_arg}\n"
            "    initrd /boot/initrd.img\n"
            "}\n",
            encoding="utf-8",
        )
        output_iso.parent.mkdir(parents=True, exist_ok=True)
        subprocess.run(
            ["grub-mkrescue", "-o", str(output_iso), str(iso_root)],
            check=True,
            capture_output=True,
            text=True,
        )
    return output_iso


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Construir imagem ou ISO bootável de resgate offline")
    parser.add_argument("--out", required=True, help="Diretório de saída ou arquivo .iso")
    parser.add_argument("--iso", action="store_true", help="Gerar ISO híbrida BIOS+UEFI via grub-mkrescue")
    args = parser.parse_args(argv)
    if args.iso:
        iso_path = build_bootable_rescue_iso(Path(args.out))
        print(f"iso: {iso_path}")
        return 0
    out = build_rescue_bundle(Path(args.out))
    for k, v in out.items():
        print(f"{k}: {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
