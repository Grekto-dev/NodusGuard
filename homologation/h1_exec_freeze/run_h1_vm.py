"""Executa o ensaio H1 real (FAN_OPEN_EXEC_PERM + cgroup.freeze) em micro-VM QEMU/KVM 6.14."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

DEFAULT_KERNEL = Path("/boot/vmlinuz-6.14.0-37-generic")

INIT_SCRIPT = """#!/bin/busybox sh
set -eu
/bin/busybox mkdir -p /proc /sys /dev /sys/fs/cgroup /run/h1
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sysfs /sys
/bin/busybox mount -t devtmpfs devtmpfs /dev || true
/bin/busybox mount -t cgroup2 none /sys/fs/cgroup
/bin/busybox mount -t tmpfs tmpfs /run/h1
/bin/busybox cp /bin/marker /run/h1/marker
/bin/busybox chmod 0755 /run/h1/marker

echo "H1_VM_KERNEL=$(/bin/busybox uname -r)"
if /usr/bin/mintsec-containment --h1-vm-test /run/h1 /run/h1/marker /bin/launcher; then
    echo "H1_VM_EXIT=0"
else
    echo "H1_VM_EXIT=1"
fi
/bin/busybox poweroff -f
"""


def build_h1_initramfs(repo_root: Path, out_cpio_gz: Path) -> None:
    """Constrói initramfs mínima contendo busybox, glibc, marker, launcher e mintsec-containment."""
    h1_dir = repo_root / "homologation/h1_exec_freeze"
    containment_bin = repo_root / "helpers/mintsec-containment/mintsec-containment"

    with tempfile.TemporaryDirectory(prefix="mintsec-h1-initrd-") as tmp:
        root = Path(tmp)
        for d in (
            "bin",
            "usr/bin",
            "lib64",
            "lib/x86_64-linux-gnu",
            "usr/lib/x86_64-linux-gnu",
            "proc",
            "sys",
            "dev",
            "run/h1",
        ):
            (root / d).mkdir(parents=True, exist_ok=True)

        shutil.copy2("/usr/bin/busybox", root / "bin/busybox")
        (root / "bin/busybox").chmod(0o755)
        for applet in ("sh", "mount", "mkdir", "cp", "chmod", "uname", "poweroff"):
            (root / "bin" / applet).symlink_to("busybox")

        # Bibliotecas dinâmicas mínimas para mintsec-containment e launcher
        shutil.copy2("/lib64/ld-linux-x86-64.so.2", root / "lib64/ld-linux-x86-64.so.2")
        shutil.copy2("/usr/lib/x86_64-linux-gnu/libc.so.6", root / "lib/x86_64-linux-gnu/libc.so.6")
        shutil.copy2(containment_bin, root / "usr/bin/mintsec-containment")
        (root / "usr/bin/mintsec-containment").chmod(0o755)

        subprocess.run(
            ["gcc", "-nostdlib", "-static", "-O2", str(h1_dir / "marker.c"), "-o", str(root / "bin/marker")],
            check=True,
        )
        subprocess.run(
            ["gcc", "-O2", "-Wall", "-Wextra", "-Werror", str(h1_dir / "launcher.c"), "-o", str(root / "bin/launcher")],
            check=True,
        )

        init_path = root / "init"
        init_path.write_text(INIT_SCRIPT, encoding="utf-8")
        init_path.chmod(0o755)

        out_cpio_gz.parent.mkdir(parents=True, exist_ok=True)
        cpio_proc = subprocess.run(
            ["sh", "-c", f'cd "{root}" && find . -print0 | cpio --null -o -H newc --quiet | gzip -1 > "{out_cpio_gz}"'],
            check=True,
            capture_output=True,
            text=True,
        )
        _ = cpio_proc


def run_h1_vm(repo_root: Path, kernel_path: Path = DEFAULT_KERNEL) -> dict[str, Any]:
    """Executa micro-VM QEMU/KVM validando FAN_OPEN_EXEC_PERM + cgroup.freeze ao vivo."""
    if not kernel_path.is_file() or not os_readable(kernel_path):
        return {
            "executed": False,
            "ok": False,
            "reason": f"Kernel {kernel_path} não legível sem privilégios.",
        }

    with tempfile.TemporaryDirectory(prefix="mintsec-h1-vm-") as tmp:
        initrd = Path(tmp) / "h1-initramfs.cpio.gz"
        build_h1_initramfs(repo_root, initrd)

        cmd = ["qemu-system-x86_64"]
        if Path("/dev/kvm").exists():
            cmd.extend(["-enable-kvm", "-cpu", "host"])
        cmd.extend(
            [
                "-m",
                "256M",
                "-kernel",
                str(kernel_path),
                "-initrd",
                str(initrd),
                "-display",
                "none",
                "-monitor",
                "none",
                "-no-reboot",
                "-serial",
                "stdio",
                "-append",
                "console=ttyS0 quiet panic=-1 rdinit=/init",
            ]
        )
        res = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=35,
        )
        output = res.stdout + "\n" + res.stderr
        kernel_line = ""
        mode_lines: list[str] = []
        for ln in output.splitlines():
            if ln.startswith("H1_VM_KERNEL="):
                kernel_line = ln.split("=", 1)[1].strip()
            elif ln.startswith("H1_MODE_OK "):
                mode_lines.append(ln.strip())

        passed = (
            "H1_VM_ALL_PASS" in output
            and "H1_SIGKILL_RECOVERY_OK" in output
            and "H1_VM_EXIT=0" in output
            and len(mode_lines) == 3
        )
        return {
            "executed": True,
            "ok": passed,
            "kernel_version": kernel_line or kernel_path.name,
            "mode_measurements": mode_lines,
            "sigkill_recovery_ok": "H1_SIGKILL_RECOVERY_OK" in output,
            "raw_tail": output[-1200:] if not passed else "",
        }


def os_readable(path: Path) -> bool:
    import os

    return os.access(path, os.R_OK)
