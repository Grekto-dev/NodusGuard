#!/usr/bin/env python3
"""Gera pacotes .deb modulares da Suíte de Segurança usando dpkg-deb."""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from mintsec import __version__ as VERSION  # noqa: E402

DIST_DIR = ROOT / "dist"
TEMPLATE = (ROOT / "debian" / "control.template").read_text(encoding="utf-8")


def _copy_tree(src: Path, dst: Path) -> None:
    shutil.copytree(
        src,
        dst,
        ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        dirs_exist_ok=True,
    )


def _write_control(
    pkg_dir: Path,
    *,
    package: str,
    architecture: str,
    depends: str,
    suggests: str,
    short_description: str,
    long_description: str,
) -> None:
    debian_dir = pkg_dir / "DEBIAN"
    debian_dir.mkdir(parents=True, exist_ok=True)
    content = TEMPLATE.format(
        package=package,
        version=VERSION,
        architecture=architecture,
        depends=depends,
        suggests=suggests,
        short_description=short_description,
        long_description=long_description,
    )
    (debian_dir / "control").write_text(content, encoding="utf-8")


def _write_maintainer_scripts(pkg_dir: Path, *, is_core: bool = False, unit_name: str | None = None) -> None:
    """Cria scripts Debian postinst, prerm e postrm seguros para chroot e systemd."""
    debian_dir = pkg_dir / "DEBIAN"
    debian_dir.mkdir(parents=True, exist_ok=True)
    if is_core:
        postinst = (
            "#!/bin/sh\nset -e\n"
            "if [ -d /run/systemd/system ]; then\n"
            "  systemctl daemon-reload >/dev/null 2>&1 || true\n"
            "  systemctl reload dbus.service >/dev/null 2>&1 || true\n"
            "fi\n"
            "if command -v gtk-update-icon-cache >/dev/null 2>&1; then\n"
            "  gtk-update-icon-cache -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true\n"
            "fi\n"
            "exit 0\n"
        )
        prerm = (
            "#!/bin/sh\nset -e\n"
            "if [ \"$1\" = \"remove\" ] && [ -d /run/systemd/system ]; then\n"
            "  for u in mintsec-antimalware mintsec-firewall mintsec-recovery mintsec-network mintsec-browsing mintsec-isolation mintsec-rescue mintsec-containment; do\n"
            "    systemctl stop \"$u.service\" >/dev/null 2>&1 || true\n"
            "  done\n"
            "fi\n"
            "exit 0\n"
        )
        postrm = (
            "#!/bin/sh\nset -e\n"
            "if [ -d /run/systemd/system ]; then\n"
            "  systemctl daemon-reload >/dev/null 2>&1 || true\n"
            "fi\n"
            "if command -v gtk-update-icon-cache >/dev/null 2>&1; then\n"
            "  gtk-update-icon-cache -f -t /usr/share/icons/hicolor >/dev/null 2>&1 || true\n"
            "fi\n"
            "exit 0\n"
        )
    else:
        stop_cmd = (
            f"  systemctl stop {unit_name} >/dev/null 2>&1 || true\n"
            if unit_name
            else ""
        )
        postinst = (
            "#!/bin/sh\nset -e\n"
            "if [ -d /run/systemd/system ]; then\n"
            "  systemctl daemon-reload >/dev/null 2>&1 || true\n"
            "fi\n"
            "exit 0\n"
        )
        prerm = f"#!/bin/sh\nset -e\nif [ \"$1\" = \"remove\" ] && [ -d /run/systemd/system ]; then\n{stop_cmd}fi\nexit 0\n"
        postrm = postinst

    for name, body in (("postinst", postinst), ("prerm", prerm), ("postrm", postrm)):
        p = debian_dir / name
        p.write_text(body, encoding="utf-8")
        p.chmod(0o755)


def _build_deb(stage_dir: Path, out_name: str) -> Path:
    DIST_DIR.mkdir(parents=True, exist_ok=True)
    out_path = DIST_DIR / out_name
    subprocess.run(
        ["dpkg-deb", "--build", "--root-owner-group", str(stage_dir), str(out_path)],
        check=True,
    )
    return out_path


def build_all() -> list[Path]:
    outputs: list[Path] = []
    with tempfile.TemporaryDirectory(prefix="mintsec-deb-stage-") as tmp:
        tmp_root = Path(tmp)

        # 1. Pacote núcleo (.deb core com os 7 módulos em Suggests)
        core_dir = tmp_root / "core"
        py_dest = core_dir / "usr/lib/python3/dist-packages"
        _copy_tree(ROOT / "src/mintsec", py_dest / "mintsec")
        _copy_tree(ROOT / "src/mintsec_ui", py_dest / "mintsec_ui")

        usr_bin = core_dir / "usr/bin"
        usr_bin.mkdir(parents=True, exist_ok=True)
        for bin_name in (
            "mint-security-suite",
            "mint-security-dialog",
            "mint-security-apt-hook",
            "mint-security-bank-mode",
        ):
            dst = usr_bin / bin_name
            shutil.copy2(ROOT / "bin" / bin_name, dst)
            dst.chmod(0o755)

        for helper_rel in (
            "helpers/mintsec-netmon/mintsec-netmon",
            "helpers/mintsec-containment/mintsec-containment",
        ):
            hp = ROOT / helper_rel
            if hp.is_file():
                dst_h = usr_bin / hp.name
                shutil.copy2(hp, dst_h)
                dst_h.chmod(0o755)

        apt_conf_dir = core_dir / "etc/apt/apt.conf.d"
        apt_conf_dir.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "apt/99mintsec-trust-hooks", apt_conf_dir)

        daemon_shim = usr_bin / "mint-security-daemon"
        daemon_shim.write_text(
            "#!/usr/bin/env python3\nimport sys\nfrom mintsec.services.daemon import main\nsys.exit(main())\n",
            encoding="utf-8",
        )
        daemon_shim.chmod(0o755)

        agent_bin = ROOT / "agent/target/release/mint-security-agent"
        if agent_bin.is_file():
            dst_agent = usr_bin / "mint-security-agent"
            shutil.copy2(agent_bin, dst_agent)
            dst_agent.chmod(0o755)

        _copy_tree(ROOT / "manifests", core_dir / "usr/share/mint-security-suite/manifests")

        polkit_dst = core_dir / "usr/share/polkit-1/actions"
        polkit_dst.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "polkit/org.mintsecurity.suite.policy", polkit_dst)

        dbus_conf = core_dir / "etc/dbus-1/system.d"
        dbus_conf.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "dbus/org.mintsecurity.Suite.conf", dbus_conf)

        dbus_srv = core_dir / "usr/share/dbus-1/system-services"
        dbus_srv.mkdir(parents=True, exist_ok=True)
        for srv_file in (ROOT / "dbus").glob("*.service"):
            shutil.copy2(srv_file, dbus_srv)

        sys_units = core_dir / "usr/lib/systemd/system"
        sys_units.mkdir(parents=True, exist_ok=True)
        for unit in (ROOT / "systemd").glob("mintsec-*"):
            if unit.name == "mintsec-session-agent.service":
                continue
            shutil.copy2(unit, sys_units)

        usr_units = core_dir / "usr/lib/systemd/user"
        usr_units.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "systemd/mintsec-session-agent.service", usr_units)

        for size_label, asset_name in (
            ("48x48", "nodusguard_icon_48.png"),
            ("64x64", "nodusguard_icon_64.png"),
            ("128x128", "nodusguard_logo.png"),
            ("256x256", "nodusguard_icon_256.png"),
        ):
            icon_src = ROOT / "src/mintsec_ui/assets" / asset_name
            if icon_src.is_file():
                icon_dir = core_dir / f"usr/share/icons/hicolor/{size_label}/apps"
                icon_dir.mkdir(parents=True, exist_ok=True)
                shutil.copy2(icon_src, icon_dir / "nodusguard.png")

        tray_dir = core_dir / "usr/share/icons/hicolor/48x48/apps"
        tray_dir.mkdir(parents=True, exist_ok=True)
        for tray_name in (
            "nodusguard_tray_ok.png",
            "nodusguard_tray_alert.png",
            "nodusguard_tray_paused.png",
        ):
            tray_src = ROOT / "src/mintsec_ui/assets" / tray_name
            if tray_src.is_file():
                shutil.copy2(tray_src, tray_dir / tray_name)

        apps_dir = core_dir / "usr/share/applications"
        apps_dir.mkdir(parents=True, exist_ok=True)
        (apps_dir / "nodusguard.desktop").write_text(
            "[Desktop Entry]\n"
            "Type=Application\n"
            "Name=NodusGuard\n"
            "GenericName=Computer Protection\n"
            "GenericName[pt_BR]=Proteção do computador\n"
            "Comment=Clear, transparent protection for your computer\n"
            "Comment[pt_BR]=Proteção direta e transparente para o computador\n"
            "Exec=mint-security-suite\n"
            "Icon=nodusguard\n"
            "Terminal=false\n"
            "Categories=System;Security;\n",
            encoding="utf-8",
        )

        suggests_all = (
            "gir1.2-xapp-1.0, "
            "gir1.2-ayatanaappindicator3-0.1, "
            "mint-security-suite-antimalware, "
            "mint-security-suite-firewall, "
            "mint-security-suite-backup, "
            "mint-security-suite-network, "
            "mint-security-suite-browsing, "
            "mint-security-suite-isolation, "
            "mint-security-suite-rescue, "
            "mint-security-suite-nemo, "
            "mint-security-suite-caja, "
            "mint-security-suite-thunar"
        )
        _write_control(
            core_dir,
            package="mint-security-suite-core",
            architecture="amd64",
            depends=(
                "python3 (>= 3.12), python3-gi, gir1.2-gtk-3.0, gir1.2-atk-1.0, "
                "gir1.2-notify-0.7, gir1.2-udisks-2.0, python3-dbus, python3-apt, "
                "aptkit"
            ),
            suggests=suggests_all,
            short_description="NodusGuard core library, GTK 3 interface, and Rust session agent",
            long_description=(
                "Provides the unified NodusGuard control panel, versioned module contracts,\n"
                " Polkit authorization rules, optional WAL SQLite event history, and Rust session agent."
            ),
        )
        _write_maintainer_scripts(core_dir, is_core=True)
        outputs.append(_build_deb(core_dir, f"mint-security-suite-core_{VERSION}_amd64.deb"))

        # 2. Individual module packages for all 7 protections
        module_specs = [
            (
                "mint-security-suite-antimalware",
                "mint-security-suite-core, clamav, clamav-freshclam",
                "clamav-daemon",
                "NodusGuard Antivirus module",
                "Integrates unprivileged ClamAV scans, FreshClam updates, schedules, and confirmed quarantine.",
            ),
            (
                "mint-security-suite-firewall",
                "mint-security-suite-core, ufw",
                "opensnitch",
                "NodusGuard Network Shield (Firewall) module",
                "Integrates UFW incoming firewall protection and per-application OpenSnitch outbound contract.",
            ),
            (
                "mint-security-suite-backup",
                "mint-security-suite-core, timeshift, restic",
                "btrfs-progs",
                "NodusGuard File Backups & Recovery module",
                "Integrates Timeshift system snapshots, encrypted restic backups, and incident recovery.",
            ),
            (
                "mint-security-suite-network",
                "mint-security-suite-core, network-manager, iproute2",
                "",
                "NodusGuard Wi-Fi Network module",
                "Local Wi-Fi device inventory using NetworkManager and a CAP_NET_RAW ARP/DHCP helper.",
            ),
            (
                "mint-security-suite-browsing",
                "mint-security-suite-core, dnsmasq-base",
                "dnscrypt-proxy",
                "NodusGuard Safe Browsing module",
                "Local DNS filtering against phishing, malware, and cryptomining while preserving VPN split domains.",
            ),
            (
                "mint-security-suite-isolation",
                "mint-security-suite-core, bubblewrap, apparmor",
                "apparmor-utils",
                "NodusGuard Protected Browser & Isolation module",
                "AppArmor enforcement inspection, update awareness, bubblewrap Protected Browser, and experimental Bank Mode.",
            ),
            (
                "mint-security-suite-rescue",
                "mint-security-suite-core, udisks2, gpgv",
                "cryptsetup, squashfs-tools",
                "NodusGuard Emergency USB Rescue module",
                "GPG signature verification and exclusive UDisks2 imaging for offline rescue USB media.",
            ),
        ]
        for pkg_name, deps, sugg, sdesc, ldesc in module_specs:
            mdir = tmp_root / pkg_name
            doc_dir = mdir / "usr/share/doc" / pkg_name
            doc_dir.mkdir(parents=True, exist_ok=True)
            (doc_dir / "README").write_text(f"{sdesc}\n", encoding="utf-8")
            _write_control(
                mdir,
                package=pkg_name,
                architecture="all",
                depends=deps,
                suggests=sugg,
                short_description=sdesc,
                long_description=ldesc,
            )
            unit_map = {
                "mint-security-suite-antimalware": "mintsec-antimalware.service",
                "mint-security-suite-firewall": "mintsec-firewall.service",
                "mint-security-suite-backup": "mintsec-recovery.service",
                "mint-security-suite-network": "mintsec-network.service",
                "mint-security-suite-browsing": "mintsec-browsing.service",
                "mint-security-suite-isolation": "mintsec-isolation.service",
                "mint-security-suite-rescue": "mintsec-rescue.service",
            }
            _write_maintainer_scripts(mdir, is_core=False, unit_name=unit_map.get(pkg_name))
            outputs.append(_build_deb(mdir, f"{pkg_name}_{VERSION}_all.deb"))

        # 3. File-manager context-menu integration packages (Nemo, Caja, Thunar)
        nemo_dir = tmp_root / "mint-security-suite-nemo"
        nemo_actions = nemo_dir / "usr/share/nemo/actions"
        nemo_actions.mkdir(parents=True, exist_ok=True)
        shutil.copy2(
            ROOT / "integrations/nemo/mintsec-previous-versions.nemo_action",
            nemo_actions,
        )
        _write_control(
            nemo_dir,
            package="mint-security-suite-nemo",
            architecture="all",
            depends="mint-security-suite-core, nemo",
            suggests="mint-security-suite-backup",
            short_description="Previous versions integration for Nemo",
            long_description="Adds a 'Previous versions…' action to the Nemo file manager context menu.",
        )
        outputs.append(_build_deb(nemo_dir, f"mint-security-suite-nemo_{VERSION}_all.deb"))

        caja_dir = tmp_root / "mint-security-suite-caja"
        caja_scripts = caja_dir / "usr/share/caja/scripts"
        caja_scripts.mkdir(parents=True, exist_ok=True)
        caja_dst = caja_scripts / "Versões anteriores…"
        shutil.copy2(ROOT / "integrations/caja/mintsec-previous-versions.sh", caja_dst)
        caja_dst.chmod(0o755)
        _write_control(
            caja_dir,
            package="mint-security-suite-caja",
            architecture="all",
            depends="mint-security-suite-core, caja",
            suggests="mint-security-suite-backup",
            short_description="Previous versions integration for Caja",
            long_description="Adds a previous-versions recovery script to the Caja (MATE) context menu.",
        )
        outputs.append(_build_deb(caja_dir, f"mint-security-suite-caja_{VERSION}_all.deb"))

        thunar_dir = tmp_root / "mint-security-suite-thunar"
        thunar_share = thunar_dir / "usr/share/mint-security-suite/thunar"
        thunar_share.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / "integrations/thunar/uca-entry.xml", thunar_share)
        _write_control(
            thunar_dir,
            package="mint-security-suite-thunar",
            architecture="all",
            depends="mint-security-suite-core, thunar",
            suggests="mint-security-suite-backup",
            short_description="Previous versions integration for Thunar",
            long_description="Provides a custom UCA entry for previous-versions recovery in Thunar (Xfce).",
        )
        outputs.append(_build_deb(thunar_dir, f"mint-security-suite-thunar_{VERSION}_all.deb"))

    return outputs


if __name__ == "__main__":
    built = build_all()
    for p in built:
        print(p)
