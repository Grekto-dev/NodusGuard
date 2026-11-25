"""Testes para exceções de aplicativos no firewall e aplicação automática de recomendações."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import ModuleState, load_manifests
from mintsec.dbus_client import SystemModuleClient
from mintsec.firewall_apps import (
    detect_app_presets,
    detect_listening_apps,
    detect_local_lan_cidr,
    list_ufw_app_profiles,
)
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult, SubprocessRunner
from mintsec.services.catalog import SuiteController
from mintsec.services.daemon import ModuleDBusService


class _RecordingAuthorizer(CallerAuthorizer):
    def __init__(self, *, decision: bool = True) -> None:
        super().__init__(test_decision=decision)
        self.calls: list[tuple[str, str | None, int | None]] = []

    def get_dbus_caller_uid(self, sender_bus_name: str, bus: object | None = None) -> int:
        return 1000

    def require(
        self,
        action_id: str,
        *,
        sender_bus_name: str | None = None,
        caller_uid: int | None = None,
        allow_interaction: bool = True,
    ):
        self.calls.append((action_id, sender_bus_name, caller_uid))
        return super().require(
            action_id,
            sender_bus_name=sender_bus_name,
            caller_uid=caller_uid,
            allow_interaction=allow_interaction,
        )


class _RichFirewallRunner:
    def __init__(self, *, binaries: set[str] | None = None, db_dir: Path | None = None) -> None:
        self.binaries = binaries if binaries is not None else {
            "ufw", "ip", "ss", "kdeconnectd", "clamscan", "freshclam", "dnsmasq",
        }
        self.db_dir = db_dir
        self.active = False
        self.commands: list[list[str]] = []
        self.live_rules: list[tuple[str, str, str]] = [("22/tcp", "ALLOW IN", "Anywhere")]
        self.ss_output = (
            'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=900,fd=14))\n'
            'udp UNCONN 0 0 *:1716 0.0.0.0:* users:(("kdeconnectd",pid=2151,fd=18))\n'
            'tcp LISTEN 0 50 *:1716 0.0.0.0:* users:(("kdeconnectd",pid=2151,fd=19))\n'
            'tcp LISTEN 0 32 *:59100 0.0.0.0:* users:(("AudioRelay",pid=3310,fd=11))\n'
            'tcp LISTEN 0 32 *:9090 0.0.0.0:* users:(("devserver",pid=4100,fd=8))\n'
        )
        self.ip_output = "2: enp4s0    inet 192.168.3.166/24 brd 192.168.3.255 scope global enp4s0\n"

    def which(self, binary: str) -> str | None:
        if binary in self.binaries:
            if binary in ("ufw", "ip", "ss"):
                return f"/usr/sbin/{binary}"
            return f"/usr/bin/{binary}"
        return None

    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None, pause_event=None) -> CommandResult:
        cmd = [str(a) for a in argv]
        self.commands.append(cmd)
        name = Path(cmd[0]).name

        if name == "dpkg-query":
            pkg = cmd[-1]
            if pkg in ("ufw", "clamav", "clamav-freshclam", "dnsmasq-base"):
                return CommandResult(tuple(cmd), 0, "install ok installed\t1.0.0\n", "")
            return CommandResult(tuple(cmd), 1, "", "not installed")
        if name == "apt-cache":
            return CommandResult(
                tuple(cmd),
                0,
                " *** 1.0.0 500\n        500 http://archive.ubuntu.com/ubuntu noble/main amd64 Packages\n",
                "",
            )
        if name == "ip":
            return CommandResult(tuple(cmd), 0, self.ip_output, "")
        if name == "ss":
            return CommandResult(tuple(cmd), 0, self.ss_output, "")
        if name == "freshclam":
            if self.db_dir is not None:
                self.db_dir.mkdir(parents=True, exist_ok=True)
                (self.db_dir / "daily.cld").write_bytes(b"ClamAV-VDB")
            return CommandResult(tuple(cmd), 0, "Database up-to-date\n", "")
        if name == "clamscan":
            return CommandResult(tuple(cmd), 0, "", "")
        if name == "ufw":
            args = cmd[1:]
            if args == ["status", "numbered"]:
                st_line = "Status: active" if self.active else "Status: inactive"
                lines = [st_line, "", "     To                         Action      From", "     --                         ------      ----"]
                for idx, (tgt, act_dir, src) in enumerate(self.live_rules, start=1):
                    lines.append(f"[{idx:2d}] {tgt:26s} {act_dir:11s} {src}")
                return CommandResult(tuple(cmd), 0, "\n".join(lines) + "\n", "")
            if args == ["--force", "enable"]:
                self.active = True
                return CommandResult(tuple(cmd), 0, "Firewall active\n", "")
            if args == ["disable"]:
                self.active = False
                return CommandResult(tuple(cmd), 0, "Firewall stopped\n", "")
            is_delete = False
            if args and args[0] == "delete":
                is_delete = True
                args = args[1:]
            if args and args[0] == "allow":
                rest = args[1:]
                direction = "out" if (rest and rest[0] == "out") else "in"
                act_dir = "ALLOW OUT" if direction == "out" else "ALLOW IN"
                if "from" in rest and "port" in rest:
                    src = rest[rest.index("from") + 1]
                    port = rest[rest.index("port") + 1]
                    proto = f"/{rest[rest.index('proto') + 1]}" if "proto" in rest else ""
                    tgt = f"{port}{proto}"
                elif "to" in rest and "port" in rest:
                    src = rest[rest.index("to") + 1]
                    port = rest[rest.index("port") + 1]
                    proto = f"/{rest[rest.index('proto') + 1]}" if "proto" in rest else ""
                    tgt = f"{port}{proto}"
                else:
                    src = "Anywhere"
                    tgt = rest[-1]
                entry = (tgt, act_dir, src)
                if is_delete:
                    self.live_rules = [r for r in self.live_rules if r != entry]
                elif entry not in self.live_rules:
                    self.live_rules.append(entry)
                return CommandResult(tuple(cmd), 0, "Rule updated\n", "")
        return CommandResult(tuple(cmd), 0, "", "")


class FirewallAppsAndAutoRecsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory(prefix="mintsec-fw-apps-")
        self.root = Path(self.tmp.name)
        self.manifests = load_manifests()

    def tearDown(self) -> None:
        self.tmp.cleanup()

    def _make_controller(
        self,
        runner: _RichFirewallRunner | None = None,
        authorizer: CallerAuthorizer | None = None,
    ) -> tuple[SuiteController, _RichFirewallRunner]:
        r = runner or _RichFirewallRunner(db_dir=self.root / "clamdb")
        if r.db_dir is None:
            r.db_dir = self.root / "clamdb"
        ufw_conf = self.root / "ufw.conf"
        ufw_conf.write_text("ENABLED=no\n", encoding="utf-8")
        app_dir = self.root / "desktop_apps"
        app_dir.mkdir(exist_ok=True)
        (app_dir / "audiorelay.desktop").write_text("[Desktop Entry]\nName=AudioRelay\n", encoding="utf-8")

        prof_dir = self.root / "ufw_profiles"
        prof_dir.mkdir(exist_ok=True)
        (prof_dir / "custom-apps").write_text(
            "[MyCustomApp]\ntitle=Custom App\ndescription=Test app\nports=8123/tcp\n",
            encoding="utf-8",
        )
        # Symlink malicioso deve ser ignorado em applications.d
        secret = self.root / "secret_prof"
        secret.write_text("[EvilProf]\ntitle=Evil\nports=9999/tcp\n", encoding="utf-8")
        (prof_dir / "symlinked").symlink_to(secret)

        ctrl = SuiteController(
            config_store=ConfigStore(self.root / "settings.json"),
            pending_store=PendingStore(self.root / "pending.json"),
            history_store=HistoryStore(self.root / "history.db"),
            incident_manager=IncidentManager(self.root / "incidents"),
            runner=r,
            authorizer=authorizer or _RecordingAuthorizer(),
            data_dir=self.root / "data",
            clamav_db_dir=self.root / "clamdb",
        )
        ctrl.firewall.ufw_conf_path = ufw_conf
        ctrl._extra_fw_app_dirs = (app_dir,)
        ctrl._fw_profiles_dir = prof_dir
        return ctrl, r

    def test_firewall_apps_discovery_lan_detection_and_profiles(self) -> None:
        runner = _RichFirewallRunner()
        self.assertEqual(detect_local_lan_cidr(runner), "192.168.0.0/16")

        runner.ip_output = "2: eth0 inet 10.20.1.5/24 scope global eth0\n"
        self.assertEqual(detect_local_lan_cidr(runner), "10.0.0.0/8")

        listening = detect_listening_apps(runner)
        procs = {item["process"]: item for item in listening}
        self.assertNotIn("systemd-resolve", procs)  # loopback ignorado
        self.assertIn("kdeconnectd", procs)
        self.assertEqual(procs["kdeconnectd"]["preset_id"], "kdeconnect")
        self.assertEqual(procs["kdeconnectd"]["ports"], ["1716/tcp", "1716/udp"])
        self.assertIn("AudioRelay", procs)
        self.assertEqual(procs["AudioRelay"]["preset_id"], "audiorelay")
        self.assertIn("devserver", procs)
        self.assertEqual(procs["devserver"]["preset_id"], "")

        ctrl, _ = self._make_controller(runner)
        profiles = list_ufw_app_profiles(ctrl._fw_profiles_dir)  # type: ignore[arg-type]
        self.assertEqual([p["name"] for p in profiles], ["MyCustomApp"])

        presets = detect_app_presets(
            runner,
            extra_app_dirs=ctrl._extra_fw_app_dirs,
            listening_apps=listening,
        )
        by_id = {p["preset_id"]: p for p in presets}
        self.assertTrue(by_id["kdeconnect"]["running"])
        self.assertTrue(by_id["audiorelay"]["detected"])

    def test_firewall_service_presets_custom_ports_profiles_and_clean_revert(self) -> None:
        ctrl, runner = self._make_controller()
        fw = ctrl.firewall

        fw.enable(apply_essential_rules=True)
        res_kde = fw.allow_app_preset("kdeconnect")
        self.assertTrue(res_kde["ok"])
        self.assertEqual(res_kde["source_cidr"], "192.168.0.0/16")
        self.assertEqual(len(res_kde["rules"]), 2)
        self.assertIn(("1714:1764/tcp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)
        self.assertIn(("1714:1764/udp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)

        res_ar = fw.allow_app_preset("audiorelay", lan_only=True)
        self.assertTrue(res_ar["ok"])
        self.assertIn(("59100/tcp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)
        self.assertIn(("59200/udp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)

        # Live UFW status deve casar os rule_ids "suite-..." reais para revogação na UI
        st_live = ctrl.get_module_status("firewall")
        self.assertIn("kdeconnect", st_live.details["allowed_presets"])
        self.assertIn("audiorelay", st_live.details["allowed_presets"])
        kde_live = [r for r in st_live.details["rules"] if r.get("preset_id") == "kdeconnect"]
        self.assertEqual(len(kde_live), 2)
        self.assertTrue(kde_live[0]["managed_by_suite"])
        self.assertTrue(kde_live[0]["rule_id"].startswith("suite-"))

        # Portas customizadas (protocol=both expande TCP + UDP) e validações
        res_cust = fw.allow_custom_app_ports(
            app_name="DevServer",
            ports=["9090", "9100:9105/tcp"],
            direction="in",
            protocol="both",
            lan_only=True,
        )
        self.assertEqual(len(res_cust["rules"]), 3)
        self.assertIn(("9090/tcp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)
        self.assertIn(("9090/udp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)
        self.assertIn(("9100:9105/tcp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)

        with self.assertRaises(ValueError):
            fw.allow_custom_app_ports(app_name="BadPort", ports=["99999"], lan_only=True)
        with self.assertRaises(ValueError):
            fw.allow_custom_app_ports(app_name="BadRange", ports=["1000:500/tcp"], lan_only=True)
        with self.assertRaises(ValueError):
            fw.allow_custom_app_ports(app_name="BadCidr", ports=["8080"], lan_only=True, source_cidr="not-a-cidr")

        # Perfil UFW válido vs inexistente
        res_prof = fw.allow_ufw_profile("MyCustomApp", profiles_dir=ctrl._fw_profiles_dir)
        self.assertTrue(res_prof["ok"])
        with self.assertRaises(ValueError):
            fw.allow_ufw_profile("EvilProf", profiles_dir=ctrl._fw_profiles_dir)

        # Revogar preset AudioRelay remove apenas suas regras
        rev_ar = fw.revoke_app_preset("audiorelay")
        self.assertEqual(rev_ar["removed"], 2)
        self.assertNotIn(("59100/tcp", "ALLOW IN", "192.168.0.0/16"), runner.live_rules)

        # Reversão total ao desativar mantém apenas a regra externa pré-existente (22/tcp)
        fw.disable(revert_suite_changes=True)
        self.assertEqual(runner.live_rules, [("22/tcp", "ALLOW IN", "Anywhere")])

    def test_daemon_dbus_methods_and_client_routing(self) -> None:
        import dbus

        rec_auth = _RecordingAuthorizer(decision=True)
        ctrl, _ = self._make_controller(authorizer=rec_auth)
        with mock.patch("dbus.service.BusName"), mock.patch("dbus.service.Object.__init__", return_value=None):
            srv = ModuleDBusService(
                controller=ctrl,
                module_id="firewall",
                idle_exit_secs=0,
                bus=mock.MagicMock(),
            )

        with self.assertRaises(dbus.DBusException):
            srv._exported.AllowAppPreset('{"preset_id":"kdeconnect","_preauthorized":true}', sender=":1.60")
        with self.assertRaises(dbus.DBusException):
            srv._exported.AllowCustomPorts('{"app_name":"X","ports":"80"}', sender=":1.60")

        rec_auth.calls.clear()
        out_preset = json.loads(
            srv._exported.AllowAppPreset('{"preset_id":"audiorelay","lan_only":true}', sender=":1.60")
        )
        self.assertTrue(out_preset["ok"])
        self.assertEqual(rec_auth.calls, [("org.mintsecurity.firewall.configure", ":1.60", 1000)])

        out_custom = json.loads(
            srv._exported.AllowCustomPorts(
                '{"app_name":"LocalAPI","ports":["8085"],"protocol":"tcp","lan_only":true}',
                sender=":1.60",
            )
        )
        self.assertTrue(out_custom["ok"])

        out_rev = json.loads(srv._exported.RevokeAppPreset("audiorelay", sender=":1.60"))
        self.assertEqual(out_rev["removed"], 2)

        # SuiteController em modo SystemBus roteia via SystemModuleClient
        live_ctrl = SuiteController(
            config_store=ConfigStore(self.root / "sys_settings.json"),
            pending_store=PendingStore(self.root / "sys_pending.json"),
            history_store=HistoryStore(self.root / "sys_history.db"),
            incident_manager=IncidentManager(self.root / "sys_incidents"),
            runner=SubprocessRunner(),
            authorizer=CallerAuthorizer(test_decision=True),
            data_dir=self.root / "sys_data",
            clamav_db_dir=self.root / "clamdb",
        )
        with mock.patch.dict(os.environ, {"MINTSEC_USE_SYSTEM_BUS": "1"}):
            with mock.patch.object(
                live_ctrl.dbus_client,
                "allow_firewall_preset",
                return_value={"ok": True, "preset_id": "kdeconnect", "source_cidr": "192.168.0.0/16"},
            ) as mock_allow:
                r_allow = live_ctrl.allow_firewall_preset("kdeconnect")
                self.assertTrue(r_allow["ok"])
                mock_allow.assert_called_once()

    def test_auto_recommendations_and_apply_all(self) -> None:
        ctrl, runner = self._make_controller()
        # Tudo desabilitado inicialmente + scan pendente + banco ausente + auto_quick_scan off
        ctrl.config_store.update(auto_quick_scan_enabled=False)

        recs = ctrl.get_protection_recommendations()
        rec_ids = {r["rec_id"] for r in recs}
        self.assertIn("db_outdated", rec_ids)
        self.assertIn("enable_antimalware", rec_ids)
        self.assertIn("enable_firewall", rec_ids)
        self.assertIn("enable_browsing", rec_ids)
        self.assertIn("enable_auto_scan", rec_ids)
        self.assertIn("run_quick_scan", rec_ids)

        # Aplicar todas as recomendações automáticas ativa tudo + libera KDE Connect e AudioRelay no firewall!
        res = ctrl.apply_all_recommendations(recs=recs)
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["trigger_scan"], "quick")
        self.assertEqual(ctrl.antimalware.query_status().state, ModuleState.ATIVO)
        self.assertTrue(runner.active)
        self.assertEqual(ctrl.browsing.query_status().state, ModuleState.ATIVO)
        self.assertTrue(ctrl.config_store.load().auto_quick_scan_enabled)

        fw_st = ctrl.get_module_status("firewall")
        self.assertIn("kdeconnect", fw_st.details["allowed_presets"])
        self.assertIn("audiorelay", fw_st.details["allowed_presets"])

        # Falha parcial numa etapa não interrompe as outras recomendações automáticas
        bad_recs = [
            {"rec_id": "bad_step", "action": "allow_fw_preset:nonexistent", "auto_apply": True},
            {"rec_id": "enable_auto_scan", "action": "enable_auto_scan", "auto_apply": True},
        ]
        ctrl.config_store.update(auto_quick_scan_enabled=False)
        partial = ctrl.apply_all_recommendations(recs=bad_recs)
        self.assertFalse(partial["ok"])
        self.assertEqual(len(partial["failed"]), 1)
        self.assertIn("enable_auto_scan", partial["applied"])
        self.assertTrue(ctrl.config_store.load().auto_quick_scan_enabled)

    def test_gtk_xephyr_firewall_allow_apps_and_home_apply_all(self) -> None:
        repo_root = Path(__file__).resolve().parents[1]
        disp_num = next(
            (
                d
                for d in range(114, 146)
                if not Path(f"/tmp/.X{d}-lock").exists() and not Path(f"/tmp/.X11-unix/X{d}").exists()
            ),
            145,
        )
        disp = f":{disp_num}"
        xephyr = subprocess.Popen(
            ["Xephyr", disp, "-screen", "1280x820", "-ac", "-noreset"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            sock = Path(f"/tmp/.X11-unix/X{disp_num}")
            for _ in range(50):
                if sock.exists():
                    break
                time.sleep(0.1)
            self.assertTrue(sock.exists(), f"Xephyr failed on {disp}")

            script = """
import tempfile, time
from pathlib import Path
import gi
gi.require_version("Gtk", "3.0")
from gi.repository import GLib, Gtk
Gtk.init([])

from mintsec.auth import CallerAuthorizer
from mintsec.config import ConfigStore
from mintsec.contracts import ModuleState
from mintsec.history import HistoryStore
from mintsec.incident import IncidentManager
from mintsec.pending import PendingStore
from mintsec.runner import CommandResult
from mintsec.services.catalog import SuiteController
from mintsec_ui.window import SuiteWindow

class _UiFwRunner:
    def __init__(self):
        self.active = False
        self.live_rules = []
    def which(self, b):
        if b in ("ufw", "ip", "ss", "kdeconnectd", "clamscan", "freshclam", "dnsmasq"):
            return f"/usr/bin/{b}"
        return None
    def run(self, argv, *, timeout=None, env=None, on_line=None, cancel_event=None, pause_event=None):
        cmd = [str(a) for a in argv]
        name = Path(cmd[0]).name
        if name == "dpkg-query":
            if cmd[-1] in ("ufw", "clamav", "clamav-freshclam", "dnsmasq-base"):
                return CommandResult(tuple(cmd), 0, "install ok installed\\t1.0.0\\n", "")
            return CommandResult(tuple(cmd), 1, "", "not installed")
        if name == "ip":
            return CommandResult(tuple(cmd), 0, "2: enp4s0 inet 192.168.1.50/24 scope global enp4s0\\n", "")
        if name == "ss":
            return CommandResult(tuple(cmd), 0, 'udp UNCONN 0 0 *:1716 0.0.0.0:* users:(("kdeconnectd",pid=2151,fd=18))\\n', "")
        if name == "freshclam":
            return CommandResult(tuple(cmd), 0, "OK\\n", "")
        if name == "clamscan":
            return CommandResult(tuple(cmd), 0, "", "")
        if name == "ufw":
            args = cmd[1:]
            if args == ["status", "numbered"]:
                lines = ["Status: active" if self.active else "Status: inactive"]
                for i, (t, d, s) in enumerate(self.live_rules, 1):
                    lines.append(f"[{i:2d}] {t:26s} {d:11s} {s}")
                return CommandResult(tuple(cmd), 0, "\\n".join(lines) + "\\n", "")
            if args == ["--force", "enable"]:
                self.active = True
                return CommandResult(tuple(cmd), 0, "Active\\n", "")
            if args == ["disable"]:
                self.active = False
                return CommandResult(tuple(cmd), 0, "Inactive\\n", "")
            if args[0] == "allow":
                tgt = args[args.index("port") + 1] + (f"/{args[args.index('proto') + 1]}" if "proto" in args else "") if "port" in args else args[-1]
                src = args[args.index("from") + 1] if "from" in args else "Anywhere"
                self.live_rules.append((tgt, "ALLOW IN", src))
                return CommandResult(tuple(cmd), 0, "Added\\n", "")
            if args[0] == "delete":
                self.live_rules = []
                return CommandResult(tuple(cmd), 0, "Deleted\\n", "")
        return CommandResult(tuple(cmd), 0, "", "")

def flush(ms=60):
    end = time.monotonic() + (ms / 1000.0)
    ctx = GLib.MainContext.default()
    while time.monotonic() < end:
        while ctx.pending():
            Gtk.main_iteration_do(False)
        time.sleep(0.01)

def walk_widgets(w):
    out = [w]
    if isinstance(w, Gtk.Container):
        for ch in w.get_children():
            out.extend(walk_widgets(ch))
    return out

with tempfile.TemporaryDirectory() as tmp:
    base = Path(tmp)
    db_dir = base / "clamdb"
    db_dir.mkdir()
    (db_dir / "daily.cld").write_bytes(b"ok")
    runner = _UiFwRunner()
    ctrl = SuiteController(
        config_store=ConfigStore(base / "settings.json"),
        pending_store=PendingStore(base / "pending.json"),
        history_store=HistoryStore(base / "history.db"),
        incident_manager=IncidentManager(base / "incidents"),
        runner=runner,
        authorizer=CallerAuthorizer(test_decision=True),
        data_dir=base / "data",
        clamav_db_dir=db_dir,
    )
    ufw_conf = base / "ufw.conf"
    ufw_conf.write_text("ENABLED=no\\n", encoding="utf-8")
    ctrl.firewall.ufw_conf_path = ufw_conf
    app_dir = base / "apps"
    app_dir.mkdir()
    (app_dir / "audiorelay.desktop").write_text("[Desktop Entry]\\n", encoding="utf-8")
    ctrl._extra_fw_app_dirs = (app_dir,)
    ctrl.config_store.update(first_run_completed=True, language="en", auto_quick_scan_enabled=False)

    win = SuiteWindow(None, controller=ctrl, initial_width=1280, initial_height=760)
    flush(100)

    # 1. Home exibe botão "Apply all automatically" e aplica tudo com 1 chamada
    assert win.home_page.apply_all_recs_btn.get_visible()
    win.home_page.execute_apply_all_recommendations(win.home_page._last_recs_data)
    flush(150)
    win.scans_page.cancel_scan()
    flush(80)
    assert ctrl.get_module_status("firewall").state == ModuleState.ATIVO
    assert ctrl.browsing.query_status().state == ModuleState.ATIVO

    # 2. Página Firewall -> aba "Allow apps" filtra e permite app customizado (AudioRelay / Custom)
    win.open_module_detail("firewall")
    flush(80)
    md = win.module_detail_page
    assert md.fw_notebook is not None
    assert md.fw_notebook.get_current_page() == 1  # aba Allow apps selecionada com firewall ativo

    # Filtro reduz lista de presets
    assert md.fw_search_entry is not None
    before_rows = len(md.fw_presets_list_box.get_children())
    md.fw_search_entry.set_text("audiorelay")
    flush(50)
    after_rows = len(md.fw_presets_list_box.get_children())
    assert after_rows < before_rows, (before_rows, after_rows)

    # Enviar porta customizada pela interface
    md.fw_custom_name_entry.set_text("AudioRelayCustom")
    md.fw_custom_ports_entry.set_text("59150")
    allow_custom_btns = [
        w for w in walk_widgets(md.body_box)
        if isinstance(w, Gtk.Button) and w.get_label() == "Allow app / port"
    ]
    assert len(allow_custom_btns) == 1
    allow_custom_btns[0].clicked()
    flush(80)
    assert any(t == "59150/tcp" and s == "192.168.0.0/16" for t, _d, s in runner.live_rules), runner.live_rules

    win.destroy()
    flush(40)
print("XEPHYR_FW_APPS_AUTORECS_OK")
"""
            env = dict(os.environ)
            env["DISPLAY"] = disp
            env["MINTSEC_DISABLE_TRAY"] = "1"
            env["PYTHONPATH"] = str(repo_root / "src")
            res = subprocess.run(
                [sys.executable, "-c", script],
                env=env,
                capture_output=True,
                text=True,
                timeout=30.0,
                check=False,
            )
            self.assertEqual(res.returncode, 0, f"STDOUT:\n{res.stdout}\nSTDERR:\n{res.stderr}")
            self.assertIn("XEPHYR_FW_APPS_AUTORECS_OK", res.stdout)
        finally:
            xephyr.terminate()
            try:
                xephyr.wait(timeout=3)
            except subprocess.TimeoutExpired:
                xephyr.kill()


if __name__ == "__main__":
    unittest.main()
