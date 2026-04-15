"""
tray.py — System Tray Application
====================================
Minimal UX for end users. IT admins enable advanced features
via config/settings.json → admin_mode: true.

USER MENU (admin_mode: false):
    Aegis Wireless
    ─────────────
    Status: Protected
    Last scan: 2 min ago
    ─────────────
    Scan Now
    ─────────────
    Exit

ADMIN MENU (admin_mode: true):
    All of the above PLUS:
    Full Audit, VPN Status, View Logs,
    Run on Startup, Notifications toggle,
    Open Terminal UI
"""

import os
import sys
import json
import time
import threading
import subprocess
import platform
import logging
from pathlib import Path
from network.monitor import ConnectionMonitor

logger = logging.getLogger("aegis.tray")

_APP_DIR = Path(__file__).resolve().parent.parent
if str(_APP_DIR) not in sys.path:
    sys.path.insert(0, str(_APP_DIR))

from scanner.wifi_scan import WiFiScanner
from scanner.port_probe import PortScanner
from core.engine import RiskEngine
from core.blacklist import BlacklistManager
from network.enforcement import NetworkEnforcer
from network.vpn_tunnel import VPNStatus
from api.telemetry import AegisLogger

from ui.notifications import NotificationManager
from ui.startup import StartupManager


# ─────────────────────────────────────────────────────────────
#  Config loader
# ─────────────────────────────────────────────────────────────

def _load_config() -> dict:
    """Load full config from settings.json with safe defaults."""
    defaults = {
        "admin_mode": False,
        "policy": {
            "require_vpn": True,
            "minimum_encryption": "WPA2",
            "allow_open_networks": False,
            "max_acceptable_risk_score": 40,
            "auto_enforce_disconnect": False,
            "blocked_ssids": [],
            "trusted_ssids": [],
            "auto_scan_on_start": True,
            "scan_interval_minutes": 15,
            "org_name": "",
        },
        "notifications": {"enabled": True},
        "tray": {
            "run_on_startup": True,
            "show_exit_button": True,
            "user_can_disable_notifications": False,
            "user_can_toggle_startup": False,
        },
    }
    try:
        path = _APP_DIR / "config" / "settings.json"
        data = json.loads(path.read_text("utf-8"))
        for key in defaults:
            if isinstance(defaults[key], dict) and key in data:
                defaults[key].update(data[key])
            elif key in data:
                defaults[key] = data[key]
        return defaults
    except Exception:
        return defaults


# ─────────────────────────────────────────────────────────────
#  Icon generation
# ─────────────────────────────────────────────────────────────

def _create_icon_image(size: int = 64):
    """Load bundled icon or generate a teal shield fallback."""
    from PIL import Image, ImageDraw, ImageFont

    for p in (_APP_DIR / "assets" / "aegis_icon.ico",
              _APP_DIR / "assets" / "aegis_icon.png"):
        if p.exists():
            try:
                return Image.open(str(p)).resize((size, size))
            except Exception:
                pass

    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)
    s = size
    shield = [
        (s*0.50, s*0.05), (s*0.85, s*0.20), (s*0.80, s*0.65),
        (s*0.50, s*0.95), (s*0.20, s*0.65), (s*0.15, s*0.20),
    ]
    draw.polygon(shield, fill=(0, 172, 193, 240),
                 outline=(0, 131, 148, 255))
    try:
        font = ImageFont.truetype("arial.ttf", size // 3)
    except (OSError, IOError):
        font = ImageFont.load_default()
    bbox = draw.textbbox((0, 0), "A", font=font)
    tw, th = bbox[2] - bbox[0], bbox[3] - bbox[1]
    draw.text(((s-tw)/2, (s-th)/2 - s*0.02), "A",
              fill="white", font=font)
    return img


# ─────────────────────────────────────────────────────────────
#  Tray Application
# ─────────────────────────────────────────────────────────────

class AegisTray:
    """
    System tray wrapper. Minimal for users, full-featured for admins.
    All behavior driven by config/settings.json.

    On startup:
    1. Creates the enforcer
    2. Passes it to the blacklist manager so add/remove
       trigger OS-level blocks automatically
    3. Repairs any blacklist data inconsistency (entries vs
       blacklisted_networks desync)
    4. Syncs all blacklisted networks to OS-level blocks
    5. Loads IT-defined blocked_ssids into the blacklist
    6. Starts the connection monitor
    """

    def __init__(self):
        self.config = _load_config()
        self.policy = self.config["policy"]
        self.tray_cfg = self.config["tray"]
        self.admin_mode = self.config.get("admin_mode", False)

        # ── Core modules ──
        self.wifi_scanner = WiFiScanner()
        self.port_scanner = PortScanner()
        self.risk_engine = RiskEngine()
        self.enforcer = NetworkEnforcer()
        self.logger = AegisLogger()

        # ── Blacklist with enforcer attached ──
        # The enforcer is passed to the blacklist so that
        # every add() triggers an OS-level block, and every
        # remove() lifts it.
        # NOTE: BlacklistManager._load() also repairs any
        # desync between entries and blacklisted_networks
        # (the root cause of the WhiteSky-109Tower bug).
        self.blacklist = BlacklistManager(enforcer=self.enforcer)

        # ── State ──
        self._scanning = False
        self._icon = None
        self._last_scan_time = None
        self._last_status = "No scan yet"

        # ── Load IT-defined blocked SSIDs into blacklist ──
        for ssid in self.policy.get("blocked_ssids", []):
            self.blacklist.add(ssid, reason="Blocked by IT policy")

        # ── Sync all blacklisted networks to OS-level blocks ──
        # This ensures that even if the app was closed and
        # networks were added to blacklist.json manually,
        # they will be enforced at the OS level.
        self.blacklist.sync_os_blocks()

        # ── Load notification policy ──
        NotificationManager.load_policy()

        self.monitor = ConnectionMonitor(
            wifi_scanner=self.wifi_scanner,
            risk_engine=self.risk_engine,
            blacklist=self.blacklist,
            enforcer=self.enforcer,
            aegis_logger=self.logger,
            policy=self.policy,
            port_scanner=self.port_scanner,
        )

    # ─────────────────────────────────────────────────────────
    #  Build the context menu
    # ─────────────────────────────────────────────────────────

    def _build_menu(self):
        """
        Build the tray menu.

        USER mode  → Status, Last scan, Scan Now, Exit
        ADMIN mode → Everything above + audit, VPN, logs,
                     toggles, terminal UI
        """
        from pystray import MenuItem as Item, Menu

        items = []

        # ── Header ──
        org = self.policy.get("org_name", "")
        header = f"Aegis Wireless — {org}" if org else "Aegis Wireless"
        items.append(Item(header, action=None, enabled=False))
        items.append(Menu.SEPARATOR)

        # ── Status lines (always visible) ──
        items.append(Item(
            lambda text: f"Status: {self._last_status}",
            action=None, enabled=False,
        ))

        def _last_scan_label(item):
            if not self._last_scan_time:
                return "Last scan: never"
            ago = int(time.time() - self._last_scan_time)
            if ago < 60:
                return f"Last scan: {ago}s ago"
            return f"Last scan: {ago // 60}m ago"

        items.append(Item(_last_scan_label, action=None, enabled=False))
        items.append(Menu.SEPARATOR)

        # ── Scan Now (always visible) ──
        items.append(Item(
            "Scan Now",
            self._on_quick_scan,
            enabled=lambda item: not self._scanning,
        ))

        # ══════════════════════════════════════════════════════
        #  ADMIN-ONLY ITEMS — everything below this block is
        #  hidden when admin_mode is false
        # ══════════════════════════════════════════════════════

        if self.admin_mode:
            items.append(Item(
                "Full Audit",
                self._on_full_audit,
                enabled=lambda item: not self._scanning,
            ))
            items.append(Menu.SEPARATOR)

            items.append(Item("VPN Status", self._on_vpn_status))
            items.append(Item("View Logs", self._on_view_logs))
            items.append(Menu.SEPARATOR)

            items.append(Item(
                "Run on Startup",
                self._on_toggle_startup,
                checked=lambda item: StartupManager.is_enabled(),
            ))
            items.append(Item(
                "Notifications",
                self._on_toggle_notifications,
                checked=lambda item: NotificationManager.enabled,
            ))
            items.append(Menu.SEPARATOR)

            items.append(Item("Open Terminal UI", self._on_open_terminal))

        # ── Exit (always visible) ──
        items.append(Menu.SEPARATOR)
        items.append(Item("Exit", self._on_exit))

        return Menu(*items)

    # ─────────────────────────────────────────────────────────
    #  Run
    # ─────────────────────────────────────────────────────────

    def run(self):
        """Start the system tray icon. Blocks the calling thread."""
        import pystray

        icon_image = _create_icon_image(64)
        self._icon = pystray.Icon(
            name="aegis_wireless",
            icon=icon_image,
            title="Aegis Wireless — WiFi Security",
            menu=self._build_menu(),
        )

        NotificationManager.aegis_started()
        self.logger.log_message("Aegis tray mode started")

        # ── Auto-scan on start (policy) ──
        if self.policy.get("auto_scan_on_start", True):
            threading.Thread(
                target=self._do_quick_scan, daemon=True
            ).start()

        # ── Periodic scanning (policy) ──
        interval = self.policy.get("scan_interval_minutes", 0)
        if interval > 0:
            self._start_periodic_scan(interval)

        logger.info("System tray icon running.")
        self.monitor.start()
        self._icon.run()

    def _start_periodic_scan(self, interval_minutes: int):
        """Schedule a background scan every N minutes."""
        def _loop():
            while True:
                time.sleep(interval_minutes * 60)
                if not self._scanning:
                    logger.info("Periodic scan triggered.")
                    self._do_quick_scan()

        timer = threading.Thread(target=_loop, daemon=True)
        timer.start()

    # ─────────────────────────────────────────────────────────
    #  Scan handlers
    # ─────────────────────────────────────────────────────────

    def _on_quick_scan(self, icon, item):
        threading.Thread(
            target=self._do_quick_scan, daemon=True
        ).start()

    def _do_quick_scan(self):
        """WiFi scan → risk analysis → policy checks → notifications."""
        self._scanning = True
        self._last_status = "Scanning..."
        try:
            networks = self.wifi_scanner.scan()
            if not networks:
                self._last_status = "No networks found"
                NotificationManager.notify(
                    "Aegis Scan",
                    "No WiFi networks found. Is WiFi enabled?",
                    category="scan_empty",
                )
                return

            assessments = self.risk_engine.analyze_multiple(networks)

            dangerous = sum(1 for a in assessments if a.risk_level == "DANGEROUS")
            moderate = sum(1 for a in assessments if a.risk_level == "MODERATE")
            total = len(assessments)

            # ── Update status ──
            if dangerous > 0:
                self._last_status = f"⚠ {dangerous} threat(s) detected"
            elif moderate > 0:
                self._last_status = f"~ {moderate} moderate risk"
            else:
                self._last_status = f"✓ Protected ({total} networks)"

            self._last_scan_time = time.time()

            # ── Notify dangerous networks ──
            for a in assessments:
                if a.risk_level == "DANGEROUS":
                    NotificationManager.dangerous_network(
                        a.ssid, a.safety_score
                    )

            # ── Policy: blocked SSIDs ──
            for net in networks:
                if self.blacklist.is_blacklisted(net.ssid):
                    NotificationManager.blacklisted_network(net.ssid)

            # ── Policy: open network check ──
            if not self.policy.get("allow_open_networks", False):
                open_count = sum(
                    1 for n in networks if n.encryption == "Open"
                )
                if open_count:
                    NotificationManager.open_network_warning(open_count)

            # ── Policy: VPN required ──
            if self.policy.get("require_vpn", False):
                if not VPNStatus.is_vpn_active():
                    NotificationManager.vpn_warning()

            # ── Summary toast ──
            NotificationManager.scan_complete(total, dangerous, moderate)

            # ── Logging ──
            self.logger.log_wifi_scan(
                self.wifi_scanner.get_results_as_dicts()
            )
            for a in assessments:
                self.logger.log_assessment(a.to_dict())
            self.logger.log_message("Quick scan completed (tray)")

        except Exception as exc:
            self._last_status = "Scan error"
            logger.error("Quick scan failed: %s", exc)
            NotificationManager.notify(
                "Scan Error", f"Quick scan failed: {exc}",
                category="error",
            )
        finally:
            self._scanning = False

    def _on_full_audit(self, icon, item):
        threading.Thread(
            target=self._do_full_audit, daemon=True
        ).start()

    def _do_full_audit(self):
        """Complete audit: WiFi + ports + VPN + risk."""
        self._scanning = True
        self._last_status = "Full audit..."
        try:
            networks = self.wifi_scanner.scan()
            if not networks:
                self._last_status = "No networks found"
                NotificationManager.notify(
                    "Audit", "No networks found. Audit aborted.",
                    category="audit_empty",
                )
                return

            port_report = self.port_scanner.quick_scan("127.0.0.1")
            vpn_active = VPNStatus.is_vpn_active()
            if not vpn_active:
                NotificationManager.vpn_warning()

            assessments = self.risk_engine.analyze_multiple(networks)
            dangerous = sum(
                1 for a in assessments if a.risk_level == "DANGEROUS"
            )
            moderate = sum(
                1 for a in assessments if a.risk_level == "MODERATE"
            )
            safe = sum(
                1 for a in assessments if a.risk_level == "SAFE"
            )

            if dangerous > 0:
                self._last_status = f"⚠ {dangerous} threat(s) detected"
            else:
                self._last_status = (
                    f"✓ Audit clean ({len(networks)} networks)"
                )
            self._last_scan_time = time.time()

            for a in assessments:
                if a.risk_level == "DANGEROUS":
                    NotificationManager.dangerous_network(
                        a.ssid, a.safety_score
                    )

            vpn_str = "VPN active" if vpn_active else "NO VPN"
            open_ports = len(port_report.open_ports)
            NotificationManager.notify(
                "Full Audit Complete",
                f"{len(networks)} networks | "
                f"{open_ports} open ports | {vpn_str}\n"
                f"Safe: {safe}  Moderate: {moderate}  "
                f"Dangerous: {dangerous}",
                category="audit_done", timeout=12,
            )

            self.logger.log_wifi_scan(
                self.wifi_scanner.get_results_as_dicts()
            )
            self.logger.log_port_scan(port_report.to_dict())
            for a in assessments:
                self.logger.log_assessment(a.to_dict())
            self.logger.log_message("Full audit completed (tray)")

        except Exception as exc:
            self._last_status = "Audit error"
            logger.error("Full audit failed: %s", exc)
            NotificationManager.notify(
                "Audit Error", f"Audit failed: {exc}",
                category="error",
            )
        finally:
            self._scanning = False

    # ─────────────────────────────────────────────────────────
    #  Other menu handlers (admin only)
    # ─────────────────────────────────────────────────────────

    def _on_vpn_status(self, icon, item):
        if VPNStatus.is_vpn_active():
            NotificationManager.notify(
                "✅ VPN Active",
                "Your traffic appears to be tunneled.",
                category="vpn_check",
            )
        else:
            NotificationManager.vpn_warning()

    def _on_view_logs(self, icon, item):
        logs_dir = str(_APP_DIR / "logs")
        try:
            system = platform.system()
            if system == "Windows":
                os.startfile(logs_dir)
            elif system == "Darwin":
                subprocess.Popen(["open", logs_dir])
            else:
                subprocess.Popen(["xdg-open", logs_dir])
        except Exception as exc:
            logger.error("Could not open logs: %s", exc)
            NotificationManager.notify(
                "Logs", f"Logs stored in:\n{logs_dir}",
                category="logs",
            )

    def _on_toggle_startup(self, icon, item):
        if StartupManager.is_enabled():
            ok = StartupManager.disable()
            msg = "Startup disabled." if ok else "Failed to disable."
        else:
            ok = StartupManager.enable()
            msg = "Aegis will start on login." if ok else "Failed."
        NotificationManager.notify(
            "Startup", msg, category="startup_toggle"
        )

    def _on_toggle_notifications(self, icon, item):
        NotificationManager.enabled = not NotificationManager.enabled
        self._save_notification_pref(NotificationManager.enabled)
        if NotificationManager.enabled:
            NotificationManager.notify(
                "Notifications Enabled",
                "You will receive security alerts.",
                category="notif_toggle",
            )

    def _save_notification_pref(self, enabled: bool):
        try:
            path = _APP_DIR / "config" / "settings.json"
            data = {}
            if path.exists():
                data = json.loads(path.read_text("utf-8"))
            data.setdefault("notifications", {})["enabled"] = enabled
            path.write_text(
                json.dumps(data, indent=4) + "\n", encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Could not save pref: %s", exc)

    def _on_open_terminal(self, icon, item):
        python = sys.executable
        if python.lower().endswith("pythonw.exe"):
            python = python.replace("pythonw.exe", "python.exe")
        main_py = str(_APP_DIR / "main.py")
        try:
            system = platform.system()
            if system == "Windows":
                subprocess.Popen(
                    f'start "" "{python}" "{main_py}" --cli',
                    shell=True, cwd=str(_APP_DIR),
                )
            elif system == "Darwin":
                subprocess.Popen([
                    "osascript", "-e",
                    f'tell app "Terminal" to do script '
                    f'"{python} {main_py} --cli"'
                ])
            else:
                for term in ("x-terminal-emulator",
                             "gnome-terminal",
                             "konsole", "xterm"):
                    try:
                        subprocess.Popen(
                            [term, "-e",
                             f"{python} {main_py} --cli"],
                            cwd=str(_APP_DIR),
                        )
                        break
                    except FileNotFoundError:
                        continue
        except Exception as exc:
            logger.error("Could not open terminal: %s", exc)

    def _on_exit(self, icon, item):
        self.logger.save_session()
        self.logger.log_message("Aegis tray mode exited")
        icon.stop()
        self.monitor.stop()