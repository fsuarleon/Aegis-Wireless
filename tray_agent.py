"""
tray_agent.py — System Tray Agent with Background Monitoring
==============================================================
WHAT THIS DOES:
    Runs Aegis Wireless silently in the system tray (the little icons
    in the bottom-right corner of your taskbar). While running:

    - Scans WiFi networks at a configurable interval (default: 30 sec)
    - Automatically blocks connections to DANGEROUS networks
    - Shows Windows toast notifications for warnings and blocks
    - Provides a right-click tray menu to pause, scan now, or quit

REQUIREMENTS (install once):
    pip install pystray Pillow plyer

HOW TO RUN:
    python tray_agent.py           (normal — shows tray icon)
    python tray_agent.py --silent  (no console window at all)
    pythonw tray_agent.py          (Windows: truly hidden, no console)

HOW TO STOP:
    Right-click the shield icon in the system tray → Quit
"""

import sys
import os
import time
import threading
import json
from datetime import datetime
from pathlib import Path

# ── Add project root to path ───────────────────────────────────
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from scanner.wifi_scan import WiFiScanner
from core.engine import RiskEngine, RiskLevel
from core.blacklist import BlacklistManager
from network.enforcement import NetworkEnforcer
from api.telemetry import AegisLogger


# ── Check for required libraries ───────────────────────────────

def _check_dependencies():
    """Verify tray-specific libraries are installed."""
    missing = []
    try:
        import pystray
    except ImportError:
        missing.append("pystray")
    try:
        from PIL import Image, ImageDraw
    except ImportError:
        missing.append("Pillow")
    try:
        from plyer import notification
    except ImportError:
        missing.append("plyer")

    if missing:
        print(f"[!] Missing libraries: {', '.join(missing)}")
        print(f"    Install them with:")
        print(f"    pip install {' '.join(missing)}")
        sys.exit(1)

_check_dependencies()

import pystray
from PIL import Image, ImageDraw, ImageFont
from plyer import notification


# ═══════════════════════════════════════════════════════════════
#  STARTUP MANAGER — RUN ON BOOT
# ═══════════════════════════════════════════════════════════════

class StartupManager:
    """
    Registers/unregisters Aegis Wireless to run automatically
    when Windows starts up.

    HOW IT WORKS:
        Windows checks this Registry key on every boot:
          HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

        Any entries there are launched automatically. We add an entry
        that runs:  pythonw.exe <full_path_to>/tray_agent.py

        Using `pythonw.exe` (not `python.exe`) means NO console window
        appears — the app starts silently and only the tray icon is visible.

    NO ADMIN PRIVILEGES REQUIRED:
        HKEY_CURRENT_USER is per-user, not system-wide.
        No admin prompt will appear.
    """

    REGISTRY_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME = "AegisWireless"

    @staticmethod
    def is_windows() -> bool:
        return sys.platform == "win32"

    @classmethod
    def is_enabled(cls) -> bool:
        """Check if Aegis is currently set to run on startup."""
        if not cls.is_windows():
            return cls._check_linux_autostart()

        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                cls.REGISTRY_KEY,
                0, winreg.KEY_READ
            )
            try:
                winreg.QueryValueEx(key, cls.APP_NAME)
                winreg.CloseKey(key)
                return True
            except FileNotFoundError:
                winreg.CloseKey(key)
                return False
        except Exception:
            return False

    @classmethod
    def enable(cls) -> bool:
        """
        Add Aegis Wireless to Windows startup.
        Returns True on success.
        """
        if not cls.is_windows():
            return cls._enable_linux_autostart()

        try:
            import winreg

            # Find pythonw.exe (Python without console window)
            pythonw = cls._find_pythonw()
            tray_script = os.path.abspath(
                os.path.join(PROJECT_ROOT, "tray_agent.py")
            )

            # Command: pythonw.exe "C:\...\tray_agent.py"
            command = f'"{pythonw}" "{tray_script}"'

            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                cls.REGISTRY_KEY,
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, cls.APP_NAME, 0, winreg.REG_SZ, command)
            winreg.CloseKey(key)

            print(f"[+] Aegis Wireless will now start automatically on boot.")
            print(f"    Command: {command}")
            return True

        except Exception as e:
            print(f"[!] Failed to enable startup: {e}")
            return False

    @classmethod
    def disable(cls) -> bool:
        """
        Remove Aegis Wireless from Windows startup.
        Returns True on success.
        """
        if not cls.is_windows():
            return cls._disable_linux_autostart()

        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                cls.REGISTRY_KEY,
                0, winreg.KEY_SET_VALUE
            )
            try:
                winreg.DeleteValue(key, cls.APP_NAME)
                print(f"[-] Aegis Wireless removed from startup.")
            except FileNotFoundError:
                print(f"[*] Aegis Wireless was not in startup.")
            winreg.CloseKey(key)
            return True

        except Exception as e:
            print(f"[!] Failed to disable startup: {e}")
            return False

    @classmethod
    def toggle(cls) -> bool:
        """Toggle startup on/off. Returns new state (True = enabled)."""
        if cls.is_enabled():
            cls.disable()
            return False
        else:
            cls.enable()
            return True

    # ── Helpers ─────────────────────────────────────────────────

    @staticmethod
    def _find_pythonw() -> str:
        """
        Locate pythonw.exe — the windowless Python interpreter.
        Falls back to python.exe if pythonw isn't found.
        """
        python_dir = os.path.dirname(sys.executable)
        pythonw = os.path.join(python_dir, "pythonw.exe")

        if os.path.exists(pythonw):
            return pythonw

        # Check common locations
        for path in [
            os.path.join(sys.prefix, "pythonw.exe"),
            os.path.join(os.path.dirname(sys.executable), "pythonw.exe"),
        ]:
            if os.path.exists(path):
                return path

        # Fallback — will show a console window but still works
        print("[!] pythonw.exe not found — falling back to python.exe")
        print("    (a console window will appear briefly on startup)")
        return sys.executable

    # ── Linux autostart (XDG standard) ─────────────────────────

    @classmethod
    def _check_linux_autostart(cls) -> bool:
        """Check if .desktop file exists in ~/.config/autostart/."""
        desktop_file = os.path.expanduser(
            "~/.config/autostart/aegis-wireless.desktop"
        )
        return os.path.exists(desktop_file)

    @classmethod
    def _enable_linux_autostart(cls) -> bool:
        """Create a .desktop autostart entry on Linux."""
        try:
            autostart_dir = os.path.expanduser("~/.config/autostart")
            os.makedirs(autostart_dir, exist_ok=True)

            tray_script = os.path.abspath(
                os.path.join(PROJECT_ROOT, "tray_agent.py")
            )

            desktop_entry = f"""[Desktop Entry]
Type=Application
Name=Aegis Wireless
Comment=WiFi Security Monitor
Exec=python3 {tray_script}
Hidden=false
NoDisplay=false
X-GNOME-Autostart-enabled=true
"""
            desktop_path = os.path.join(autostart_dir, "aegis-wireless.desktop")
            with open(desktop_path, "w") as f:
                f.write(desktop_entry)

            print(f"[+] Autostart enabled: {desktop_path}")
            return True
        except Exception as e:
            print(f"[!] Failed to enable Linux autostart: {e}")
            return False

    @classmethod
    def _disable_linux_autostart(cls) -> bool:
        """Remove the .desktop autostart entry on Linux."""
        try:
            desktop_path = os.path.expanduser(
                "~/.config/autostart/aegis-wireless.desktop"
            )
            if os.path.exists(desktop_path):
                os.remove(desktop_path)
                print(f"[-] Autostart disabled.")
            return True
        except Exception as e:
            print(f"[!] Failed to disable Linux autostart: {e}")
            return False


# ═══════════════════════════════════════════════════════════════
#  TOAST NOTIFICATION HELPER
# ═══════════════════════════════════════════════════════════════

class ToastNotifier:
    """
    Shows Windows toast notifications (the pop-ups in the
    bottom-right corner). Uses `plyer` which works cross-platform.
    """

    APP_NAME = "Aegis Wireless"

    @staticmethod
    def notify_safe(ssid: str, score: int):
        """Green notification — network passed checks."""
        notification.notify(
            title=f"✅ {ssid} — Safe",
            message=f"Safety score: {score}/100. Connection permitted.",
            app_name=ToastNotifier.APP_NAME,
            timeout=5,
        )

    @staticmethod
    def notify_warning(ssid: str, score: int, reason: str):
        """Yellow notification — moderate risk detected."""
        notification.notify(
            title=f"⚠️ {ssid} — Moderate Risk",
            message=f"Score: {score}/100. {reason}. Consider using a VPN.",
            app_name=ToastNotifier.APP_NAME,
            timeout=8,
        )

    @staticmethod
    def notify_blocked(ssid: str, score: int, reason: str):
        """Red notification — network was blocked/disconnected."""
        notification.notify(
            title=f"🚨 BLOCKED: {ssid}",
            message=f"Score: {score}/100. {reason}. Disconnected automatically.",
            app_name=ToastNotifier.APP_NAME,
            timeout=10,
        )

    @staticmethod
    def notify_status(message: str):
        """Generic status notification."""
        notification.notify(
            title="Aegis Wireless",
            message=message,
            app_name=ToastNotifier.APP_NAME,
            timeout=4,
        )


# ═══════════════════════════════════════════════════════════════
#  BACKGROUND WATCHDOG — CONTINUOUS MONITORING
# ═══════════════════════════════════════════════════════════════

class WatchdogMonitor:
    """
    Runs in a background thread. Periodically scans for WiFi
    networks, evaluates each one, and auto-blocks dangerous
    networks by disconnecting.
    """

    def __init__(self, scan_interval: int = 30, auto_block: bool = True):
        """
        Args:
            scan_interval: Seconds between scans (default 30).
            auto_block:    Automatically disconnect from dangerous networks.
        """
        self.scan_interval = scan_interval
        self.auto_block = auto_block
        self.running = False
        self.paused = False
        self._thread = None

        # Initialize all modules
        self.wifi_scanner = WiFiScanner()
        self.risk_engine = RiskEngine()
        self.blacklist = BlacklistManager()
        self.enforcer = NetworkEnforcer()
        self.logger = AegisLogger()
        self.toast = ToastNotifier()

        # Track what we've already notified about (avoid spam)
        self._notified_networks = {}  # ssid -> last_notification_time
        self._notification_cooldown = 120  # seconds before re-notifying same network

        # Stats
        self.scans_completed = 0
        self.blocks_performed = 0
        self.last_scan_time = None

    # ── Control ─────────────────────────────────────────────────

    def start(self):
        """Start the background monitoring thread."""
        if self.running:
            return
        self.running = True
        self.paused = False
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.logger.log_message("Background watchdog started")

    def stop(self):
        """Stop the background monitoring thread."""
        self.running = False
        if self._thread:
            self._thread.join(timeout=5)
        self.logger.save_session()
        self.logger.log_message("Background watchdog stopped")

    def pause(self):
        """Pause scanning (tray icon stays active)."""
        self.paused = True
        self.logger.log_message("Watchdog paused by user")

    def resume(self):
        """Resume scanning after pause."""
        self.paused = False
        self.logger.log_message("Watchdog resumed by user")

    def scan_now(self):
        """Force an immediate scan (called from tray menu)."""
        threading.Thread(target=self._run_single_scan, daemon=True).start()

    # ── Main Loop ───────────────────────────────────────────────

    def _monitor_loop(self):
        """
        Main background loop. Runs until self.running is False.
        Scans WiFi → evaluates each network → enforces policy.
        """
        while self.running:
            if not self.paused:
                self._run_single_scan()

            # Sleep in small increments so we can stop quickly
            for _ in range(self.scan_interval):
                if not self.running:
                    break
                time.sleep(1)

    def _run_single_scan(self):
        """Execute one full scan-evaluate-enforce cycle."""
        try:
            networks = self.wifi_scanner.scan()
            self.scans_completed += 1
            self.last_scan_time = datetime.now()

            if not networks:
                return

            # Log scan
            self.logger.log_wifi_scan(self.wifi_scanner.get_results_as_dicts())

            # Evaluate each network
            for network in networks:
                assessment = self.risk_engine.analyze(network)

                # Check notification cooldown
                now = time.time()
                last_notified = self._notified_networks.get(network.ssid, 0)
                should_notify = (now - last_notified) > self._notification_cooldown

                # ── DANGEROUS → auto-block ──
                if assessment.risk_level == RiskLevel.DANGEROUS:
                    if self.auto_block:
                        success = self.enforcer._disconnect()
                        action = "disconnected" if success else "disconnect_failed"

                        if success:
                            self.blocks_performed += 1

                        if should_notify:
                            top_finding = assessment.findings[0].description if assessment.findings else "Multiple risks detected"
                            self.toast.notify_blocked(
                                network.ssid,
                                assessment.safety_score,
                                top_finding[:80]
                            )
                            self._notified_networks[network.ssid] = now

                        self.logger.log_enforcement(
                            action, network.ssid,
                            f"Auto-blocked. Score: {assessment.safety_score}/100"
                        )

                # ── MODERATE → warn via toast ──
                elif assessment.risk_level == RiskLevel.MODERATE:
                    if should_notify:
                        top_finding = assessment.findings[0].description if assessment.findings else "Possible risk"
                        self.toast.notify_warning(
                            network.ssid,
                            assessment.safety_score,
                            top_finding[:80]
                        )
                        self._notified_networks[network.ssid] = now

                    self.logger.log_enforcement(
                        "warned", network.ssid,
                        f"Toast warning. Score: {assessment.safety_score}/100"
                    )

                # Log assessment
                self.logger.log_assessment(assessment.to_dict())

        except Exception as e:
            self.logger.log_message(f"Watchdog scan error: {e}", level="error")


# ═══════════════════════════════════════════════════════════════
#  SYSTEM TRAY ICON
# ═══════════════════════════════════════════════════════════════

class AegisTrayApp:
    """
    System tray application. Shows a shield icon in the taskbar.
    Right-click for options: Scan Now, Pause, View Logs, Quit.
    """

    def __init__(self, scan_interval: int = 30, auto_block: bool = True):
        self.watchdog = WatchdogMonitor(
            scan_interval=scan_interval,
            auto_block=auto_block
        )
        self.icon = None

    def run(self):
        """Start the tray icon and background watchdog."""
        # Create the tray icon image (a simple shield shape)
        icon_image = self._create_shield_icon()

        # Build the right-click menu
        menu = pystray.Menu(
            pystray.MenuItem("Aegis Wireless v1.0", None, enabled=False),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Scan Now", self._on_scan_now),
            pystray.MenuItem(
                "Pause Monitoring",
                self._on_toggle_pause,
                checked=lambda item: self.watchdog.paused
            ),
            pystray.MenuItem(
                "Auto-Block Dangerous",
                self._on_toggle_autoblock,
                checked=lambda item: self.watchdog.auto_block
            ),
            pystray.MenuItem(
                "Run on Startup",
                self._on_toggle_startup,
                checked=lambda item: StartupManager.is_enabled()
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem(
                lambda item: f"Scans: {self.watchdog.scans_completed} | "
                             f"Blocks: {self.watchdog.blocks_performed}",
                None, enabled=False
            ),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Open Logs Folder", self._on_open_logs),
            pystray.MenuItem("Quit", self._on_quit),
        )

        self.icon = pystray.Icon(
            "aegis_wireless",
            icon_image,
            "Aegis Wireless — Monitoring",
            menu
        )

        # Start watchdog in background before showing tray
        self.watchdog.start()
        ToastNotifier.notify_status("Background monitoring active. Scanning every 30 seconds.")

        # This blocks — it runs the tray event loop
        self.icon.run()

    # ── Menu Callbacks ──────────────────────────────────────────

    def _on_scan_now(self, icon, item):
        """User clicked 'Scan Now' in the tray menu."""
        self.watchdog.scan_now()
        ToastNotifier.notify_status("Running scan...")

    def _on_toggle_pause(self, icon, item):
        """Toggle pause/resume."""
        if self.watchdog.paused:
            self.watchdog.resume()
            ToastNotifier.notify_status("Monitoring resumed.")
        else:
            self.watchdog.pause()
            ToastNotifier.notify_status("Monitoring paused.")

    def _on_toggle_autoblock(self, icon, item):
        """Toggle auto-blocking on/off."""
        self.watchdog.auto_block = not self.watchdog.auto_block
        state = "enabled" if self.watchdog.auto_block else "disabled"
        ToastNotifier.notify_status(f"Auto-blocking {state}.")

    def _on_toggle_startup(self, icon, item):
        """Toggle run-on-startup on/off."""
        new_state = StartupManager.toggle()
        if new_state:
            ToastNotifier.notify_status(
                "Aegis will now start automatically when you log in."
            )
        else:
            ToastNotifier.notify_status(
                "Aegis will no longer start on login."
            )

    def _on_open_logs(self, icon, item):
        """Open the logs folder in File Explorer."""
        log_dir = os.path.join(PROJECT_ROOT, "logs")
        os.makedirs(log_dir, exist_ok=True)
        if sys.platform == "win32":
            os.startfile(log_dir)
        elif sys.platform == "darwin":
            os.system(f'open "{log_dir}"')
        else:
            os.system(f'xdg-open "{log_dir}"')

    def _on_quit(self, icon, item):
        """Shut down watchdog and exit."""
        self.watchdog.stop()
        icon.stop()

    # ── Icon Generation ─────────────────────────────────────────

    @staticmethod
    def _create_shield_icon(size: int = 64) -> Image.Image:
        """
        Draw a simple shield icon programmatically.
        No external image file needed.
        """
        img = Image.new("RGBA", (size, size), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)

        # Shield shape points (normalized to 0-1, scaled to size)
        cx, cy = size // 2, size // 2
        s = size * 0.45  # scale

        # Shield outline (pointed at bottom)
        shield_points = [
            (cx - s, cy - s * 0.8),       # top-left
            (cx, cy - s),                   # top-center (slight peak)
            (cx + s, cy - s * 0.8),        # top-right
            (cx + s, cy + s * 0.1),        # right side
            (cx, cy + s),                   # bottom point
            (cx - s, cy + s * 0.1),        # left side
        ]

        # Fill with a teal/green color
        draw.polygon(shield_points, fill=(29, 158, 117, 255))

        # White checkmark inside
        check_points = [
            (cx - s * 0.35, cy - s * 0.05),
            (cx - s * 0.05, cy + s * 0.35),
            (cx + s * 0.4, cy - s * 0.35),
        ]
        draw.line(check_points, fill=(255, 255, 255, 255), width=max(3, size // 16))

        return img


# ═══════════════════════════════════════════════════════════════
#  ENTRY POINT
# ═══════════════════════════════════════════════════════════════

def main():
    """Parse arguments and launch the tray agent."""
    import argparse
    parser = argparse.ArgumentParser(description="Aegis Wireless — System Tray Agent")
    parser.add_argument(
        "--interval", type=int, default=30,
        help="Seconds between background scans (default: 30)"
    )
    parser.add_argument(
        "--no-autoblock", action="store_true",
        help="Disable automatic disconnection from dangerous networks"
    )
    parser.add_argument(
        "--install", action="store_true",
        help="Register Aegis to run automatically on Windows startup"
    )
    parser.add_argument(
        "--uninstall", action="store_true",
        help="Remove Aegis from Windows startup"
    )
    args = parser.parse_args()

    # ── Handle install/uninstall and exit ──
    if args.install:
        StartupManager.enable()
        print("\n  To start the agent right now, run:")
        print("    pythonw tray_agent.py")
        return

    if args.uninstall:
        StartupManager.disable()
        return

    # ── Normal launch ──
    startup_status = "ON" if StartupManager.is_enabled() else "OFF"

    print("[*] Aegis Wireless — Starting system tray agent...")
    print(f"    Scan interval:    {args.interval}s")
    print(f"    Auto-block:       {'OFF' if args.no_autoblock else 'ON'}")
    print(f"    Run on startup:   {startup_status}")
    print(f"    Right-click the shield icon in your taskbar to control.")
    print(f"    To run without this console: use 'pythonw tray_agent.py'")
    print(f"    To enable startup: python tray_agent.py --install")

    app = AegisTrayApp(
        scan_interval=args.interval,
        auto_block=not args.no_autoblock
    )
    app.run()


if __name__ == "__main__":
    main()