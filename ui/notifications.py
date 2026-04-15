"""
notifications.py — Toast Notification Manager
================================================
Sends desktop toast notifications for security events.
Respects IT policy from config/settings.json for which
notification types are enabled.

DEPENDENCIES:
    Windows:    pip install winotify
    macOS/Linux: pip install plyer
"""

import os
import sys
import json
import logging
import threading

logger = logging.getLogger("aegis.notifications")

_APP_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_ICON_PATH = os.path.join(_APP_DIR, "assets", "aegis_icon.ico")
_SETTINGS_PATH = os.path.join(_APP_DIR, "config", "settings.json")

if sys.platform == "win32":
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(
            "Aegis.Wireless.WiFiSecurity.1.0"
        )
    except Exception:
        pass


def _load_notification_policy() -> dict:
    defaults = {
        "enabled": True,
        "cooldown_seconds": 30,
        "on_dangerous_network": True,
        "on_open_network": True,
        "on_blacklisted_network": True,
        "on_vpn_missing": True,
        "on_scan_complete": True,
        "on_startup": True,
        "on_connection_blocked": True,
        "on_connection_allowed": True,
    }
    try:
        with open(_SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        notif_cfg = data.get("notifications", {})
        defaults.update(notif_cfg)
    except Exception:
        pass
    return defaults


class NotificationManager:
    enabled: bool = True
    _COOLDOWNS: dict = {}
    COOLDOWN_SECONDS: int = 30
    _policy: dict = {}

    @classmethod
    def load_policy(cls):
        cls._policy = _load_notification_policy()
        cls.enabled = cls._policy.get("enabled", True)
        cls.COOLDOWN_SECONDS = cls._policy.get("cooldown_seconds", 30)

    @classmethod
    def _is_category_allowed(cls, category: str) -> bool:
        if not cls._policy:
            cls.load_policy()

        category_map = {
            "scan_danger": "on_scan_complete",
            "scan_moderate": "on_scan_complete",
            "scan_safe": "on_scan_complete",
            "scan_empty": "on_scan_complete",
            "danger_net": "on_dangerous_network",
            "open_nets": "on_open_network",
            "blacklist": "on_blacklisted_network",
            "vpn": "on_vpn_missing",
            "vpn_check": "on_vpn_missing",
            "startup": "on_startup",
            "audit_done": "on_scan_complete",
            "audit_empty": "on_scan_complete",
            "connection_blocked": "on_connection_blocked",
            "connection_allowed": "on_connection_allowed",
        }

        policy_key = category_map.get(category)
        if policy_key:
            return cls._policy.get(policy_key, True)
        return True

    # ─────────────────────────────────────────────────────────
    #  Core sender
    # ─────────────────────────────────────────────────────────

    @classmethod
    def notify(cls, title: str, message: str,
               category: str = "general", timeout: int = 8) -> None:
        if not cls.enabled:
            return
        if not cls._is_category_allowed(category):
            return

        import time
        now = time.time()
        last = cls._COOLDOWNS.get(category, 0)
        if now - last < cls.COOLDOWN_SECONDS:
            return
        cls._COOLDOWNS[category] = now

        threading.Thread(
            target=cls._send, args=(title, message, timeout),
            daemon=True,
        ).start()

    @classmethod
    def _send(cls, title: str, message: str, timeout: int) -> None:
        try:
            if sys.platform == "win32":
                cls._send_windows(title, message, timeout)
            else:
                cls._send_plyer(title, message, timeout)
        except ImportError as exc:
            logger.warning("Notification library missing: %s", exc)
            cls.enabled = False
        except Exception as exc:
            logger.error("Notification failed: %s", exc)

    @classmethod
    def _send_windows(cls, title: str, message: str, timeout: int) -> None:
        from winotify import Notification, audio
        toast = Notification(
            app_id="Aegis Wireless", title=title, msg=message,
            duration="long" if timeout > 8 else "short",
            icon=_ICON_PATH if os.path.isfile(_ICON_PATH) else "",
        )
        toast.set_audio(audio.Default, loop=False)
        toast.show()

    @classmethod
    def _send_plyer(cls, title: str, message: str, timeout: int) -> None:
        from plyer import notification as plyer_notify
        kwargs = {"title": title, "message": message,
                  "app_name": "Aegis Wireless", "timeout": timeout}
        if os.path.isfile(_ICON_PATH):
            kwargs["app_icon"] = _ICON_PATH
        plyer_notify.notify(**kwargs)

    # ─────────────────────────────────────────────────────────
    #  Connection enforcement toasts
    # ─────────────────────────────────────────────────────────

    @classmethod
    def connection_blocked(cls, ssid: str, reason: str) -> None:
        """Toast when a connection is blocked and disconnected."""
        cls.notify(
            "🚫 Connection Blocked",
            f'Disconnected from "{ssid}". {reason}',
            category="connection_blocked",
            timeout=12,
        )

    @classmethod
    def connection_allowed(cls, ssid: str,
                           warning: str = None) -> None:
        """Toast when a connection passes security checks."""
        if warning:
            cls.notify(
                f"⚠️ Connected to {ssid}",
                warning,
                category="connection_allowed",
                timeout=8,
            )
        else:
            cls.notify(
                f"✅ Connected to {ssid}",
                "Network passed security checks.",
                category="connection_allowed",
                timeout=5,
            )

    # ─────────────────────────────────────────────────────────
    #  Existing helpers
    # ─────────────────────────────────────────────────────────

    @classmethod
    def scan_complete(cls, total: int, dangerous: int, moderate: int) -> None:
        if dangerous > 0:
            cls.notify("⚠️ Aegis Scan Complete",
                       f"Found {total} networks — "
                       f"{dangerous} DANGEROUS, {moderate} moderate.",
                       category="scan_danger")
        elif moderate > 0:
            cls.notify("Aegis Scan Complete",
                       f"Found {total} networks — "
                       f"{moderate} with moderate risk.",
                       category="scan_moderate")
        else:
            cls.notify("✅ Aegis Scan Complete",
                       f"Found {total} networks — all appear safe.",
                       category="scan_safe")

    @classmethod
    def dangerous_network(cls, ssid: str, score: int) -> None:
        cls.notify("🚨 Dangerous Network Detected",
                   f'"{ssid}" scored {score}/100. Avoid this network.',
                   category="danger_net", timeout=12)

    @classmethod
    def blacklisted_network(cls, ssid: str) -> None:
        cls.notify("⛔ Blacklisted Network Nearby",
                   f'"{ssid}" is blocked by policy. Do not connect.',
                   category="blacklist", timeout=12)

    @classmethod
    def vpn_warning(cls) -> None:
        cls.notify("🔓 VPN Not Active",
                   "Your traffic is not tunneled. Connect to VPN.",
                   category="vpn")

    @classmethod
    def open_network_warning(cls, count: int) -> None:
        cls.notify("📡 Open Networks Detected",
                   f"{count} unencrypted network(s) nearby.",
                   category="open_nets")

    @classmethod
    def aegis_started(cls) -> None:
        cls.notify("Aegis Wireless Active",
                   "Monitoring your network security. "
                   "Right-click the tray icon for options.",
                   category="startup", timeout=5)

    @classmethod
    def policy_violation(cls, message: str) -> None:
        cls.notify("⚠️ Policy Violation", message,
                   category="policy", timeout=12)