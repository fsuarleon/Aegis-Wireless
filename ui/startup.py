"""
startup.py — Run on Startup Configuration
============================================
WHAT THIS DOES:
    Provides a one-time setup to register (or unregister) Aegis
    Wireless so it starts automatically when the user logs in.

SUPPORTED PLATFORMS:
    - Windows : Adds a registry key under HKCU\\...\\Run
    - macOS   : Creates a LaunchAgent plist
    - Linux   : Creates a .desktop autostart entry

HOW IT WORKS:
    Call `StartupManager.enable()` once and the app will launch in
    system-tray mode on every login.  Call `.disable()` to undo.
"""

import os
import sys
import platform
import logging
import json
from pathlib import Path

logger = logging.getLogger("aegis.startup")

# ── Paths ──
_APP_DIR = Path(__file__).resolve().parent.parent
_CONFIG_DIR = _APP_DIR / "config"
_SETTINGS_FILE = _CONFIG_DIR / "settings.json"
_APP_NAME = "AegisWireless"


class StartupManager:
    """
    One-time configuration to launch Aegis on user login.
    Detects the OS and uses the appropriate native mechanism.
    """

    # ─────────────────────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────────────────────

    @classmethod
    def enable(cls) -> bool:
        """Register Aegis to start on login. Returns True on success."""
        system = platform.system()
        try:
            if system == "Windows":
                ok = cls._enable_windows()
            elif system == "Darwin":
                ok = cls._enable_macos()
            elif system == "Linux":
                ok = cls._enable_linux()
            else:
                logger.warning("Unsupported OS for startup: %s", system)
                return False

            if ok:
                cls._save_startup_flag(True)
                logger.info("Startup registration enabled (%s).", system)
            return ok

        except Exception as exc:
            logger.error("Failed to enable startup: %s", exc)
            return False

    @classmethod
    def disable(cls) -> bool:
        """Remove Aegis from login startup. Returns True on success."""
        system = platform.system()
        try:
            if system == "Windows":
                ok = cls._disable_windows()
            elif system == "Darwin":
                ok = cls._disable_macos()
            elif system == "Linux":
                ok = cls._disable_linux()
            else:
                return False

            if ok:
                cls._save_startup_flag(False)
                logger.info("Startup registration disabled (%s).", system)
            return ok

        except Exception as exc:
            logger.error("Failed to disable startup: %s", exc)
            return False

    @classmethod
    def is_enabled(cls) -> bool:
        """Check whether startup is currently registered."""
        system = platform.system()
        try:
            if system == "Windows":
                return cls._check_windows()
            elif system == "Darwin":
                return cls._check_macos()
            elif system == "Linux":
                return cls._check_linux()
        except Exception:
            pass
        return False

    # ─────────────────────────────────────────────────────────
    #  Build the command that will be invoked on login
    # ─────────────────────────────────────────────────────────

    @classmethod
    def _launch_command(cls) -> str:
        """
        Build the shell command to start Aegis in tray mode.

        On Windows: uses pythonw.exe + aegis_tray.pyw (no console)
        On macOS/Linux: uses python + main.py --tray
        """
        if platform.system() == "Windows":
            # Use pythonw.exe for windowless launch
            python = sys.executable
            pythonw = python.replace("python.exe", "pythonw.exe")
            if not os.path.isfile(pythonw):
                pythonw = python   # Fallback
            launcher = str(_APP_DIR / "aegis_tray.pyw")
            return f'"{pythonw}" "{launcher}"'
        else:
            python = sys.executable
            main_py = str(_APP_DIR / "main.py")
            return f'"{python}" "{main_py}" --tray'

    # ─────────────────────────────────────────────────────────
    #  Windows — Registry
    # ─────────────────────────────────────────────────────────

    @classmethod
    def _enable_windows(cls) -> bool:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path, 0,
                winreg.KEY_SET_VALUE,
            )
            winreg.SetValueEx(
                key, _APP_NAME, 0, winreg.REG_SZ,
                cls._launch_command(),
            )
            winreg.CloseKey(key)
            return True
        except OSError as exc:
            logger.error("Windows registry write failed: %s", exc)
            return False

    @classmethod
    def _disable_windows(cls) -> bool:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path, 0,
                winreg.KEY_SET_VALUE,
            )
            winreg.DeleteValue(key, _APP_NAME)
            winreg.CloseKey(key)
            return True
        except FileNotFoundError:
            return True
        except OSError as exc:
            logger.error("Windows registry delete failed: %s", exc)
            return False

    @classmethod
    def _check_windows(cls) -> bool:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER, key_path, 0,
                winreg.KEY_READ,
            )
            winreg.QueryValueEx(key, _APP_NAME)
            winreg.CloseKey(key)
            return True
        except (FileNotFoundError, OSError):
            return False

    # ─────────────────────────────────────────────────────────
    #  macOS — LaunchAgent plist
    # ─────────────────────────────────────────────────────────

    @classmethod
    def _plist_path(cls) -> Path:
        return (
            Path.home()
            / "Library" / "LaunchAgents"
            / "com.aegis.wireless.plist"
        )

    @classmethod
    def _enable_macos(cls) -> bool:
        plist = cls._plist_path()
        plist.parent.mkdir(parents=True, exist_ok=True)

        python = sys.executable
        main_py = str(_APP_DIR / "main.py")

        content = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.aegis.wireless</string>
    <key>ProgramArguments</key>
    <array>
        <string>{python}</string>
        <string>{main_py}</string>
        <string>--tray</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <false/>
</dict>
</plist>
"""
        plist.write_text(content, encoding="utf-8")
        return True

    @classmethod
    def _disable_macos(cls) -> bool:
        plist = cls._plist_path()
        if plist.exists():
            plist.unlink()
        return True

    @classmethod
    def _check_macos(cls) -> bool:
        return cls._plist_path().exists()

    # ─────────────────────────────────────────────────────────
    #  Linux — XDG Autostart
    # ─────────────────────────────────────────────────────────

    @classmethod
    def _desktop_path(cls) -> Path:
        config_home = os.environ.get(
            "XDG_CONFIG_HOME",
            str(Path.home() / ".config"),
        )
        return (
            Path(config_home) / "autostart"
            / "aegis-wireless.desktop"
        )

    @classmethod
    def _enable_linux(cls) -> bool:
        desktop = cls._desktop_path()
        desktop.parent.mkdir(parents=True, exist_ok=True)

        content = f"""[Desktop Entry]
Type=Application
Name=Aegis Wireless
Comment=WiFi Security Analysis Tool
Exec={cls._launch_command()}
Icon={_APP_DIR / "assets" / "aegis_icon.png"}
Terminal=false
StartupNotify=false
X-GNOME-Autostart-enabled=true
"""
        desktop.write_text(content, encoding="utf-8")
        return True

    @classmethod
    def _disable_linux(cls) -> bool:
        desktop = cls._desktop_path()
        if desktop.exists():
            desktop.unlink()
        return True

    @classmethod
    def _check_linux(cls) -> bool:
        return cls._desktop_path().exists()

    # ─────────────────────────────────────────────────────────
    #  Persist the flag in settings.json
    # ─────────────────────────────────────────────────────────

    @classmethod
    def _save_startup_flag(cls, enabled: bool) -> None:
        """Write the run_on_startup flag into config/settings.json."""
        try:
            data = {}
            if _SETTINGS_FILE.exists():
                data = json.loads(_SETTINGS_FILE.read_text("utf-8"))
            data.setdefault("tray", {})["run_on_startup"] = enabled
            _SETTINGS_FILE.write_text(
                json.dumps(data, indent=4) + "\n", encoding="utf-8"
            )
        except Exception as exc:
            logger.error("Could not save startup flag: %s", exc)