"""
enforcement.py — Network Enforcement Actions
===============================================
WHAT THIS DOES:
    Takes action based on the risk assessment:
    - Warn the user about unsafe networks (always)
    - Disconnect from dangerous networks (with permission)
    - Block networks at the OS level so the device cannot reconnect
    - Log all enforcement actions for auditing

TWO MODES:
    Interactive (default):  Asks user before disconnecting.
    Auto-block:             Disconnects automatically.
                           Used by the system tray background agent.

OS-LEVEL BLOCKING:
    - Windows: netsh wlan add filter permission=block ssid=...
               Also removes any saved WiFi profile for the network.
    - Linux:   nmcli connection delete (removes saved connection)
    - macOS:   networksetup -removePreferredWirelessNetwork

OS SUPPORT:
    - Windows: uses "netsh wlan disconnect"
    - Linux:   uses "nmcli device disconnect"
"""

# ---------- IMPORTS ----------

import subprocess    # For running OS commands
import platform      # For detecting Windows vs Linux
import logging
from typing import Optional, List
from datetime import datetime

logger = logging.getLogger("aegis.enforcement")


# ---------- NETWORK ENFORCER CLASS ----------

class NetworkEnforcer:
    """
    Handles enforcement actions like warnings and disconnections.
    Supports both interactive (ask user) and automatic modes.
    Includes OS-level WiFi profile blocking to prevent
    reconnection to blacklisted networks.
    """

    def __init__(self, auto_block: bool = False):
        """
        Args:
            auto_block: If True, automatically disconnect from
                       DANGEROUS networks without asking.
        """
        self.os_type = platform.system()
        self.auto_block = auto_block
        self.action_log = []     # In-memory log of actions taken
        self.total_blocks = 0    # Counter of total disconnections

    # ── PUBLIC METHODS ──────────────────────────────────────────

    def enforce(self, assessment,
                auto_disconnect: bool = None) -> str:
        """
        Decide and execute enforcement based on an assessment.

        Args:
            assessment:       A NetworkAssessment from engine.py
            auto_disconnect:  Override auto-block for this call.
                             None = use self.auto_block setting.

        Returns:
            Action taken: "none", "warned", "disconnected",
            or "blocked"
        """
        # Determine blocking mode
        should_auto_block = (
            auto_disconnect if auto_disconnect is not None
            else self.auto_block
        )

        risk = assessment.risk_level
        action = "none"

        if risk == "SAFE":
            self._log_action(assessment.ssid, "none",
                           "Network is safe.")
            return "none"

        # ── MODERATE risk ──
        if risk == "MODERATE":
            self._print_warning(assessment)
            self._log_action(assessment.ssid, "warned",
                           "Moderate risk warning issued.")
            action = "warned"

        # ── DANGEROUS risk ──
        elif risk == "DANGEROUS":
            self._print_danger(assessment)

            if should_auto_block:
                # Automatic enforcement — no user prompt
                success = self._disconnect()
                action = "blocked" if success else "disconnect_failed"
                if success:
                    self.total_blocks += 1
                    print("  [*] Connection automatically "
                          "blocked by policy.")
            else:
                # Interactive mode — ask user for permission
                print("\n  Would you like to disconnect "
                      "from this network?")
                response = input(
                    "  Type 'yes' to disconnect, "
                    "anything else to stay: "
                ).strip().lower()

                if response in ("yes", "y"):
                    success = self._disconnect()
                    action = ("disconnected" if success
                              else "disconnect_failed")
                else:
                    print("  [*] Staying connected. "
                          "Please use a VPN.")
                    action = "warned"

            self._log_action(
                assessment.ssid, action,
                f"Score: {assessment.safety_score}/100"
            )

        return action

    def get_action_log(self) -> list:
        """Return the full log of enforcement actions."""
        return self.action_log

    # ── DISCONNECT METHOD ───────────────────────────────────────

    def _disconnect(self) -> bool:
        """
        Disconnect from the current WiFi network.
        Uses OS-specific commands.
        """
        print("  [*] Disconnecting from WiFi...")

        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ["netsh", "wlan", "disconnect"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if hasattr(subprocess, "CREATE_NO_WINDOW")
                        else 0
                    )
                )
            elif self.os_type == "Linux":
                result = subprocess.run(
                    ["nmcli", "device", "disconnect", "wlan0"],
                    capture_output=True, text=True, timeout=10
                )
            elif self.os_type == "Darwin":
                result = subprocess.run(
                    ["networksetup", "-setairportpower",
                     "en0", "off"],
                    capture_output=True, text=True, timeout=10
                )
            else:
                print(f"  [!] Disconnect not supported "
                      f"on {self.os_type}")
                return False

            if result.returncode == 0:
                print("  [OK] Disconnected successfully.")
                return True
            else:
                print(f"  [!] Disconnect error: "
                      f"{result.stderr.strip()}")
                return False

        except subprocess.TimeoutExpired:
            print("  [!] Disconnect command timed out.")
            return False
        except FileNotFoundError:
            print("  [!] Network command not found "
                  "for this OS.")
            return False
        except Exception as e:
            print(f"  [!] Disconnect failed: {e}")
            return False

    # ══════════════════════════════════════════════════════════════
    #  OS-LEVEL WIFI BLOCKING
    #  Prevents the device from reconnecting to a blacklisted SSID.
    # ══════════════════════════════════════════════════════════════

    def block_network(self, ssid: str) -> bool:
        """
        Block a WiFi network at the OS level so the device
        cannot reconnect to it.

        Windows:
            1. Adds a 'deny' filter via netsh so the network
               is hidden from the available-networks list.
            2. Deletes any saved WiFi profile for the SSID
               so auto-connect won't fire.

        Linux:
            1. Deletes any saved connection for the SSID.

        macOS:
            1. Removes the SSID from the preferred list.

        Returns True if at least one command succeeded.
        """
        try:
            if self.os_type == "Windows":
                return self._block_windows(ssid)
            elif self.os_type == "Linux":
                return self._block_linux(ssid)
            elif self.os_type == "Darwin":
                return self._block_macos(ssid)
            else:
                logger.warning(
                    "OS-level block not supported on %s",
                    self.os_type,
                )
                return False
        except Exception as exc:
            logger.error(
                "Failed to block '%s' at OS level: %s",
                ssid, exc,
            )
            return False

    def unblock_network(self, ssid: str) -> bool:
        """
        Remove the OS-level block for a WiFi network,
        allowing the device to see and connect to it again.

        Returns True if the unblock command succeeded.
        """
        try:
            if self.os_type == "Windows":
                return self._unblock_windows(ssid)
            elif self.os_type == "Linux":
                # On Linux deleting the connection IS the block;
                # unblocking just means the user can reconnect.
                logger.info(
                    "Linux: '%s' unblocked (no saved profile "
                    "to restore).", ssid,
                )
                return True
            elif self.os_type == "Darwin":
                logger.info(
                    "macOS: '%s' unblocked (no saved profile "
                    "to restore).", ssid,
                )
                return True
            else:
                return False
        except Exception as exc:
            logger.error(
                "Failed to unblock '%s': %s", ssid, exc,
            )
            return False

    def sync_os_blocks(self, blacklisted_ssids: List[str]) -> int:
        """
        Ensure every blacklisted SSID is blocked at the OS level.
        Call on startup to catch networks that were added to the
        blacklist while the app wasn't running.

        Returns the number of networks newly blocked.
        """
        count = 0
        for ssid in blacklisted_ssids:
            if self.block_network(ssid):
                count += 1
        if count:
            logger.info(
                "Synced OS-level blocks for %d network(s).",
                count,
            )
        return count

    # ── Windows blocking ─────────────────────────────────────────

    def _block_windows(self, ssid: str) -> bool:
        """
        Block on Windows using netsh filter + profile deletion.
        """
        blocked = False
        cflags = (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )

        # Step 1: Add a deny filter — hides the network
        # from the available-networks list entirely.
        result = subprocess.run(
            [
                "netsh", "wlan", "add", "filter",
                "permission=block",
                f"ssid={ssid}",
                "networktype=infrastructure",
            ],
            capture_output=True, text=True, timeout=10,
            creationflags=cflags,
        )
        if result.returncode == 0:
            logger.info(
                "Windows: deny filter added for '%s'.", ssid,
            )
            blocked = True
        else:
            logger.warning(
                "Windows: deny filter failed for '%s': %s",
                ssid, result.stderr.strip(),
            )

        # Step 2: Delete the saved profile so auto-connect
        # cannot fire (ignore errors — profile may not exist).
        result2 = subprocess.run(
            [
                "netsh", "wlan", "delete", "profile",
                f"name={ssid}",
            ],
            capture_output=True, text=True, timeout=10,
            creationflags=cflags,
        )
        if result2.returncode == 0:
            logger.info(
                "Windows: deleted saved profile for '%s'.", ssid,
            )
        else:
            logger.debug(
                "Windows: no saved profile for '%s' (OK).", ssid,
            )

        self._log_action(
            ssid,
            "os_block" if blocked else "os_block_failed",
            "Added Windows deny filter"
            if blocked else "Deny filter failed",
        )
        return blocked

    def _unblock_windows(self, ssid: str) -> bool:
        """Remove the deny filter on Windows."""
        cflags = (
            subprocess.CREATE_NO_WINDOW
            if hasattr(subprocess, "CREATE_NO_WINDOW")
            else 0
        )
        result = subprocess.run(
            [
                "netsh", "wlan", "delete", "filter",
                "permission=block",
                f"ssid={ssid}",
                "networktype=infrastructure",
            ],
            capture_output=True, text=True, timeout=10,
            creationflags=cflags,
        )
        if result.returncode == 0:
            logger.info(
                "Windows: deny filter removed for '%s'.", ssid,
            )
            self._log_action(
                ssid, "os_unblock",
                "Removed Windows deny filter",
            )
            return True
        else:
            logger.warning(
                "Windows: remove filter failed for '%s': %s",
                ssid, result.stderr.strip(),
            )
            return False

    # ── Linux blocking ───────────────────────────────────────────

    def _block_linux(self, ssid: str) -> bool:
        """Delete any saved NetworkManager connection."""
        result = subprocess.run(
            ["nmcli", "connection", "delete", ssid],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            logger.info(
                "Linux: deleted connection for '%s'.", ssid,
            )
        else:
            logger.debug(
                "Linux: no saved connection for '%s' (OK).",
                ssid,
            )
        self._log_action(
            ssid, "os_block",
            "Deleted Linux NM connection",
        )
        return True

    # ── macOS blocking ───────────────────────────────────────────

    def _block_macos(self, ssid: str) -> bool:
        """Remove SSID from the preferred wireless list."""
        result = subprocess.run(
            [
                "networksetup",
                "-removePreferredWirelessNetwork",
                "en0", ssid,
            ],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            logger.info(
                "macOS: removed '%s' from preferred list.", ssid,
            )
        else:
            logger.debug(
                "macOS: '%s' not in preferred list (OK).", ssid,
            )
        self._log_action(
            ssid, "os_block",
            "Removed from macOS preferred list",
        )
        return True

    # ── DISPLAY METHODS ─────────────────────────────────────────

    @staticmethod
    def _print_warning(assessment):
        """Show a yellow warning for moderate-risk networks."""
        YELLOW = "\033[93m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

        print(f"\n  {YELLOW}{BOLD}WARNING — MODERATE RISK: "
              f"{assessment.ssid}{RESET}")
        print(f"  {YELLOW}   Score: "
              f"{assessment.safety_score}/100{RESET}")
        print(f"  {YELLOW}   Consider using a VPN on "
              f"this network.{RESET}")

        # Show up to 3 findings
        for f in assessment.findings[:3]:
            print(f"  {YELLOW}   - {f.description}{RESET}")

    @staticmethod
    def _print_danger(assessment):
        """Show a red alert for dangerous networks."""
        RED = "\033[91m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

        print(f"\n  {RED}{BOLD}ALERT — DANGEROUS NETWORK: "
              f"{assessment.ssid}{RESET}")
        print(f"  {RED}   Score: "
              f"{assessment.safety_score}/100{RESET}")
        print(f"  {RED}   THIS NETWORK IS NOT SAFE "
              f"FOR USE.{RESET}")

        for f in assessment.findings:
            icon = "[HIGH]" if f.severity == "high" else "[MED]"
            print(f"  {RED}   {icon} {f.description}{RESET}")
            print(f"  {RED}     -> "
                  f"{f.recommendation}{RESET}")

    # ── LOGGING ─────────────────────────────────────────────────

    def _log_action(self, ssid: str, action: str,
                    details: str = ""):
        """Record an enforcement action to the in-memory log."""
        self.action_log.append({
            "timestamp": datetime.now().isoformat(),
            "ssid": ssid,
            "action": action,
            "details": details,
        })