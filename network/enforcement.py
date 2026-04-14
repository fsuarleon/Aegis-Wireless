"""
enforcement.py — Network Enforcement Actions
===============================================
WHAT THIS DOES:
    Takes action based on the risk assessment:
    - Warn the user about unsafe networks (always)
    - Disconnect from dangerous networks (with permission)
    - Log all enforcement actions for auditing

TWO MODES:
    Interactive (default):  Asks user before disconnecting.
    Auto-block:             Disconnects automatically.
                           Used by the system tray background agent.

OS SUPPORT:
    - Windows: uses "netsh wlan disconnect"
    - Linux:   uses "nmcli device disconnect"
"""

# ---------- IMPORTS ----------

import subprocess    # For running OS commands
import platform      # For detecting Windows vs Linux
from typing import Optional
from datetime import datetime


# ---------- NETWORK ENFORCER CLASS ----------

class NetworkEnforcer:
    """
    Handles enforcement actions like warnings and disconnections.
    Supports both interactive (ask user) and automatic modes.
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