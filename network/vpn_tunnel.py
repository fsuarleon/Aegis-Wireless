"""
vpn_tunnel.py — VPN Tunnel Placeholder
========================================
WHAT THIS FILE IS:
    A VPN status checker with stubs for future integration.
    Currently provides:
    - VPN status checking (detects if you're using one)
    - Recommendations for VPN providers
    - Stubs for future WireGuard/OpenVPN integration

WHY IT'S A PLACEHOLDER:
    Building a real VPN client requires system-level privileges
    and depends on your VPN provider's API. This module is
    designed to be extended once you pick a provider.
"""

# ---------- IMPORTS ----------

import subprocess    # For running OS commands
import platform      # For detecting Windows vs Linux
import socket        # For network checks
from typing import Dict, Optional


# ---------- VPN STATUS CHECKER ----------

class VPNStatus:
    """Check whether the system is currently using a VPN."""

    @staticmethod
    def is_vpn_active() -> bool:
        """
        Heuristic check: are we likely behind a VPN?
        Checks for common VPN network adapter names.
        This is NOT foolproof — a real check would query
        the VPN client directly.
        """
        os_type = platform.system()

        try:
            if os_type == "Windows":
                # Run ipconfig and look for VPN adapter names
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if hasattr(subprocess, "CREATE_NO_WINDOW")
                        else 0
                    )
                )
                output = result.stdout.lower()
                # These words appear in VPN adapter names
                vpn_indicators = [
                    "tap-windows", "wireguard", "wintun",
                    "vpn", "tunnel", "nordlynx", "proton"
                ]
                return any(ind in output
                           for ind in vpn_indicators)

            elif os_type == "Linux":
                # Check for VPN network interfaces
                result = subprocess.run(
                    ["ip", "link", "show"],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout.lower()
                vpn_indicators = [
                    "tun0", "wg0", "tap0", "vpn",
                    "wireguard", "nordlynx", "proton"
                ]
                return any(ind in output
                           for ind in vpn_indicators)

            elif os_type == "Darwin":
                result = subprocess.run(
                    ["ifconfig"],
                    capture_output=True, text=True, timeout=10
                )
                output = result.stdout.lower()
                return "utun" in output or "ipsec" in output

        except Exception:
            pass

        return False

    @staticmethod
    def get_public_ip() -> Optional[str]:
        """
        Try to determine the local network IP address.
        If a VPN is active, this may show the VPN's IP.
        """
        try:
            sock = socket.socket(
                socket.AF_INET, socket.SOCK_DGRAM
            )
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return None

    @staticmethod
    def recommend_vpn() -> Dict[str, str]:
        """Return VPN recommendations for different needs."""
        return {
            "Best Overall": (
                "Mullvad VPN — privacy-focused, no email "
                "needed, open source (mullvad.net)"
            ),
            "Best Free": (
                "ProtonVPN — free tier available, Swiss-based, "
                "no-log policy (protonvpn.com)"
            ),
            "Best for Speed": (
                "WireGuard — lightweight protocol, can be "
                "self-hosted (wireguard.com)"
            ),
            "Self-Hosted": (
                "Algo VPN — deploy your own VPN server on "
                "a cloud VM (github.com/trailofbits/algo)"
            ),
        }


# ---------- STUB FOR FUTURE INTEGRATION ----------

class VPNTunnel:
    """
    Future: Manage a WireGuard or OpenVPN tunnel.
    This is a stub — methods show the intended API
    but are not yet implemented.
    """

    def __init__(self, config_path: str = None):
        self.config_path = config_path
        self.connected = False

    def connect(self) -> bool:
        """Connect to VPN. (Not yet implemented)"""
        print("[*] VPN tunnel connect — not yet implemented.")
        print("    To add VPN support:")
        print("    1. Install WireGuard: "
              "https://wireguard.com/install/")
        print("    2. Place your .conf file in config/vpn/")
        print("    3. Extend this class to call "
              "'wg-quick up <config>'")
        return False

    def disconnect(self) -> bool:
        """Disconnect from VPN. (Not yet implemented)"""
        print("[*] VPN tunnel disconnect — "
              "not yet implemented.")
        return False

    def status(self) -> Dict:
        """Get VPN tunnel status."""
        return {
            "connected": self.connected,
            "vpn_detected": VPNStatus.is_vpn_active(),
        }