"""
wifi_scan.py — WiFi Network Scanner
=====================================
WHAT THIS DOES:
    Detects all WiFi networks your computer can see and collects:
    - SSID (the network name, like "Starbucks_WiFi")
    - Signal strength (how strong the connection is)
    - Encryption type (WPA2, WPA3, Open, etc.)

HOW IT WORKS:
    - On Windows: runs the built-in command "netsh wlan show networks"
    - On Linux:  runs "nmcli dev wifi list" or "iwlist scan"
    - Parses the text output into clean Python dictionaries

NO EXTRA INSTALLS NEEDED — uses only built-in OS commands.
"""

# ---------- IMPORTS ----------
# These are Python libraries that come pre-installed.
# We don't need to install anything extra.

import subprocess   # Lets us run terminal commands from Python
import platform     # Tells us what operating system we're on
import re           # Helps us search text using patterns

# "dataclass" is a shortcut for creating simple data containers
from dataclasses import dataclass, field, asdict
# "List" and "Optional" help us label what types our variables hold
from typing import List, Optional


# ---------- WIFI NETWORK DATA CONTAINER ----------
# This is like a form with blank fields. Each WiFi network
# we find gets its own "form" filled out with these details.

@dataclass
class WiFiNetwork:
    """Represents one WiFi network detected by the scanner."""
    ssid: str                          # Network name (like "Home_WiFi")
    signal_strength: int = 0           # 0-100 (percentage, higher = stronger)
    encryption: str = "Unknown"        # WPA2, WPA3, Open, etc.
    bssid: str = ""                    # MAC address of the router
    channel: int = 0                   # Radio channel number
    band: str = ""                     # 2.4 GHz or 5 GHz

    # 802.11 frame inspection results (populated when available)
    frame_validated: bool = False      # Was frame inspection run?
    frame_encryption: str = ""         # Encryption from beacon frame
    frame_ciphers: str = ""            # e.g. "CCMP-128, TKIP"
    frame_akm: str = ""               # e.g. "PSK, SAE"
    frame_mismatch: bool = False       # OS vs frame disagreement?
    frame_downgrade: bool = False      # TKIP-only on WPA2 label?
    frame_pmf: bool = False            # 802.11w PMF capable?

    def to_dict(self) -> dict:
        """Convert this network's info into a plain dictionary."""
        return asdict(self)


# ---------- WIFI SCANNER CLASS ----------
# This is the main tool. It runs OS commands to find WiFi networks.

class WiFiScanner:
    """
    Scans for nearby WiFi networks using OS-level commands.
    No admin/root privileges needed for basic scanning.

    When Scapy is available the scanner also performs 802.11
    frame inspection to validate encryption from raw beacons.
    """

    def __init__(self):
        # Figure out what OS we're running on
        # This will be "Windows", "Linux", or "Darwin" (macOS)
        self.os_type = platform.system()
        # This list will hold all the networks we find
        self.networks: List[WiFiNetwork] = []

        # 802.11 frame inspector (optional — needs Scapy)
        self._frame_inspector = None
        self._last_frame_data = {}
        self._last_validation = []
        try:
            from scanner.frame_inspector import FrameInspector
            self._frame_inspector = FrameInspector()
        except Exception:
            pass

    # ── PUBLIC METHODS (the ones you actually call) ─────────────

    def scan(self, frame_inspect: bool = True) -> List[WiFiNetwork]:
        """
        Run a WiFi scan and return a list of WiFiNetwork objects.
        Automatically picks the right method for your OS.

        Args:
            frame_inspect: If True (default) and Scapy is available,
                          also run 802.11 frame inspection to validate
                          encryption from raw beacon frames.
        """
        # Clear any old results
        self.networks = []

        # Pick the right scanning method based on OS
        if self.os_type == "Windows":
            self._scan_windows()
        elif self.os_type == "Linux":
            self._scan_linux()
        elif self.os_type == "Darwin":
            self._scan_macos()
        else:
            print(f"[!] Unsupported OS: {self.os_type}")

        # Sort by signal strength (strongest first)
        self.networks.sort(key=lambda n: n.signal_strength, reverse=True)

        # ── 802.11 frame inspection (enrichment layer) ──
        if frame_inspect and self.networks:
            self._run_frame_inspection()

        return self.networks

    def _run_frame_inspection(self):
        """
        Run Scapy-based 802.11 frame inspection and enrich
        the WiFiNetwork objects with beacon-level data.

        This validates the OS-reported encryption against what
        the actual 802.11 beacon frames advertise, and adds
        cipher suite and AKM details.
        """
        if self._frame_inspector is None:
            return
        if not self._frame_inspector.available:
            return

        try:
            # Capture beacons for a few seconds
            frame_data = self._frame_inspector.inspect(timeout=4)
            self._last_frame_data = frame_data

            if not frame_data:
                return

            # Cross-validate OS results against frame data
            validations = self._frame_inspector.validate(
                self.networks, frame_data
            )
            self._last_validation = validations

            # Build a lookup by BSSID for quick matching
            val_by_bssid = {v.bssid: v for v in validations}

            # Enrich each WiFiNetwork with frame-level detail
            for net in self.networks:
                bssid = net.bssid.upper().strip()
                if bssid in frame_data:
                    info = frame_data[bssid]
                    net.frame_validated = True
                    net.frame_encryption = info.encryption_label
                    net.frame_ciphers = ", ".join(
                        info.rsn_pairwise_ciphers
                        or info.wpa_pairwise_ciphers
                    )
                    net.frame_akm = ", ".join(
                        info.rsn_akm_suites
                        or info.wpa_akm_suites
                    )
                    net.frame_pmf = info.supports_pmf

                if bssid in val_by_bssid:
                    val = val_by_bssid[bssid]
                    net.frame_mismatch = not val.match
                    net.frame_downgrade = val.downgrade_risk

        except Exception as exc:
            # Never let frame inspection break the scan
            pass

    def get_frame_validation(self) -> list:
        """Return the last frame validation results as dicts."""
        return [v.to_dict() for v in self._last_validation]

    def get_results_as_dicts(self) -> List[dict]:
        """Return scan results as plain dictionaries (for JSON logging)."""
        return [n.to_dict() for n in self.networks]

    # ── WINDOWS SCANNER ─────────────────────────────────────────

    def _scan_windows(self):
        """
        Uses: netsh wlan show networks mode=bssid
        This is a built-in Windows command — no installs needed.
        """
        try:
            # Run the Windows command and capture its text output
            result = subprocess.run(
                ["netsh", "wlan", "show", "networks", "mode=bssid"],
                capture_output=True,  # Capture the output text
                text=True,            # Return as string, not bytes
                timeout=15,           # Give up after 15 seconds
                # This flag prevents a console window from flashing
                creationflags=subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW") else 0
            )
            # Parse the messy text output into clean data
            self._parse_windows_output(result.stdout)

        except FileNotFoundError:
            print("[!] 'netsh' not found. Are you on Windows?")
        except subprocess.TimeoutExpired:
            print("[!] WiFi scan timed out.")
        except Exception as e:
            print(f"[!] Windows scan error: {e}")

    def _parse_windows_output(self, output: str):
        """
        Parse the text blocks that netsh returns.
        Each network is separated by a blank line.
        """
        # Split the big text into blocks (one per network)
        blocks = output.strip().split("\n\n")

        for block in blocks:
            lines = block.strip().split("\n")
            # Create a blank network "form" to fill in
            network = WiFiNetwork(ssid="")

            for line in lines:
                line = line.strip()

                # Look for the network name (SSID)
                if "SSID" in line and "BSSID" not in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        ssid = parts[1].strip()
                        # If the name is blank, it's a hidden network
                        network.ssid = ssid if ssid else "<Hidden Network>"

                # Look for signal strength (like "Signal : 85%")
                elif "Signal" in line:
                    match = re.search(r"(\d+)%", line)
                    if match:
                        network.signal_strength = int(match.group(1))

                # Look for encryption type
                elif "Authentication" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        network.encryption = self._normalize_encryption(
                            parts[1].strip()
                        )

                # Look for the router's MAC address (BSSID)
                elif "BSSID" in line:
                    parts = line.split(":", 1)
                    if len(parts) == 2:
                        network.bssid = parts[1].strip()

                # Look for the radio channel
                elif "Channel" in line:
                    match = re.search(r"(\d+)", line)
                    if match:
                        ch = int(match.group(1))
                        network.channel = ch
                        # Channels above 14 are 5 GHz
                        network.band = "5 GHz" if ch > 14 else "2.4 GHz"

            # Only add this network if we found a name
            if network.ssid:
                self.networks.append(network)

    # ── LINUX SCANNER ───────────────────────────────────────────

    def _scan_linux(self):
        """
        Uses: nmcli dev wifi list (NetworkManager, most common)
        Fallback: iwlist wlan0 scan (needs sudo)
        """
        try:
            result = subprocess.run(
                ["nmcli", "-t", "-f",
                 "SSID,SIGNAL,SECURITY,BSSID,CHAN",
                 "dev", "wifi", "list"],
                capture_output=True, text=True, timeout=15
            )
            if result.returncode == 0:
                self._parse_linux_nmcli(result.stdout)
                return
        except FileNotFoundError:
            pass

        # Fallback for systems without NetworkManager
        try:
            result = subprocess.run(
                ["sudo", "iwlist", "wlan0", "scan"],
                capture_output=True, text=True, timeout=15
            )
            self._parse_linux_iwlist(result.stdout)
        except FileNotFoundError:
            print("[!] Neither 'nmcli' nor 'iwlist' found.")
            print("    Install NetworkManager: "
                  "sudo apt install network-manager")

    def _parse_linux_nmcli(self, output: str):
        """Parse nmcli colon-separated output."""
        for line in output.strip().split("\n"):
            if not line.strip():
                continue
            parts = line.split(":")
            if len(parts) >= 5:
                ssid = parts[0].strip() or "<Hidden Network>"
                signal = int(parts[1]) if parts[1].isdigit() else 0
                security = parts[2].strip() or "Open"
                bssid = (":".join(parts[3:8]).strip()
                         if len(parts) > 7 else parts[3].strip())
                channel_str = parts[-1].strip()
                ch = int(channel_str) if channel_str.isdigit() else 0

                self.networks.append(WiFiNetwork(
                    ssid=ssid,
                    signal_strength=signal,
                    encryption=self._normalize_encryption(security),
                    bssid=bssid,
                    channel=ch,
                    band="5 GHz" if ch > 14 else "2.4 GHz"
                ))

    def _parse_linux_iwlist(self, output: str):
        """Parse iwlist scan output (fallback for older Linux)."""
        cells = output.split("Cell ")
        for cell in cells[1:]:
            network = WiFiNetwork(ssid="")

            # Find the network name
            ssid_match = re.search(r'ESSID:"([^"]*)"', cell)
            if ssid_match:
                network.ssid = (ssid_match.group(1)
                                or "<Hidden Network>")

            # Find signal strength (convert from dBm to percentage)
            signal_match = re.search(r"Signal level[=:](-?\d+)", cell)
            if signal_match:
                dbm = int(signal_match.group(1))
                network.signal_strength = max(
                    0, min(100, 2 * (dbm + 100))
                )

            # Find encryption type
            if "WPA2" in cell:
                network.encryption = "WPA2"
            elif "WPA" in cell:
                network.encryption = "WPA"
            elif "WEP" in cell:
                network.encryption = "WEP"
            else:
                network.encryption = "Open"

            # Find channel
            ch_match = re.search(r"Channel[:\s]+(\d+)", cell)
            if ch_match:
                ch = int(ch_match.group(1))
                network.channel = ch
                network.band = "5 GHz" if ch > 14 else "2.4 GHz"

            if network.ssid:
                self.networks.append(network)

    # ── macOS SCANNER ───────────────────────────────────────────

    def _scan_macos(self):
        """Uses the macOS airport utility."""
        airport_path = ("/System/Library/PrivateFrameworks/"
                        "Apple80211.framework/Versions/"
                        "Current/Resources/airport")
        try:
            result = subprocess.run(
                [airport_path, "-s"],
                capture_output=True, text=True, timeout=15
            )
            for line in result.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 7:
                    ssid = parts[0]
                    rssi = (int(parts[1])
                            if parts[1].lstrip("-").isdigit() else -80)
                    signal = max(0, min(100, 2 * (rssi + 100)))
                    security = parts[-1]

                    self.networks.append(WiFiNetwork(
                        ssid=ssid,
                        signal_strength=signal,
                        encryption=("Open" if security == "None"
                                    else security)
                    ))
        except Exception as e:
            print(f"[!] macOS scan error: {e}")

    # ── HELPER METHODS ──────────────────────────────────────────

    @staticmethod
    def _normalize_encryption(raw: str) -> str:
        """
        Convert messy OS output into clean encryption labels.
        For example, "WPA2-Personal" becomes "WPA2".
        """
        raw_upper = raw.upper()
        if "WPA3" in raw_upper:
            return "WPA3"
        if "WPA2" in raw_upper and "ENTERPRISE" in raw_upper:
            return "WPA2-Enterprise"
        if "WPA2" in raw_upper:
            return "WPA2"
        if "WPA" in raw_upper:
            return "WPA"
        if "WEP" in raw_upper:
            return "WEP"
        if "OPEN" in raw_upper or raw.strip() == "":
            return "Open"
        return raw.strip()


# ---------- QUICK TEST ----------
# This code ONLY runs if you open this file directly.
# It won't run when another file imports this module.

if __name__ == "__main__":
    scanner = WiFiScanner()
    print(f"[*] Scanning on {scanner.os_type}...\n")
    networks = scanner.scan()

    if not networks:
        print("[!] No networks found. Make sure WiFi is enabled.")
    else:
        # Print a nice table header
        print(f"{'SSID':<30} {'Signal':>6}  "
              f"{'Encryption':<16} {'Channel':>7}")
        print("-" * 70)
        # Print each network on its own line
        for net in networks:
            print(f"{net.ssid:<30} {net.signal_strength:>5}%  "
                  f"{net.encryption:<16} {net.channel:>7}")