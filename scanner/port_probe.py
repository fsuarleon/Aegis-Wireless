"""
port_probe.py — Network Port Scanner
======================================
WHAT THIS DOES:
    Scans a target IP address to find "open ports" — doors into
    a device that are listening for connections.

HOW IT WORKS:
    Uses Python's built-in "socket" library to try connecting
    to each port. If the connection succeeds, the port is open.
    If it fails or times out, the port is closed.

    We use "threading" to scan many ports at once (parallel),
    making it MUCH faster than checking one at a time.

LEGAL NOTE:
    Only scan devices YOU own or have explicit permission to scan.
    Scanning others' devices without consent may violate laws.
"""

# ---------- IMPORTS ----------

import socket       # Built-in library for network connections
import json         # For reading JSON files
import os           # For file paths
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from pathlib import Path


# ---------- PORT DATABASE ----------
# Maps port numbers to (service_name, risk_description).
# These are well-known ports that specific services use.

PORT_DATABASE: Dict[int, tuple] = {
    20:   ("FTP Data",      "File transfer (data channel)"),
    21:   ("FTP",           "File transfer — often unencrypted"),
    22:   ("SSH",           "Secure shell — generally safe if updated"),
    23:   ("Telnet",        "DANGEROUS — sends passwords in plain text"),
    25:   ("SMTP",          "Email sending — can be abused for spam"),
    53:   ("DNS",           "Domain name resolution"),
    80:   ("HTTP",          "Unencrypted web traffic"),
    110:  ("POP3",          "Email retrieval — often unencrypted"),
    135:  ("MS-RPC",        "Windows RPC — common attack target"),
    139:  ("NetBIOS",       "Windows file sharing — frequently exploited"),
    143:  ("IMAP",          "Email access — check for TLS"),
    443:  ("HTTPS",         "Encrypted web traffic — generally safe"),
    445:  ("SMB",           "Windows file sharing — ransomware vector"),
    993:  ("IMAPS",         "Encrypted email — safe"),
    995:  ("POP3S",         "Encrypted email — safe"),
    1433: ("MS-SQL",        "Database — should not be exposed publicly"),
    1521: ("Oracle DB",     "Database — should not be exposed publicly"),
    3306: ("MySQL",         "Database — should not be exposed publicly"),
    3389: ("RDP",           "Remote Desktop — major attack target"),
    5432: ("PostgreSQL",    "Database — should not be exposed publicly"),
    5900: ("VNC",           "Remote desktop — often unencrypted"),
    6379: ("Redis",         "Database — often has no authentication"),
    8080: ("HTTP-Alt",      "Alternative web server"),
    8443: ("HTTPS-Alt",     "Alternative encrypted web server"),
    27017: ("MongoDB",      "Database — often left unprotected"),
}


# ---------- PORT RESULT DATA CONTAINER ----------

@dataclass
class PortResult:
    """Represents the scan result for a single port."""
    port: int                        # The port number (e.g., 80)
    state: str                       # "open", "closed", or "filtered"
    service: str = "Unknown"         # Name of the service (e.g., "HTTP")
    risk_note: str = ""              # Description of the risk
    banner: str = ""                 # Text the service sends back

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ScanReport:
    """Complete scan report for one target."""
    target: str                                      # IP address scanned
    open_ports: List[PortResult] = field(
        default_factory=list
    )
    closed_count: int = 0                            # How many were closed
    total_scanned: int = 0                           # Total ports checked

    def to_dict(self) -> dict:
        return {
            "target": self.target,
            "total_scanned": self.total_scanned,
            "open_port_count": len(self.open_ports),
            "closed_count": self.closed_count,
            "open_ports": [p.to_dict() for p in self.open_ports],
        }


# ---------- PORT SCANNER CLASS ----------

class PortScanner:
    """
    Multi-threaded port scanner using only Python's built-in
    libraries. No nmap or third-party tools required.
    """

    def __init__(self, timeout: float = 1.0, max_threads: int = 50):
        """
        Args:
            timeout:     Seconds to wait per port connection attempt.
            max_threads: How many ports to scan at the same time.
        """
        self.timeout = timeout
        self.max_threads = max_threads

        # Try to load settings from config file
        self._load_settings()

    def _load_settings(self):
        """Try to load scan settings from config/settings.json."""
        self.common_ports = sorted(PORT_DATABASE.keys())
        self.default_port_range = (1, 1024)

        config_path = (Path(__file__).parent.parent
                       / "config" / "settings.json")
        if config_path.exists():
            try:
                with open(config_path) as f:
                    cfg = json.load(f)
                scan_cfg = cfg.get("scan_settings", {})
                self.timeout = scan_cfg.get(
                    "scan_timeout_seconds", self.timeout
                )
                self.max_threads = scan_cfg.get(
                    "max_threads", self.max_threads
                )
                if "common_ports" in scan_cfg:
                    self.common_ports = sorted(scan_cfg["common_ports"])
                if "default_port_range" in scan_cfg:
                    pr = scan_cfg["default_port_range"]
                    if isinstance(pr, list) and len(pr) == 2:
                        self.default_port_range = (pr[0], pr[1])
            except (json.JSONDecodeError, KeyError):
                pass  # Use defaults if config is broken

    # ── PUBLIC METHODS ──────────────────────────────────────────

    def scan(self, target: str, port_range: tuple = None,
             specific_ports: List[int] = None) -> ScanReport:
        """
        Scan a target for open ports.

        Args:
            target:         IP address or hostname (e.g., "192.168.1.1")
            port_range:     Tuple of (start, end) e.g., (1, 1024)
            specific_ports: Specific list of port numbers to scan

        Returns:
            ScanReport with all findings.
        """
        # Resolve hostname to IP address
        try:
            resolved_ip = socket.gethostbyname(target)
        except socket.gaierror:
            print(f"[!] Cannot resolve hostname: {target}")
            return ScanReport(target=target)

        # Decide which ports to scan
        if specific_ports:
            ports = specific_ports
        elif port_range:
            ports = list(range(port_range[0], port_range[1] + 1))
        else:
            # Default: scan the well-known ports from our database
            ports = sorted(PORT_DATABASE.keys())

        report = ScanReport(target=resolved_ip,
                           total_scanned=len(ports))

        print(f"[*] Scanning {resolved_ip} — {len(ports)} ports "
              f"with {self.max_threads} threads...")

        # ── Multi-threaded scan ──
        # This runs many port checks at the same time for speed
        with ThreadPoolExecutor(
            max_workers=self.max_threads
        ) as executor:
            # Submit all port checks to the thread pool
            futures = {
                executor.submit(self._probe_port, resolved_ip, port): port
                for port in ports
            }

            completed = 0
            for future in as_completed(futures):
                completed += 1
                result = future.result()

                if result.state == "open":
                    report.open_ports.append(result)
                    print(f"    [+] Port {result.port:<6} OPEN  — "
                          f"{result.service} ({result.risk_note})")
                else:
                    report.closed_count += 1

                # Show progress every 100 ports
                if completed % 100 == 0:
                    print(f"    ... scanned {completed}/"
                          f"{len(ports)} ports")

        # Sort open ports by number
        report.open_ports.sort(key=lambda p: p.port)
        return report

    def quick_scan(self, target: str) -> ScanReport:
        """Scan only the common ports from settings.json (fast)."""
        return self.scan(target, specific_ports=self.common_ports)

    def full_scan(self, target: str) -> ScanReport:
        """Scan the default_port_range from settings.json."""
        return self.scan(target, port_range=self.default_port_range)

    # ── INTERNAL METHODS ────────────────────────────────────────

    def _probe_port(self, ip: str, port: int) -> PortResult:
        """
        Try to connect to one port on the target.
        This runs inside a thread — many of these run at once.
        """
        # Look up what service this port usually runs
        service, risk_note = PORT_DATABASE.get(
            port, ("Unknown", "")
        )

        try:
            # Create a TCP socket (like picking up a phone)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set how long to wait before giving up
            sock.settimeout(self.timeout)

            # Try to connect (like dialing the number)
            result_code = sock.connect_ex((ip, port))

            if result_code == 0:
                # Connection succeeded — port is open!
                # Try to grab a "banner" (service greeting text)
                banner = self._grab_banner(sock)
                sock.close()
                return PortResult(
                    port=port, state="open",
                    service=service, risk_note=risk_note,
                    banner=banner
                )

            sock.close()
            return PortResult(port=port, state="closed",
                             service=service)

        except socket.timeout:
            return PortResult(port=port, state="filtered",
                             service=service)
        except OSError:
            return PortResult(port=port, state="closed",
                             service=service)

    def _grab_banner(self, sock: socket.socket) -> str:
        """
        Try to read the first response from an open port.
        Many services announce themselves when you connect.
        """
        try:
            sock.settimeout(0.5)
            banner = sock.recv(1024).decode(
                "utf-8", errors="replace"
            ).strip()
            return banner[:200]  # Limit banner length
        except Exception:
            return ""

    # ── UTILITY METHODS ─────────────────────────────────────────

    @staticmethod
    def get_local_ip() -> str:
        """
        Find this computer's IP address on the local network.
        Creates a brief UDP socket (doesn't actually send anything).
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.connect(("8.8.8.8", 80))
            local_ip = sock.getsockname()[0]
            sock.close()
            return local_ip
        except Exception:
            return "127.0.0.1"

    @staticmethod
    def get_network_prefix(ip: str) -> str:
        """
        Get the first 3 parts of an IP address.
        Example: '192.168.1.42' becomes '192.168.1.'
        Used to scan other devices on the same network.
        """
        parts = ip.rsplit(".", 1)
        return parts[0] + "." if len(parts) == 2 else ip


# ---------- QUICK TEST ----------
if __name__ == "__main__":
    scanner = PortScanner()
    local_ip = scanner.get_local_ip()
    print(f"[*] Your local IP: {local_ip}\n")

    # Scan your own machine (always legal!)
    report = scanner.quick_scan("127.0.0.1")

    print(f"\n{'=' * 50}")
    print(f"  Scan Complete: {report.target}")
    print(f"  Ports scanned: {report.total_scanned}")
    print(f"  Open ports:    {len(report.open_ports)}")
    print(f"  Closed ports:  {report.closed_count}")
    print(f"{'=' * 50}")