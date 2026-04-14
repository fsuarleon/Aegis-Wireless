"""
engine.py — Risk Detection Engine
===================================
WHAT THIS DOES:
    Takes data from the WiFi scanner and port scanner and decides
    how dangerous a network is. It checks for:

    1. Encryption quality  — WPA2/WPA3 or wide open?
    2. Suspicious ports    — Are dangerous services exposed?
    3. Hidden networks     — Networks hiding their name
    4. Signal anomalies    — Extremely strong signal could be
                            an "evil twin" (fake access point)
    5. Blacklisted status  — Has the user flagged this network?

    Produces a SAFETY SCORE from 0 (deadly) to 100 (safe) and a
    human-readable risk level: SAFE / MODERATE / DANGEROUS.
"""

# ---------- IMPORTS ----------

import json
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional
from pathlib import Path


# ---------- RISK LEVEL LABELS ----------
# Simple labels we'll use throughout the project.

class RiskLevel:
    SAFE = "SAFE"
    MODERATE = "MODERATE"
    DANGEROUS = "DANGEROUS"


# ---------- SCORING PENALTIES ----------
# These numbers define how many points each problem costs.

ENCRYPTION_PENALTIES = {
    "Open":     40,   # No encryption at all — very bad
    "WEP":      30,   # WEP can be cracked in under 60 seconds
    "WPA":      15,   # WPA v1 has known weaknesses
    "WPA2":     0,    # Good encryption
    "WPA3":     0,    # Best encryption
    "WPA2-Enterprise": 0,   # Corporate-grade — good
    "WPA3-Enterprise": 0,   # Corporate-grade — best
    "Unknown":  20,   # Can't determine — suspicious
}

# Ports that should NOT be open on public networks
DANGEROUS_PORTS = {23, 135, 139, 445, 3389, 5900, 6379, 27017}

PORT_PENALTY_DANGEROUS = 8   # Points lost per dangerous open port
PORT_PENALTY_UNKNOWN = 3     # Points lost per unknown open port
HIDDEN_SSID_PENALTY = 10     # Points lost for hidden network name
BLACKLIST_PENALTY = 50        # Points lost for being on the blacklist

# Signal strength above this % is suspiciously high
EVIL_TWIN_SIGNAL_THRESHOLD = 95


# ---------- RISK FINDING DATA CONTAINER ----------

@dataclass
class RiskFinding:
    """One specific risk identified during analysis."""
    category: str        # e.g., "encryption", "port", "blacklist"
    severity: str        # "high", "medium", or "low"
    description: str     # Human-readable explanation
    penalty: int         # Points deducted from safety score
    recommendation: str  # What the user should do about it


# ---------- NETWORK ASSESSMENT DATA CONTAINER ----------

@dataclass
class NetworkAssessment:
    """Complete risk assessment for one network."""
    ssid: str                                          # Network name
    encryption: str                                    # Encryption type
    safety_score: int = 100                            # Starts at 100
    risk_level: str = RiskLevel.SAFE                   # Default: safe
    findings: List[RiskFinding] = field(
        default_factory=list
    )
    open_ports: List[int] = field(default_factory=list)
    is_blacklisted: bool = False
    summary: str = ""

    def to_dict(self) -> dict:
        return {
            "ssid": self.ssid,
            "encryption": self.encryption,
            "safety_score": self.safety_score,
            "risk_level": self.risk_level,
            "is_blacklisted": self.is_blacklisted,
            "summary": self.summary,
            "finding_count": len(self.findings),
            "findings": [asdict(f) for f in self.findings],
            "open_ports": self.open_ports,
        }


# ---------- RISK ENGINE CLASS ----------

class RiskEngine:
    """
    Analyzes WiFi networks and produces safety assessments.

    Usage:
        engine = RiskEngine()
        assessment = engine.analyze(wifi_network, port_scan_report)
        print(assessment.risk_level, assessment.safety_score)
    """

    def __init__(self, blacklist_path: str = None):
        """
        Args:
            blacklist_path: Path to the blacklist JSON file.
                           If None, looks in the default location.
        """
        if blacklist_path is None:
            blacklist_path = str(
                Path(__file__).parent.parent
                / "config" / "blacklist.json"
            )
        self.blacklist_path = blacklist_path
        self.blacklisted_networks = self._load_blacklist()

    # ── PUBLIC METHODS ──────────────────────────────────────────

    def analyze(self, wifi_network,
                port_report=None) -> NetworkAssessment:
        """
        Run a full risk analysis on a network.

        Args:
            wifi_network:  A WiFiNetwork object from wifi_scan.py
            port_report:   A ScanReport from port_probe.py (optional)

        Returns:
            NetworkAssessment with score, level, and findings.
        """
        assessment = NetworkAssessment(
            ssid=wifi_network.ssid,
            encryption=wifi_network.encryption,
        )

        # Run each check — each one may add findings and penalties
        self._check_encryption(wifi_network, assessment)
        self._check_hidden_ssid(wifi_network, assessment)
        if port_report:
            self._check_ports(port_report, assessment)
        self._check_signal_anomaly(wifi_network, assessment)
        self._check_blacklist(wifi_network, assessment)

        # Calculate final score (can't go below 0)
        total_penalty = sum(f.penalty for f in assessment.findings)
        assessment.safety_score = max(0, 100 - total_penalty)

        # Assign risk level based on score
        if assessment.safety_score >= 70:
            assessment.risk_level = RiskLevel.SAFE
        elif assessment.safety_score >= 40:
            assessment.risk_level = RiskLevel.MODERATE
        else:
            assessment.risk_level = RiskLevel.DANGEROUS

        # Generate a human-readable summary
        assessment.summary = self._generate_summary(assessment)

        return assessment

    def analyze_multiple(self, networks: list,
                         port_reports: dict = None
                         ) -> List[NetworkAssessment]:
        """
        Analyze multiple networks at once.

        Args:
            networks:     List of WiFiNetwork objects
            port_reports: Dict mapping SSID to ScanReport (optional)

        Returns:
            List of assessments, sorted worst-first.
        """
        if port_reports is None:
            port_reports = {}

        assessments = []
        for net in networks:
            port_report = port_reports.get(net.ssid)
            assessments.append(self.analyze(net, port_report))

        # Sort: most dangerous first
        assessments.sort(key=lambda a: a.safety_score)
        return assessments

    # ── INDIVIDUAL CHECKS ───────────────────────────────────────
    # Each method checks one specific risk factor.

    def _check_encryption(self, network, assessment):
        """Check if the network encryption is strong enough."""
        enc = network.encryption
        penalty = ENCRYPTION_PENALTIES.get(enc, 15)

        if penalty > 0:
            # Determine severity and create a helpful message
            if enc == "Open":
                severity = "high"
                desc = ("Network has NO encryption — all traffic "
                        "is visible to anyone nearby.")
                rec = ("AVOID this network or use a VPN. Never "
                       "enter passwords or banking info.")
            elif enc == "WEP":
                severity = "high"
                desc = ("WEP encryption can be cracked in under "
                        "60 seconds with free tools.")
                rec = ("Treat this the same as an open network. "
                       "Use a VPN if you must connect.")
            elif enc == "WPA":
                severity = "medium"
                desc = ("WPA v1 has known vulnerabilities. Better "
                        "than nothing but outdated.")
                rec = ("Prefer WPA2 or WPA3 networks. Use a VPN "
                       "for sensitive activities.")
            else:
                severity = "medium"
                desc = (f"Encryption type '{enc}' could not "
                        f"be verified.")
                rec = ("Verify the network with venue staff "
                       "before connecting.")

            assessment.findings.append(RiskFinding(
                category="encryption",
                severity=severity,
                description=desc,
                penalty=penalty,
                recommendation=rec,
            ))

    def _check_hidden_ssid(self, network, assessment):
        """Hidden networks can be used to lure devices."""
        if network.ssid in ("<Hidden Network>", ""):
            assessment.findings.append(RiskFinding(
                category="hidden_ssid",
                severity="medium",
                description="Network is hiding its name "
                           "(hidden SSID).",
                penalty=HIDDEN_SSID_PENALTY,
                recommendation="Hidden networks aren't always "
                    "dangerous, but attackers sometimes use them. "
                    "Only connect if you know what it is.",
            ))

    def _check_ports(self, port_report, assessment):
        """Check open ports for known dangerous services."""
        for port_result in port_report.open_ports:
            assessment.open_ports.append(port_result.port)

            if port_result.port in DANGEROUS_PORTS:
                assessment.findings.append(RiskFinding(
                    category="dangerous_port",
                    severity="high",
                    description=(
                        f"Port {port_result.port} "
                        f"({port_result.service}) is open. "
                        f"{port_result.risk_note}"
                    ),
                    penalty=PORT_PENALTY_DANGEROUS,
                    recommendation=(
                        f"Port {port_result.port} should not be "
                        f"exposed on a public network. This could "
                        f"indicate a misconfigured device or "
                        f"active attack."
                    ),
                ))
            elif port_result.service == "Unknown":
                assessment.findings.append(RiskFinding(
                    category="unknown_port",
                    severity="low",
                    description=(
                        f"Port {port_result.port} is open with "
                        f"an unknown service."
                    ),
                    penalty=PORT_PENALTY_UNKNOWN,
                    recommendation="Unusual open ports may "
                        "indicate unauthorized services.",
                ))

    def _check_signal_anomaly(self, network, assessment):
        """Extremely strong signals may be evil twin attacks."""
        if network.signal_strength >= EVIL_TWIN_SIGNAL_THRESHOLD:
            assessment.findings.append(RiskFinding(
                category="signal_anomaly",
                severity="low",
                description=(
                    f"Signal strength is unusually high "
                    f"({network.signal_strength}%). This could "
                    f"be normal (you're close to the router) or "
                    f"could indicate a nearby 'evil twin' "
                    f"access point."
                ),
                penalty=5,
                recommendation="Verify with staff that the "
                    "network name matches the official one. "
                    "An attacker's fake AP is often placed "
                    "physically close to targets.",
            ))

    def _check_blacklist(self, network, assessment):
        """Check if the user previously flagged this network."""
        if network.ssid.lower() in [
            n.lower() for n in self.blacklisted_networks
        ]:
            assessment.is_blacklisted = True
            assessment.findings.append(RiskFinding(
                category="blacklist",
                severity="high",
                description="You previously marked this network "
                           "as UNSAFE.",
                penalty=BLACKLIST_PENALTY,
                recommendation="Do NOT connect. You flagged this "
                    "network for a reason.",
            ))

    # ── HELPER METHODS ──────────────────────────────────────────

    def _load_blacklist(self) -> List[str]:
        """Load the blacklist file if it exists."""
        try:
            with open(self.blacklist_path) as f:
                data = json.load(f)
                return data.get("blacklisted_networks", [])
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def _generate_summary(self, assessment) -> str:
        """Create a one-paragraph summary of the assessment."""
        score = assessment.safety_score
        level = assessment.risk_level
        n = len(assessment.findings)

        if level == RiskLevel.SAFE:
            return (
                f"Network '{assessment.ssid}' appears safe "
                f"(score: {score}/100). "
                f"{'No issues detected.' if n == 0 else f'{n} minor note(s) found.'} "
                f"Standard precautions apply."
            )
        elif level == RiskLevel.MODERATE:
            return (
                f"Network '{assessment.ssid}' has moderate risk "
                f"(score: {score}/100). {n} issue(s) detected. "
                f"Use a VPN if possible and avoid online banking "
                f"or entering passwords."
            )
        else:
            return (
                f"Network '{assessment.ssid}' is DANGEROUS "
                f"(score: {score}/100). {n} serious issue(s) "
                f"found. DO NOT connect without a VPN. Avoid "
                f"all sensitive activities."
            )

    # ── DISPLAY METHOD ──────────────────────────────────────────

    @staticmethod
    def print_assessment(assessment):
        """Pretty-print an assessment to the terminal."""
        # Terminal color codes (make text colorful)
        COLORS = {
            RiskLevel.SAFE: "\033[92m",       # Green
            RiskLevel.MODERATE: "\033[93m",    # Yellow
            RiskLevel.DANGEROUS: "\033[91m",   # Red
        }
        RESET = "\033[0m"
        BOLD = "\033[1m"

        color = COLORS.get(assessment.risk_level, "")

        print(f"\n{'=' * 60}")
        print(f"  {BOLD}NETWORK ASSESSMENT: "
              f"{assessment.ssid}{RESET}")
        print(f"{'=' * 60}")
        print(f"  Encryption:   {assessment.encryption}")
        print(f"  Safety Score: {color}{BOLD}"
              f"{assessment.safety_score}/100{RESET}")
        print(f"  Risk Level:   {color}{BOLD}"
              f"{assessment.risk_level}{RESET}")
        print(f"  Blacklisted:  "
              f"{'YES' if assessment.is_blacklisted else 'No'}")

        if assessment.findings:
            print(f"\n  {BOLD}FINDINGS "
                  f"({len(assessment.findings)}):{RESET}")
            for i, finding in enumerate(assessment.findings, 1):
                sev_icon = {
                    "high": "[HIGH]",
                    "medium": "[MED]",
                    "low": "[LOW]"
                }.get(finding.severity, "[?]")
                print(f"\n  {sev_icon} #{i} "
                      f"[{finding.category.upper()}] "
                      f"(-{finding.penalty} pts)")
                print(f"     {finding.description}")
                print(f"     -> {finding.recommendation}")

        if assessment.open_ports:
            print(f"\n  Open Ports: "
                  f"{', '.join(map(str, assessment.open_ports))}")

        print(f"\n  {BOLD}Summary:{RESET}")
        print(f"  {assessment.summary}")
        print(f"{'=' * 60}\n")