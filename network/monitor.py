"""
monitor.py — Real-Time WiFi Connection Monitor
=================================================
WHAT THIS DOES:
    Watches your WiFi connection in real time. Every few seconds
    it checks what network you're connected to and enforces
    security policy:

    1. NEW CONNECTION DETECTED:
       - Is the SSID blacklisted?
         YES → Disconnect immediately, log incident, toast alert.
              (OS-level block already prevents most reconnection
               attempts, but this catches edge cases.)
         NO  → Is the SSID trusted?
           YES → Allow, toast: "Connected safely"
           NO  → Run a full policy scan:
               a) Check encryption against minimum_encryption
               b) Check if open networks are allowed
               c) Port-scan the default gateway for dangerous
                  services (multi-threaded, quick scan)
               d) Run risk engine analysis (with port data
                  and 802.11 frame validation results)
               e) Check safety score against max_acceptable_risk_score
               f) PASS → toast: "Connected safely to <network>"
               g) FAIL → Add to blacklist (+ OS-level block),
                         disconnect, toast alert.

    2. DISCONNECTION DETECTED:
       - Logs the disconnection event.

OS SUPPORT:
    - Windows: netsh wlan show interfaces / netsh wlan disconnect
    - Linux:   nmcli / nmcli device disconnect
    - macOS:   airport / networksetup
"""

import subprocess
import platform
import threading
import time
import logging
import re
from typing import Optional
from datetime import datetime

logger = logging.getLogger("aegis.monitor")

# ── Encryption hierarchy for minimum_encryption policy ──
_ENCRYPTION_RANK = {
    "Open": 0,
    "WEP": 1,
    "WPA": 2,
    "WPA2": 3,
    "WPA2-Enterprise": 4,
    "WPA3": 5,
    "WPA3-Enterprise": 6,
}


def _enc_rank(enc_type: str) -> int:
    """Return the security rank for an encryption type."""
    return _ENCRYPTION_RANK.get(enc_type, -1)


class ConnectionMonitor:
    """
    Background thread that monitors WiFi connection changes
    and enforces blacklist/risk policy in real time.

    Policy checks performed on every new connection:
    - Blacklist check (instant block)
    - Trusted SSID check (instant allow)
    - Encryption minimum check (from settings.json)
    - Open network check (from settings.json)
    - Port scan of default gateway
    - Full risk engine analysis + score threshold
    """

    def __init__(self, wifi_scanner, risk_engine, blacklist,
                 enforcer, aegis_logger, policy: dict,
                 port_scanner=None):
        """
        Args:
            wifi_scanner:  WiFiScanner instance
            risk_engine:   RiskEngine instance
            blacklist:     BlacklistManager instance
            enforcer:      NetworkEnforcer instance
            aegis_logger:  AegisLogger instance
            policy:        Policy dict from settings.json
            port_scanner:  PortScanner instance (optional)
        """
        self.wifi_scanner = wifi_scanner
        self.risk_engine = risk_engine
        self.blacklist = blacklist
        self.enforcer = enforcer
        self.logger = aegis_logger
        self.policy = policy
        self.port_scanner = port_scanner

        self.os_type = platform.system()
        self._running = False
        self._thread = None
        self._current_ssid = None       # Last known connected SSID
        self._poll_interval = 5         # Seconds between checks
        self._incident_log = []         # In-memory incident history

    # ─────────────────────────────────────────────────────────
    #  Start / Stop
    # ─────────────────────────────────────────────────────────

    def start(self):
        """Start the connection monitor background thread."""
        if self._running:
            return
        self._running = True

        # Get the initial connection
        self._current_ssid = self._get_connected_ssid()

        # If already connected, scan that network now
        if self._current_ssid:
            logger.info(
                "Monitor started. Already connected to: %s",
                self._current_ssid,
            )
            threading.Thread(
                target=self._on_connect,
                args=(self._current_ssid,),
                daemon=True,
            ).start()
        else:
            logger.info("Monitor started. Not connected to WiFi.")

        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True
        )
        self._thread.start()
        logger.info("Connection monitor active (polling every %ds).",
                     self._poll_interval)

    def stop(self):
        """Stop the monitor."""
        self._running = False
        logger.info("Connection monitor stopped.")

    # ─────────────────────────────────────────────────────────
    #  Main monitor loop
    # ─────────────────────────────────────────────────────────

    def _monitor_loop(self):
        """Poll for connection changes every N seconds."""
        while self._running:
            try:
                new_ssid = self._get_connected_ssid()

                if new_ssid != self._current_ssid:
                    old_ssid = self._current_ssid
                    self._current_ssid = new_ssid

                    if new_ssid and not old_ssid:
                        # Just connected to a network
                        logger.info("New connection detected: %s",
                                     new_ssid)
                        self._on_connect(new_ssid)

                    elif new_ssid and old_ssid:
                        # Switched from one network to another
                        logger.info("Switched from %s to %s",
                                     old_ssid, new_ssid)
                        self._on_connect(new_ssid)

                    elif not new_ssid and old_ssid:
                        # Disconnected
                        logger.info("Disconnected from %s",
                                     old_ssid)

            except Exception as exc:
                logger.error("Monitor error: %s", exc)

            time.sleep(self._poll_interval)

    # ─────────────────────────────────────────────────────────
    #  Connection event handler
    # ─────────────────────────────────────────────────────────

    def _on_connect(self, ssid: str):
        """
        Called when a new WiFi connection is detected.

        Full policy enforcement flow:
        1. Blacklist check       → block if listed
        2. Trusted SSID check    → allow if trusted
        3. WiFi scan + policy checks:
           a. Open network check
           b. Minimum encryption check
           c. Port scan of default gateway
           d. Risk engine analysis (with port data)
           e. Score threshold check
        4. PASS → allow + notify
        5. FAIL → blacklist + OS-block + disconnect + notify
        """
        from ui.notifications import NotificationManager

        timestamp = datetime.now().isoformat()

        # ── Step 1: Blacklist check ──
        if self.blacklist.is_blacklisted(ssid):
            logger.warning("BLOCKED: %s is blacklisted.", ssid)

            # Disconnect immediately
            success = self._disconnect()

            # Log incident
            incident = {
                "timestamp": timestamp,
                "ssid": ssid,
                "action": "blocked",
                "reason": "Network is on the blacklist",
                "disconnect_success": success,
            }
            self._incident_log.append(incident)
            self.logger.log_message(
                f"BLOCKED connection to blacklisted network: {ssid}"
            )

            # Toast notification
            NotificationManager.connection_blocked(
                ssid, "This network is on your blacklist."
            )
            return

        # ── Step 2: Trusted SSID check ──
        trusted = [
            t.lower()
            for t in self.policy.get("trusted_ssids", [])
        ]
        if ssid.lower() in trusted:
            logger.info(
                "TRUSTED: %s is in trusted_ssids. Skipping scan.",
                ssid,
            )
            NotificationManager.connection_allowed(ssid)
            self.logger.log_message(
                f"Trusted network connected: {ssid}"
            )
            return

        # ── Step 3: Scan and analyze ──
        logger.info("Scanning network for policy compliance: %s",
                     ssid)

        try:
            networks = self.wifi_scanner.scan()
            target_net = None
            for net in networks:
                if net.ssid.lower() == ssid.lower():
                    target_net = net
                    break

            if target_net:
                # ── 3a: Open network policy check ──
                allow_open = self.policy.get(
                    "allow_open_networks", False
                )
                if (target_net.encryption == "Open"
                        and not allow_open):
                    logger.warning(
                        "POLICY FAIL: %s is an open network "
                        "(open networks are blocked by policy).",
                        ssid,
                    )
                    self._block_and_disconnect(
                        ssid, timestamp,
                        reason="Open network blocked by policy",
                        detail=(
                            "Unencrypted network. Policy "
                            "requires encryption."
                        ),
                    )
                    return

                # ── 3b: Minimum encryption check ──
                min_enc = self.policy.get(
                    "minimum_encryption", "WPA2"
                )
                net_rank = _enc_rank(target_net.encryption)
                min_rank = _enc_rank(min_enc)
                if 0 <= net_rank < min_rank:
                    logger.warning(
                        "POLICY FAIL: %s uses %s but policy "
                        "requires %s minimum.",
                        ssid, target_net.encryption, min_enc,
                    )
                    self._block_and_disconnect(
                        ssid, timestamp,
                        reason=(
                            f"Encryption {target_net.encryption} "
                            f"below minimum ({min_enc})"
                        ),
                        detail=(
                            f"Uses {target_net.encryption}. "
                            f"Policy requires {min_enc} or higher."
                        ),
                    )
                    return

                # ── 3c: Port scan of default gateway ──
                port_report = None
                if self.port_scanner:
                    try:
                        gateway = self._get_default_gateway()
                        if gateway:
                            logger.info(
                                "Port-scanning gateway %s ...",
                                gateway,
                            )
                            port_report = (
                                self.port_scanner.quick_scan(gateway)
                            )
                            if port_report:
                                self.logger.log_port_scan(
                                    port_report.to_dict()
                                )
                    except Exception as exc:
                        logger.warning(
                            "Gateway port scan failed: %s", exc
                        )

                # ── 3d: Full risk engine analysis ──
                assessment = self.risk_engine.analyze(
                    target_net, port_report=port_report
                )

                # ── 3e: Score threshold check ──
                max_score = self.policy.get(
                    "max_acceptable_risk_score", 40
                )
                if assessment.safety_score < max_score:
                    # Score below threshold → DANGEROUS
                    logger.warning(
                        "DANGEROUS: %s scored %d/100 "
                        "(threshold: %d). Blacklisting.",
                        ssid, assessment.safety_score, max_score,
                    )

                    findings_str = "; ".join(
                        f.description
                        for f in assessment.findings[:3]
                    )
                    self._block_and_disconnect(
                        ssid, timestamp,
                        reason=(
                            f"Auto-blocked: scored "
                            f"{assessment.safety_score}/100 "
                            f"(min {max_score})"
                        ),
                        detail=(
                            f"Scored {assessment.safety_score}"
                            f"/100. {findings_str}"
                        ),
                        assessment=assessment,
                    )
                    return

                elif assessment.risk_level == "DANGEROUS":
                    # Engine said DANGEROUS even if above
                    # threshold (edge case)
                    logger.warning(
                        "DANGEROUS (engine): %s scored %d/100. "
                        "Blacklisting.",
                        ssid, assessment.safety_score,
                    )
                    findings_str = "; ".join(
                        f.description
                        for f in assessment.findings[:3]
                    )
                    self._block_and_disconnect(
                        ssid, timestamp,
                        reason=(
                            f"Auto-blocked: scored "
                            f"{assessment.safety_score}/100"
                        ),
                        detail=(
                            f"Scored {assessment.safety_score}"
                            f"/100. {findings_str}"
                        ),
                        assessment=assessment,
                    )
                    return

                elif assessment.risk_level == "MODERATE":
                    # ── Moderate → allow but warn ──
                    logger.info(
                        "MODERATE: %s scored %d/100. Allowing.",
                        ssid, assessment.safety_score,
                    )
                    self.logger.log_assessment(assessment.to_dict())

                    NotificationManager.connection_allowed(
                        ssid,
                        warning=(
                            f"Moderate risk "
                            f"({assessment.safety_score}/100). "
                            f"Consider using a VPN."
                        ),
                    )
                    return

                else:
                    # ── Safe → allow ──
                    self.logger.log_assessment(assessment.to_dict())

            # If we couldn't find the specific network in scan
            # results or it's safe, allow the connection
            NotificationManager.connection_allowed(ssid)

        except Exception as exc:
            logger.error("Scan failed for %s: %s", ssid, exc)
            # Don't block on scan errors — just notify
            NotificationManager.connection_allowed(
                ssid,
                warning="Could not complete security scan.",
            )

    # ─────────────────────────────────────────────────────────
    #  Block + disconnect helper
    # ─────────────────────────────────────────────────────────

    def _block_and_disconnect(self, ssid: str, timestamp: str,
                              reason: str, detail: str,
                              assessment=None):
        """
        Blacklist + OS-block + disconnect + log + notify.
        Centralizes the 'fail' path so every policy violation
        goes through the same enforcement.
        """
        from ui.notifications import NotificationManager

        # Add to blacklist (this also triggers OS-level block
        # via the enforcer attached to the BlacklistManager)
        self.blacklist.add(ssid, reason=reason)

        # Disconnect
        success = self._disconnect()

        # Log incident
        incident = {
            "timestamp": timestamp,
            "ssid": ssid,
            "action": "blocked_and_blacklisted",
            "reason": reason,
            "detail": detail,
            "disconnect_success": success,
        }
        self._incident_log.append(incident)
        self.logger.log_message(
            f"BLOCKED + BLACKLISTED: {ssid} — {reason}"
        )
        if assessment:
            self.logger.log_assessment(assessment.to_dict())

        # Toast notification
        NotificationManager.connection_blocked(ssid, detail)

    # ─────────────────────────────────────────────────────────
    #  Get default gateway IP for port scanning
    # ─────────────────────────────────────────────────────────

    def _get_default_gateway(self) -> Optional[str]:
        """
        Detect the default gateway IP of the current network.
        Used as the target for the automatic port scan.

        Returns:
            Gateway IP string (e.g. "192.168.1.1") or None.
        """
        try:
            cflags = (
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            )

            if self.os_type == "Windows":
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=cflags,
                )
                # Find "Default Gateway" line with an IP
                for line in result.stdout.split("\n"):
                    if "Default Gateway" in line:
                        match = re.search(
                            r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
                            line,
                        )
                        if match:
                            return match.group(1)

            elif self.os_type == "Linux":
                result = subprocess.run(
                    ["ip", "route", "show", "default"],
                    capture_output=True, text=True, timeout=10,
                )
                # "default via 192.168.1.1 dev wlan0 ..."
                match = re.search(
                    r"default via (\d{1,3}\.\d{1,3}\.\d{1,3}"
                    r"\.\d{1,3})",
                    result.stdout,
                )
                if match:
                    return match.group(1)

            elif self.os_type == "Darwin":
                result = subprocess.run(
                    ["route", "-n", "get", "default"],
                    capture_output=True, text=True, timeout=10,
                )
                for line in result.stdout.split("\n"):
                    if "gateway" in line.lower():
                        match = re.search(
                            r"(\d{1,3}\.\d{1,3}\.\d{1,3}"
                            r"\.\d{1,3})",
                            line,
                        )
                        if match:
                            return match.group(1)

        except Exception as exc:
            logger.debug("Could not detect gateway: %s", exc)

        return None

    # ─────────────────────────────────────────────────────────
    #  Get current connected SSID
    # ─────────────────────────────────────────────────────────

    def _get_connected_ssid(self) -> Optional[str]:
        """
        Get the SSID of the currently connected WiFi network.
        Returns None if not connected to WiFi.
        """
        try:
            if self.os_type == "Windows":
                return self._get_ssid_windows()
            elif self.os_type == "Linux":
                return self._get_ssid_linux()
            elif self.os_type == "Darwin":
                return self._get_ssid_macos()
        except Exception as exc:
            logger.debug("Could not get SSID: %s", exc)
        return None

    def _get_ssid_windows(self) -> Optional[str]:
        """Get connected SSID on Windows via netsh."""
        result = subprocess.run(
            ["netsh", "wlan", "show", "interfaces"],
            capture_output=True, text=True, timeout=10,
            creationflags=(
                subprocess.CREATE_NO_WINDOW
                if hasattr(subprocess, "CREATE_NO_WINDOW")
                else 0
            ),
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            # Match "    SSID                   : NetworkName"
            # but NOT "    BSSID"
            line_stripped = line.strip()
            if line_stripped.startswith("SSID") \
               and not line_stripped.startswith("BSSID"):
                parts = line_stripped.split(":", 1)
                if len(parts) == 2:
                    ssid = parts[1].strip()
                    if ssid:
                        return ssid
        return None

    def _get_ssid_linux(self) -> Optional[str]:
        """Get connected SSID on Linux via nmcli."""
        result = subprocess.run(
            ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            if line.startswith("yes:"):
                ssid = line.split(":", 1)[1].strip()
                if ssid:
                    return ssid
        return None

    def _get_ssid_macos(self) -> Optional[str]:
        """Get connected SSID on macOS."""
        result = subprocess.run(
            ["/System/Library/PrivateFrameworks/"
             "Apple80211.framework/Resources/airport", "-I"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return None

        for line in result.stdout.splitlines():
            line_stripped = line.strip()
            if line_stripped.startswith("SSID:"):
                ssid = line_stripped.split(":", 1)[1].strip()
                if ssid:
                    return ssid
        return None

    # ─────────────────────────────────────────────────────────
    #  Disconnect from WiFi
    # ─────────────────────────────────────────────────────────

    def _disconnect(self) -> bool:
        """Force disconnect from the current WiFi network."""
        try:
            if self.os_type == "Windows":
                result = subprocess.run(
                    ["netsh", "wlan", "disconnect"],
                    capture_output=True, text=True, timeout=10,
                    creationflags=(
                        subprocess.CREATE_NO_WINDOW
                        if hasattr(subprocess, "CREATE_NO_WINDOW")
                        else 0
                    ),
                )
            elif self.os_type == "Linux":
                result = subprocess.run(
                    ["nmcli", "device", "disconnect", "wlan0"],
                    capture_output=True, text=True, timeout=10,
                )
            elif self.os_type == "Darwin":
                result = subprocess.run(
                    ["networksetup", "-setairportpower",
                     "en0", "off"],
                    capture_output=True, text=True, timeout=10,
                )
            else:
                return False

            success = result.returncode == 0
            if success:
                logger.info("Disconnected from WiFi successfully.")
                # Clear current SSID so we detect reconnection
                self._current_ssid = None
            else:
                logger.error("Disconnect failed: %s",
                              result.stderr.strip())
            return success

        except Exception as exc:
            logger.error("Disconnect error: %s", exc)
            return False

    # ─────────────────────────────────────────────────────────
    #  Public API
    # ─────────────────────────────────────────────────────────

    def get_current_ssid(self) -> Optional[str]:
        """Get the currently connected SSID (public accessor)."""
        return self._current_ssid

    def get_incident_log(self) -> list:
        """Get the list of enforcement incidents."""
        return self._incident_log.copy()