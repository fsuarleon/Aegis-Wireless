"""
frame_inspector.py — 802.11 Frame Inspector
=============================================
WHAT THIS DOES:
    Captures and analyzes raw 802.11 beacon and probe-response
    frames using Scapy.  This provides ground-truth validation
    of encryption and AP identity that cannot be obtained from
    high-level OS commands (netsh / nmcli).

    Specifically it extracts:
    - RSN (Robust Security Network) Information Element
      → cipher suites   (CCMP, TKIP, WEP-40/104, …)
      → AKM suites      (PSK, 802.1X/EAP, SAE for WPA3, …)
    - WPA Vendor-Specific IE (Microsoft OUI 00:50:F2)
      → same cipher / AKM parsing for legacy WPA networks
    - AP capabilities and BSSID for cross-validation

    The results are used to VALIDATE what the OS-level scanner
    reports.  If the OS says "WPA2" but the beacon only
    advertises TKIP (no CCMP), Aegis flags a mismatch.

WHY THIS MATTERS:
    OS utilities summarise encryption with a single label.
    Frame-level inspection reveals the actual cipher negotiation
    so we can detect:
    - Downgrade attacks  (WPA2 label but TKIP-only cipher)
    - Misconfigured APs  (mixed-mode with weak ciphers)
    - Evil-twin clones   (BSSID mismatch for same SSID)

DEPENDENCIES:
    pip install scapy

PLATFORM NOTE:
    - Windows: requires Npcap in "802.11 monitor mode" or
      a compatible USB adapter.  Falls back gracefully if
      monitor mode is unavailable.
    - Linux: requires root/sudo and a monitor-capable NIC.
    - macOS: uses CoreWLAN; partial support.

    When capture is unavailable the module returns empty
    results and wifi_scan.py falls back to OS-only data.
"""

# ---------- IMPORTS ----------

import logging
import threading
from dataclasses import dataclass, field, asdict
from typing import List, Dict, Optional, Set

logger = logging.getLogger("aegis.frame_inspector")

# Scapy is optional — we degrade gracefully
try:
    from scapy.all import (
        sniff, Dot11, Dot11Beacon, Dot11ProbeResp,
        Dot11Elt, RadioTap, conf,
    )
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False
    logger.info(
        "Scapy not installed — 802.11 frame inspection disabled. "
        "Install with: pip install scapy"
    )


# ---------- OUI / CIPHER CONSTANTS ----------

# AKM Suite type OUI+type → human label
# IEEE 802.11-2020, Table 9-151
_AKM_SUITES = {
    b"\x00\x0f\xac\x01": "802.1X",          # EAP / Enterprise
    b"\x00\x0f\xac\x02": "PSK",             # Pre-Shared Key
    b"\x00\x0f\xac\x03": "FT-802.1X",
    b"\x00\x0f\xac\x04": "FT-PSK",
    b"\x00\x0f\xac\x05": "802.1X-SHA256",
    b"\x00\x0f\xac\x06": "PSK-SHA256",
    b"\x00\x0f\xac\x08": "SAE",             # WPA3-Personal
    b"\x00\x0f\xac\x09": "FT-SAE",
    b"\x00\x0f\xac\x0c": "SUITE-B-192",     # WPA3-Enterprise 192-bit
    # Microsoft WPA vendor OUI
    b"\x00\x50\xf2\x01": "802.1X (WPA)",
    b"\x00\x50\xf2\x02": "PSK (WPA)",
}

# Cipher Suite type OUI+type → human label
# IEEE 802.11-2020, Table 9-149
_CIPHER_SUITES = {
    b"\x00\x0f\xac\x00": "Use-Group",
    b"\x00\x0f\xac\x01": "WEP-40",
    b"\x00\x0f\xac\x02": "TKIP",
    b"\x00\x0f\xac\x04": "CCMP-128",        # AES
    b"\x00\x0f\xac\x05": "WEP-104",
    b"\x00\x0f\xac\x06": "BIP-CMAC-128",
    b"\x00\x0f\xac\x08": "GCMP-128",
    b"\x00\x0f\xac\x09": "GCMP-256",        # WPA3
    b"\x00\x0f\xac\x0a": "CCMP-256",
    # Microsoft WPA vendor OUI
    b"\x00\x50\xf2\x00": "Use-Group (WPA)",
    b"\x00\x50\xf2\x01": "WEP-40 (WPA)",
    b"\x00\x50\xf2\x02": "TKIP (WPA)",
    b"\x00\x50\xf2\x04": "CCMP (WPA)",
}

# RSN Information Element ID
_RSN_ELT_ID = 48

# WPA Vendor-Specific IE: OUI 00:50:F2, type 1
_WPA_OUI = b"\x00\x50\xf2\x01"


# ---------- DATA CONTAINERS ----------

@dataclass
class FrameSecurityInfo:
    """
    Encryption details extracted from a single 802.11 beacon
    or probe-response frame.
    """
    bssid: str = ""
    ssid: str = ""
    channel: int = 0

    # RSN (WPA2/WPA3) fields
    rsn_found: bool = False
    rsn_pairwise_ciphers: List[str] = field(default_factory=list)
    rsn_akm_suites: List[str] = field(default_factory=list)
    rsn_group_cipher: str = ""

    # Legacy WPA fields
    wpa_found: bool = False
    wpa_pairwise_ciphers: List[str] = field(default_factory=list)
    wpa_akm_suites: List[str] = field(default_factory=list)
    wpa_group_cipher: str = ""

    # Derived
    encryption_label: str = "Open"           # Best-effort label
    supports_pmf: bool = False               # 802.11w MFP

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class FrameValidationResult:
    """
    Comparison between OS-reported encryption and frame-level
    encryption for one BSSID.
    """
    bssid: str
    ssid: str
    os_encryption: str            # What netsh / nmcli said
    frame_encryption: str         # What the beacon says
    match: bool = True            # Do they agree?
    downgrade_risk: bool = False  # TKIP-only on a "WPA2" network?
    detail: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- FRAME INSPECTOR CLASS ----------

class FrameInspector:
    """
    Captures 802.11 management frames and parses their security
    Information Elements.

    Usage:
        inspector = FrameInspector()
        results = inspector.inspect(timeout=4)
        # results: Dict[bssid_str, FrameSecurityInfo]
    """

    def __init__(self, iface: Optional[str] = None):
        """
        Args:
            iface: Network interface to capture on.
                   None = let Scapy pick the default.
        """
        self.iface = iface
        self._results: Dict[str, FrameSecurityInfo] = {}
        self._available = SCAPY_AVAILABLE

    @property
    def available(self) -> bool:
        """True if Scapy is installed and ready."""
        return self._available

    # ── PUBLIC METHODS ──────────────────────────────────────────

    def inspect(self, timeout: int = 4
                ) -> Dict[str, FrameSecurityInfo]:
        """
        Sniff 802.11 beacon / probe-response frames for `timeout`
        seconds and parse their security IEs.

        Returns:
            Dict mapping BSSID strings to FrameSecurityInfo.
            Empty dict if Scapy is unavailable or capture fails.
        """
        if not self._available:
            return {}

        self._results = {}

        try:
            sniff_kwargs = {
                "prn": self._handle_frame,
                "timeout": timeout,
                "store": False,
            }
            if self.iface:
                sniff_kwargs["iface"] = self.iface

            # Use monitor filter if supported
            try:
                sniff_kwargs["lfilter"] = (
                    lambda pkt: pkt.haslayer(Dot11Beacon)
                    or pkt.haslayer(Dot11ProbeResp)
                )
            except Exception:
                pass

            sniff(**sniff_kwargs)
            logger.info(
                "Frame inspection captured %d unique BSSID(s).",
                len(self._results),
            )

        except PermissionError:
            logger.warning(
                "Frame inspection requires elevated privileges "
                "(admin / root). Skipping."
            )
        except OSError as exc:
            logger.warning(
                "Frame inspection unavailable on this adapter: %s",
                exc,
            )
        except Exception as exc:
            logger.warning(
                "Frame inspection error: %s", exc,
            )

        return dict(self._results)

    def inspect_async(self, timeout: int = 4,
                      callback=None):
        """
        Run inspection in a background thread.

        Args:
            timeout:  Capture duration in seconds.
            callback: Called with the results dict when done.
        """
        def _worker():
            results = self.inspect(timeout=timeout)
            if callback:
                callback(results)

        t = threading.Thread(
            target=_worker, daemon=True, name="FrameInspect",
        )
        t.start()
        return t

    def validate(self, os_networks: list,
                 frame_data: Dict[str, FrameSecurityInfo] = None
                 ) -> List[FrameValidationResult]:
        """
        Cross-reference OS-reported networks against frame-level
        data to detect mismatches or downgrade risks.

        Args:
            os_networks:  List of WiFiNetwork objects from wifi_scan
            frame_data:   Frame inspection results (or use last run)

        Returns:
            List of FrameValidationResult for each matched BSSID.
        """
        if frame_data is None:
            frame_data = self._results

        results = []
        for net in os_networks:
            bssid = net.bssid.upper().strip()
            if bssid and bssid in frame_data:
                info = frame_data[bssid]
                match, downgrade, detail = self._compare(
                    net.encryption, info
                )
                results.append(FrameValidationResult(
                    bssid=bssid,
                    ssid=net.ssid,
                    os_encryption=net.encryption,
                    frame_encryption=info.encryption_label,
                    match=match,
                    downgrade_risk=downgrade,
                    detail=detail,
                ))
        return results

    # ── FRAME HANDLER ──────────────────────────────────────────

    def _handle_frame(self, pkt):
        """Scapy callback for each captured packet."""
        if not pkt.haslayer(Dot11):
            return

        # Only care about Beacon and Probe Response
        is_beacon = pkt.haslayer(Dot11Beacon)
        is_probe = pkt.haslayer(Dot11ProbeResp)
        if not (is_beacon or is_probe):
            return

        try:
            bssid = pkt[Dot11].addr3
            if not bssid:
                return
            bssid = bssid.upper()

            info = FrameSecurityInfo(bssid=bssid)

            # Extract SSID from the first Dot11Elt (ID=0)
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 0:  # SSID
                    try:
                        info.ssid = elt.info.decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        info.ssid = "<Hidden Network>"
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            # Extract channel from DS Parameter Set (IE 3)
            elt = pkt[Dot11Elt]
            while elt:
                if elt.ID == 3 and elt.info:
                    info.channel = elt.info[0]
                    break
                elt = elt.payload.getlayer(Dot11Elt)

            # Parse RSN IE (ID 48)
            self._parse_rsn(pkt, info)

            # Parse WPA Vendor IE
            self._parse_wpa_vendor(pkt, info)

            # Derive a human-readable encryption label
            info.encryption_label = self._derive_label(info)

            self._results[bssid] = info

        except Exception as exc:
            logger.debug("Error parsing frame: %s", exc)

    # ── RSN IE PARSER ──────────────────────────────────────────

    def _parse_rsn(self, pkt, info: FrameSecurityInfo):
        """
        Parse the RSN Information Element (ID 48) from beacon.
        Structure (IEEE 802.11-2020 §9.4.2.25):
          - Version (2 bytes)
          - Group Data Cipher Suite (4 bytes)
          - Pairwise Cipher Suite Count (2 bytes)
          - Pairwise Cipher Suite List (4 * count bytes)
          - AKM Suite Count (2 bytes)
          - AKM Suite List (4 * count bytes)
          - RSN Capabilities (2 bytes, optional)
        """
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == _RSN_ELT_ID and elt.info:
                info.rsn_found = True
                raw = bytes(elt.info)
                offset = 0

                # Version (2 bytes) — must be 1
                if len(raw) < 2:
                    break
                offset += 2

                # Group cipher (4 bytes)
                if len(raw) >= offset + 4:
                    info.rsn_group_cipher = _CIPHER_SUITES.get(
                        raw[offset:offset + 4], "Unknown"
                    )
                    offset += 4

                # Pairwise cipher count + list
                if len(raw) >= offset + 2:
                    count = int.from_bytes(
                        raw[offset:offset + 2], "little"
                    )
                    offset += 2
                    for _ in range(count):
                        if len(raw) >= offset + 4:
                            cipher = _CIPHER_SUITES.get(
                                raw[offset:offset + 4], "Unknown"
                            )
                            info.rsn_pairwise_ciphers.append(cipher)
                            offset += 4

                # AKM suite count + list
                if len(raw) >= offset + 2:
                    count = int.from_bytes(
                        raw[offset:offset + 2], "little"
                    )
                    offset += 2
                    for _ in range(count):
                        if len(raw) >= offset + 4:
                            akm = _AKM_SUITES.get(
                                raw[offset:offset + 4], "Unknown"
                            )
                            info.rsn_akm_suites.append(akm)
                            offset += 4

                # RSN Capabilities (2 bytes)
                if len(raw) >= offset + 2:
                    caps = int.from_bytes(
                        raw[offset:offset + 2], "little"
                    )
                    # Bit 6 = MFPR (Management Frame Protection
                    #          Required)
                    # Bit 7 = MFPC (MFP Capable)
                    info.supports_pmf = bool(caps & 0x0080)

                break
            elt = elt.payload.getlayer(Dot11Elt)

    # ── WPA VENDOR IE PARSER ───────────────────────────────────

    def _parse_wpa_vendor(self, pkt, info: FrameSecurityInfo):
        """
        Parse the WPA vendor-specific IE (ID 221, OUI 00:50:F2:01).
        Same structure as RSN but uses Microsoft OUI.
        """
        elt = pkt[Dot11Elt]
        while elt:
            if elt.ID == 221 and elt.info:
                raw = bytes(elt.info)
                if raw[:4] == _WPA_OUI:
                    info.wpa_found = True
                    offset = 4

                    # Version (2 bytes)
                    if len(raw) < offset + 2:
                        break
                    offset += 2

                    # Group cipher (4 bytes)
                    if len(raw) >= offset + 4:
                        info.wpa_group_cipher = _CIPHER_SUITES.get(
                            raw[offset:offset + 4], "Unknown"
                        )
                        offset += 4

                    # Pairwise ciphers
                    if len(raw) >= offset + 2:
                        count = int.from_bytes(
                            raw[offset:offset + 2], "little"
                        )
                        offset += 2
                        for _ in range(count):
                            if len(raw) >= offset + 4:
                                cipher = _CIPHER_SUITES.get(
                                    raw[offset:offset + 4],
                                    "Unknown",
                                )
                                info.wpa_pairwise_ciphers.append(
                                    cipher
                                )
                                offset += 4

                    # AKM suites
                    if len(raw) >= offset + 2:
                        count = int.from_bytes(
                            raw[offset:offset + 2], "little"
                        )
                        offset += 2
                        for _ in range(count):
                            if len(raw) >= offset + 4:
                                akm = _AKM_SUITES.get(
                                    raw[offset:offset + 4],
                                    "Unknown",
                                )
                                info.wpa_akm_suites.append(akm)
                                offset += 4
                    break
            elt = elt.payload.getlayer(Dot11Elt)

    # ── LABEL DERIVATION ───────────────────────────────────────

    @staticmethod
    def _derive_label(info: FrameSecurityInfo) -> str:
        """
        Produce a human-readable encryption label from parsed IEs.

        Priority:
            SAE in AKM           → WPA3
            SAE + PSK mixed      → WPA3/WPA2
            RSN with CCMP + PSK  → WPA2
            RSN with EAP/802.1X  → WPA2-Enterprise
            WPA IE only + TKIP   → WPA
            Neither RSN nor WPA  → Open
        """
        all_akm = info.rsn_akm_suites + info.wpa_akm_suites

        if info.rsn_found:
            has_sae = any("SAE" in a for a in info.rsn_akm_suites)
            has_psk = any("PSK" in a for a in info.rsn_akm_suites)
            has_eap = any(
                "802.1X" in a or "SUITE-B" in a
                for a in info.rsn_akm_suites
            )

            if has_sae and has_eap:
                return "WPA3-Enterprise"
            if has_sae and has_psk:
                return "WPA3/WPA2"       # Transition mode
            if has_sae:
                return "WPA3"
            if has_eap:
                return "WPA2-Enterprise"
            if has_psk or info.rsn_pairwise_ciphers:
                return "WPA2"

        if info.wpa_found:
            has_eap = any(
                "802.1X" in a for a in info.wpa_akm_suites
            )
            return "WPA-Enterprise" if has_eap else "WPA"

        return "Open"

    # ── VALIDATION COMPARISON ──────────────────────────────────

    @staticmethod
    def _compare(os_enc: str, info: FrameSecurityInfo):
        """
        Compare OS-reported encryption with frame data.

        Returns:
            (match: bool, downgrade_risk: bool, detail: str)
        """
        frame_enc = info.encryption_label

        # Normalize for comparison
        os_norm = os_enc.upper().replace("-", "")
        fr_norm = frame_enc.upper().replace("-", "").replace("/", "")

        # Check for downgrade: OS says WPA2 but only TKIP ciphers
        downgrade = False
        if "WPA2" in os_norm and info.rsn_found:
            pairwise = info.rsn_pairwise_ciphers
            if pairwise and all(
                "TKIP" in c for c in pairwise
            ):
                downgrade = True

        # Simple match check
        match = (
            os_norm.startswith(fr_norm[:4])
            or fr_norm.startswith(os_norm[:4])
        )

        # Build detail string
        details = []
        if info.rsn_pairwise_ciphers:
            details.append(
                f"Pairwise: {', '.join(info.rsn_pairwise_ciphers)}"
            )
        if info.rsn_akm_suites:
            details.append(
                f"AKM: {', '.join(info.rsn_akm_suites)}"
            )
        if info.supports_pmf:
            details.append("PMF: capable")
        if downgrade:
            details.append(
                "DOWNGRADE RISK: WPA2 label but TKIP-only cipher"
            )
        if not match:
            details.append(
                f"MISMATCH: OS reports '{os_enc}' but beacon "
                f"indicates '{frame_enc}'"
            )

        return match, downgrade, "; ".join(details)


# ---------- QUICK TEST ----------

if __name__ == "__main__":
    if not SCAPY_AVAILABLE:
        print("[!] Scapy is not installed.")
        print("    pip install scapy")
        raise SystemExit(1)

    print("[*] Starting 802.11 frame inspection (5 seconds)...")
    inspector = FrameInspector()
    results = inspector.inspect(timeout=5)

    if not results:
        print("[!] No beacons captured.")
        print("    This usually means:")
        print("    - Your WiFi adapter does not support monitor mode")
        print("    - You need to run as administrator / root")
        print("    - Npcap (Windows) is not installed or not in "
              "monitor mode")
    else:
        print(f"\n[+] Captured {len(results)} unique AP(s):\n")
        for bssid, info in sorted(
            results.items(),
            key=lambda kv: kv[1].ssid,
        ):
            print(f"  BSSID: {bssid}")
            print(f"  SSID:  {info.ssid}")
            print(f"  Label: {info.encryption_label}")
            if info.rsn_pairwise_ciphers:
                print(f"  RSN Ciphers: "
                      f"{', '.join(info.rsn_pairwise_ciphers)}")
            if info.rsn_akm_suites:
                print(f"  RSN AKM:     "
                      f"{', '.join(info.rsn_akm_suites)}")
            if info.wpa_pairwise_ciphers:
                print(f"  WPA Ciphers: "
                      f"{', '.join(info.wpa_pairwise_ciphers)}")
            if info.supports_pmf:
                print(f"  PMF:         Capable")
            print()
