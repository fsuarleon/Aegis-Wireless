"""
telemetry.py — Local Logging & Telemetry
==========================================
WHAT THIS DOES:
    Saves all scan results, risk assessments, and enforcement
    actions to local log files on YOUR computer. Nothing goes
    to the cloud.

    Creates two types of logs:
    1. Human-readable text logs  (logs/aegis_YYYY-MM-DD.log)
    2. Machine-readable JSON logs (logs/aegis_YYYY-MM-DD.json)

PRIVACY:
    - All data stays in the /logs folder on your machine
    - No network requests are made
    - Old logs can be deleted at any time
"""

# ---------- IMPORTS ----------

import json           # For writing JSON logs
import logging        # Python's built-in logging system
import os             # For file/folder operations
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional


# ---------- AEGIS LOGGER CLASS ----------

class AegisLogger:
    """
    Handles all local logging for the Aegis Wireless tool.
    Writes both human-readable and JSON-structured logs.
    """

    def __init__(self, log_dir: str = None):
        """
        Args:
            log_dir: Directory to store log files.
                    Defaults to 'logs/' in the project folder.
        """
        if log_dir is None:
            log_dir = str(
                Path(__file__).parent.parent / "logs"
            )

        self.log_dir = log_dir
        # Create the logs folder if it doesn't exist
        os.makedirs(self.log_dir, exist_ok=True)

        # Today's date for filenames
        self.today = datetime.now().strftime("%Y-%m-%d")

        # Set up Python's built-in logging for text logs
        self.logger = self._setup_text_logger()

        # JSON log data (saved at end of session)
        self.session_data: Dict = {
            "session_start": datetime.now().isoformat(),
            "session_end": None,
            "wifi_scans": [],
            "port_scans": [],
            "assessments": [],
            "enforcement_actions": [],
            "blacklist_changes": [],
        }

    # ── PUBLIC METHODS ──────────────────────────────────────────

    def log_wifi_scan(self, networks: List[Dict]):
        """Log the results of a WiFi scan."""
        self.logger.info(
            f"WiFi scan found {len(networks)} network(s)"
        )
        for net in networks:
            enc_warn = (" !! OPEN"
                        if net.get("encryption") == "Open"
                        else "")
            self.logger.info(
                f"  Network: {net.get('ssid', '?'):<25} "
                f"Signal: {net.get('signal_strength', 0):>3}%  "
                f"Encryption: "
                f"{net.get('encryption', '?')}{enc_warn}"
            )

        self.session_data["wifi_scans"].append({
            "timestamp": datetime.now().isoformat(),
            "network_count": len(networks),
            "networks": networks,
        })

    def log_port_scan(self, report_dict: Dict):
        """Log the results of a port scan."""
        target = report_dict.get("target", "?")
        open_count = report_dict.get("open_port_count", 0)
        total = report_dict.get("total_scanned", 0)

        self.logger.info(
            f"Port scan on {target}: {open_count} open "
            f"out of {total} scanned"
        )
        for port in report_dict.get("open_ports", []):
            self.logger.info(
                f"  Port {port.get('port', '?'):>5} — "
                f"{port.get('service', 'Unknown')} "
                f"({port.get('state', '?')})"
            )

        self.session_data["port_scans"].append({
            "timestamp": datetime.now().isoformat(),
            **report_dict,
        })

    def log_assessment(self, assessment_dict: Dict):
        """Log a risk assessment."""
        ssid = assessment_dict.get("ssid", "?")
        score = assessment_dict.get("safety_score", "?")
        level = assessment_dict.get("risk_level", "?")

        level_label = {
            "SAFE": "OK",
            "MODERATE": "WARN",
            "DANGEROUS": "ALERT"
        }.get(level, "?")

        self.logger.info(
            f"Assessment: {ssid} — {level_label} {level} "
            f"(Score: {score}/100)"
        )

        for finding in assessment_dict.get("findings", []):
            self.logger.info(
                f"  [{finding.get('severity', '?').upper()}] "
                f"{finding.get('description', '')}"
            )

        self.session_data["assessments"].append({
            "timestamp": datetime.now().isoformat(),
            **assessment_dict,
        })

    def log_enforcement(self, action: str, ssid: str,
                        details: str = ""):
        """Log an enforcement action."""
        self.logger.info(
            f"Enforcement: {action.upper()} on "
            f"'{ssid}' — {details}"
        )

        self.session_data["enforcement_actions"].append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "ssid": ssid,
            "details": details,
        })

    def log_blacklist_change(self, action: str, ssid: str,
                             reason: str = ""):
        """Log a blacklist addition or removal."""
        self.logger.info(
            f"Blacklist: {action} '{ssid}' — {reason}"
        )

        self.session_data["blacklist_changes"].append({
            "timestamp": datetime.now().isoformat(),
            "action": action,
            "ssid": ssid,
            "reason": reason,
        })

    def log_message(self, message: str, level: str = "info"):
        """Log a general message."""
        log_func = getattr(
            self.logger, level.lower(), self.logger.info
        )
        log_func(message)

    # ── SESSION MANAGEMENT ──────────────────────────────────────

    def save_session(self):
        """
        Write the JSON session log to disk.
        Call this when the program exits.
        """
        self.session_data["session_end"] = (
            datetime.now().isoformat()
        )

        json_path = os.path.join(
            self.log_dir, f"aegis_{self.today}.json"
        )

        # If a JSON log already exists for today, append
        existing_sessions = []
        if os.path.exists(json_path):
            try:
                with open(json_path) as f:
                    existing = json.load(f)
                if isinstance(existing, list):
                    existing_sessions = existing
                else:
                    existing_sessions = [existing]
            except (json.JSONDecodeError, IOError):
                pass

        existing_sessions.append(self.session_data)

        with open(json_path, "w") as f:
            json.dump(existing_sessions, f, indent=2)

        self.logger.info(f"Session log saved to {json_path}")

    # ── LOG MANAGEMENT ──────────────────────────────────────────

    def list_logs(self) -> List[str]:
        """List all log files in the log directory."""
        files = []
        for f in sorted(os.listdir(self.log_dir)):
            if f.startswith("aegis_"):
                full_path = os.path.join(self.log_dir, f)
                size_kb = os.path.getsize(full_path) / 1024
                files.append(f"{f} ({size_kb:.1f} KB)")
        return files

    def clear_logs(self):
        """Delete all log files. Use with caution."""
        count = 0
        for f in os.listdir(self.log_dir):
            if f.startswith("aegis_"):
                os.remove(os.path.join(self.log_dir, f))
                count += 1
        self.logger.info(f"Cleared {count} log file(s).")
        return count

    def read_json_log(self, date: str = None
                      ) -> Optional[List[Dict]]:
        """
        Read a JSON log file for a specific date.
        Args:
            date: Date string like "2025-01-15".
                 Defaults to today.
        """
        if date is None:
            date = self.today

        json_path = os.path.join(
            self.log_dir, f"aegis_{date}.json"
        )
        if not os.path.exists(json_path):
            print(f"[!] No log found for {date}")
            return None

        with open(json_path) as f:
            return json.load(f)

    # ── INTERNAL ────────────────────────────────────────────────

    def _setup_text_logger(self) -> logging.Logger:
        """Configure Python's logging for text log files."""
        logger = logging.getLogger("aegis_wireless")
        logger.setLevel(logging.DEBUG)

        # Avoid duplicate handlers if called multiple times
        if logger.handlers:
            return logger

        # File handler — writes to logs/aegis_YYYY-MM-DD.log
        log_file = os.path.join(
            self.log_dir, f"aegis_{self.today}.log"
        )
        fh = logging.FileHandler(log_file, encoding="utf-8")
        fh.setLevel(logging.DEBUG)

        # Console handler — also print to terminal
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)

        # Format: timestamp | level | message
        formatter = logging.Formatter(
            "%(asctime)s | %(levelname)-8s | %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S"
        )
        fh.setFormatter(formatter)
        ch.setFormatter(formatter)

        logger.addHandler(fh)
        logger.addHandler(ch)

        return logger