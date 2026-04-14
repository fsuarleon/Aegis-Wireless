"""
blacklist.py — Network Blacklist Manager
==========================================
WHAT THIS DOES:
    Lets you maintain a list of WiFi networks you consider unsafe.
    - Add networks to the blacklist (with a reason and timestamp)
    - Remove networks if they become trustworthy
    - Check if a network is blacklisted before connecting

WHERE THE DATA IS STORED:
    config/blacklist.json (created automatically on first use)
    Everything stays local on your computer. Nothing goes online.
"""

# ---------- IMPORTS ----------

import json         # For reading/writing JSON files
import os           # For checking if files exist
from datetime import datetime   # For timestamps
from pathlib import Path        # For building file paths
from typing import List, Dict, Optional


# ---------- BLACKLIST MANAGER CLASS ----------

class BlacklistManager:
    """
    Manages a local blacklist of unsafe WiFi networks.
    All data stored in a JSON file — no cloud, no database.
    """

    def __init__(self, filepath: str = None):
        """
        Args:
            filepath: Path to the blacklist JSON file.
                     Defaults to config/blacklist.json
        """
        if filepath is None:
            filepath = str(
                Path(__file__).parent.parent
                / "config" / "blacklist.json"
            )

        self.filepath = filepath
        # Load existing blacklist from disk (or create empty one)
        self.data = self._load()

    # ── PUBLIC METHODS ──────────────────────────────────────────

    def add(self, ssid: str, reason: str = "",
            bssid: str = "") -> bool:
        """
        Add a network to the blacklist.

        Args:
            ssid:   The network name (e.g., "Free_Airport_WiFi")
            reason: Why you're blacklisting it
            bssid:  MAC address of the router (optional)

        Returns:
            True if added, False if it was already blacklisted.
        """
        # Check if already blacklisted
        for entry in self.data["entries"]:
            if entry["ssid"].lower() == ssid.lower():
                print(f"[!] '{ssid}' is already blacklisted.")
                return False

        # Create the new entry
        entry = {
            "ssid": ssid,
            "bssid": bssid,
            "reason": reason,
            "date_added": datetime.now().isoformat(),
            "flagged_count": 1,
        }

        # Add to both the entries list and the quick-lookup list
        self.data["entries"].append(entry)
        self.data["blacklisted_networks"].append(ssid)
        self.data["metadata"]["total_entries"] = len(
            self.data["entries"]
        )
        self.data["metadata"]["last_updated"] = (
            datetime.now().isoformat()
        )
        # Save to disk immediately
        self._save()

        print(f"[+] '{ssid}' added to blacklist.")
        return True

    def remove(self, ssid: str) -> bool:
        """
        Remove a network from the blacklist.

        Returns:
            True if removed, False if it wasn't found.
        """
        original_count = len(self.data["entries"])

        # Filter out the matching entry
        self.data["entries"] = [
            e for e in self.data["entries"]
            if e["ssid"].lower() != ssid.lower()
        ]

        if len(self.data["entries"]) == original_count:
            print(f"[!] '{ssid}' was not found in the blacklist.")
            return False

        # Also remove from the quick-lookup list
        self.data["blacklisted_networks"] = [
            n for n in self.data["blacklisted_networks"]
            if n.lower() != ssid.lower()
        ]
        self.data["metadata"]["total_entries"] = len(
            self.data["entries"]
        )
        self.data["metadata"]["last_updated"] = (
            datetime.now().isoformat()
        )
        self._save()

        print(f"[-] '{ssid}' removed from blacklist.")
        return True

    def is_blacklisted(self, ssid: str) -> bool:
        """Check if a network name is on the blacklist."""
        return ssid.lower() in [
            n.lower() for n in self.data["blacklisted_networks"]
        ]

    def get_all(self) -> List[Dict]:
        """Return all blacklist entries."""
        return self.data["entries"]

    def get_network_names(self) -> List[str]:
        """Return just the list of blacklisted network names."""
        return self.data["blacklisted_networks"]

    def clear(self) -> int:
        """
        Remove ALL entries from the blacklist.
        Returns the number of entries that were removed.
        """
        count = len(self.data["entries"])
        self.data["entries"] = []
        self.data["blacklisted_networks"] = []
        self.data["metadata"]["total_entries"] = 0
        self.data["metadata"]["last_updated"] = (
            datetime.now().isoformat()
        )
        self._save()
        print(f"[*] Blacklist cleared. {count} entries removed.")
        return count

    def count(self) -> int:
        """How many networks are blacklisted."""
        return len(self.data["entries"])

    # ── DISPLAY ─────────────────────────────────────────────────

    def print_all(self):
        """Pretty-print the entire blacklist."""
        entries = self.data["entries"]
        if not entries:
            print("[*] Blacklist is empty.")
            return

        print(f"\n{'=' * 60}")
        print(f"  BLACKLISTED NETWORKS ({len(entries)})")
        print(f"{'=' * 60}")

        for i, entry in enumerate(entries, 1):
            # Format the date to just show YYYY-MM-DD
            date_str = entry.get("date_added", "Unknown date")
            if "T" in date_str:
                date_str = date_str.split("T")[0]
            print(f"\n  {i}. {entry['ssid']}")
            if entry.get("bssid"):
                print(f"     BSSID:  {entry['bssid']}")
            print(f"     Reason: "
                  f"{entry.get('reason', 'No reason given')}")
            print(f"     Added:  {date_str}")

        print(f"\n{'=' * 60}\n")

    # ── INTERNAL METHODS ────────────────────────────────────────

    def _load(self) -> Dict:
        """Load the blacklist from disk, or create a fresh one."""
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath) as f:
                    data = json.load(f)
                # Make sure required keys exist
                data.setdefault("blacklisted_networks", [])
                data.setdefault("entries", [])
                data.setdefault("metadata", {})
                return data
            except (json.JSONDecodeError, KeyError):
                print("[!] Blacklist file corrupted. "
                      "Starting fresh.")

        # Create default empty structure
        return {
            "blacklisted_networks": [],
            "entries": [],
            "metadata": {
                "created": datetime.now().isoformat(),
                "last_updated": datetime.now().isoformat(),
                "total_entries": 0,
            }
        }

    def _save(self):
        """Write the blacklist to disk."""
        # Create the directory if it doesn't exist
        os.makedirs(
            os.path.dirname(self.filepath), exist_ok=True
        )
        with open(self.filepath, "w") as f:
            json.dump(self.data, f, indent=2)