"""
blacklist.py — Network Blacklist Manager
==========================================
WHAT THIS DOES:
    Lets you maintain a list of WiFi networks you consider unsafe.
    - Add networks to the blacklist (with a reason and timestamp)
    - Remove networks if they become trustworthy
    - Check if a network is blacklisted before connecting
    - Automatically block/unblock networks at the OS level
      so the device itself refuses to connect

WHERE THE DATA IS STORED:
    config/blacklist.json (created automatically on first use)
    Everything stays local on your computer. Nothing goes online.

DATA INTEGRITY:
    The JSON file has two related structures:
      - "entries":              full detail list (ssid, reason, date)
      - "blacklisted_networks": quick-lookup list of SSID strings

    On every load, blacklisted_networks is REBUILT from entries
    so they can never fall out of sync.

OS-LEVEL ENFORCEMENT:
    When a network is added to the blacklist, the OS is told
    to block it (Windows: netsh filter, Linux: nmcli delete,
    macOS: remove from preferred). When removed, the OS block
    is lifted.
"""

# ---------- IMPORTS ----------

import json         # For reading/writing JSON files
import os           # For checking if files exist
import logging
from datetime import datetime   # For timestamps
from pathlib import Path        # For building file paths
from typing import List, Dict, Optional


logger = logging.getLogger("aegis.blacklist")


# ---------- BLACKLIST MANAGER CLASS ----------

class BlacklistManager:
    """
    Manages a local blacklist of unsafe WiFi networks.
    All data stored in a JSON file — no cloud, no database.
    Optionally enforces blocks at the OS level via a
    NetworkEnforcer instance.
    """

    def __init__(self, filepath: str = None, enforcer=None):
        """
        Args:
            filepath: Path to the blacklist JSON file.
                     Defaults to config/blacklist.json
            enforcer: A NetworkEnforcer instance. When provided,
                     add() and remove() will also block/unblock
                     the network at the OS level.
        """
        if filepath is None:
            filepath = str(
                Path(__file__).parent.parent
                / "config" / "blacklist.json"
            )

        self.filepath = filepath
        self.enforcer = enforcer
        # Load existing blacklist from disk (or create empty one)
        self.data = self._load()

    # ── PUBLIC METHODS ──────────────────────────────────────────

    def set_enforcer(self, enforcer):
        """
        Attach a NetworkEnforcer after construction.
        Useful when the enforcer is created separately.
        """
        self.enforcer = enforcer

    def add(self, ssid: str, reason: str = "",
            bssid: str = "") -> bool:
        """
        Add a network to the blacklist.

        Also blocks the network at the OS level if an enforcer
        is attached, preventing the device from reconnecting.

        Args:
            ssid:   The network name (e.g., "Free_Airport_WiFi")
            reason: Why you're blacklisting it
            bssid:  MAC address of the router (optional)

        Returns:
            True if added, False if it was already blacklisted.
        """
        # Check if already blacklisted (check entries, not the
        # quick-lookup list, to be thorough)
        for entry in self.data["entries"]:
            if entry["ssid"].lower() == ssid.lower():
                # Already blacklisted — still ensure OS block
                # and ensure it's in the quick-lookup list
                if ssid not in self.data["blacklisted_networks"]:
                    self.data["blacklisted_networks"].append(ssid)
                    self._save()
                if self.enforcer:
                    self.enforcer.block_network(ssid)
                logger.debug("'%s' is already blacklisted.", ssid)
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

        # ── OS-level block ──
        if self.enforcer:
            self.enforcer.block_network(ssid)
            logger.info(
                "Blacklisted + OS-blocked: '%s' (%s)", ssid, reason,
            )
        else:
            logger.info("Blacklisted: '%s' (%s)", ssid, reason)

        print(f"[+] '{ssid}' added to blacklist.")
        return True

    def remove(self, ssid: str) -> bool:
        """
        Remove a network from the blacklist.
        Also lifts the OS-level block if an enforcer is attached.

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

        # ── Remove OS-level block ──
        if self.enforcer:
            self.enforcer.unblock_network(ssid)
            logger.info(
                "Un-blacklisted + OS-unblocked: '%s'", ssid,
            )
        else:
            logger.info("Un-blacklisted: '%s'", ssid)

        print(f"[-] '{ssid}' removed from blacklist.")
        return True

    def is_blacklisted(self, ssid: str) -> bool:
        """
        Check if a network name is on the blacklist.
        Checks both the quick-lookup list AND the entries
        as a safety net against data inconsistency.
        """
        ssid_lower = ssid.lower()

        # Primary check: quick-lookup list
        if ssid_lower in [
            n.lower() for n in self.data["blacklisted_networks"]
        ]:
            return True

        # Fallback check: entries list (catches desync)
        for entry in self.data["entries"]:
            if entry["ssid"].lower() == ssid_lower:
                # Repair the quick-lookup list while we're here
                self.data["blacklisted_networks"].append(
                    entry["ssid"]
                )
                self._save()
                logger.warning(
                    "Repaired: '%s' was in entries but missing "
                    "from blacklisted_networks.", ssid,
                )
                return True

        return False

    def get_all(self) -> List[Dict]:
        """Return all blacklist entries."""
        return self.data["entries"]

    def get_network_names(self) -> List[str]:
        """Return just the list of blacklisted network names."""
        return self.data["blacklisted_networks"]

    def clear(self) -> int:
        """
        Remove ALL entries from the blacklist.
        Also lifts all OS-level blocks.
        Returns the number of entries that were removed.
        """
        # Lift OS blocks first
        if self.enforcer:
            for ssid in self.data["blacklisted_networks"]:
                self.enforcer.unblock_network(ssid)

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

    def sync_os_blocks(self):
        """
        Ensure every entry in the blacklist file is also
        blocked at the OS level. Call this on app startup.
        """
        if not self.enforcer:
            return
        names = self.get_network_names()
        if names:
            blocked = self.enforcer.sync_os_blocks(names)
            logger.info(
                "Startup sync: %d/%d blacklisted networks "
                "confirmed blocked at OS level.",
                blocked, len(names),
            )

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
        """
        Load the blacklist from disk, or create a fresh one.

        IMPORTANT: After loading, we ALWAYS rebuild the
        blacklisted_networks quick-lookup list from entries.
        This prevents the desync bug where an SSID exists in
        entries but is missing from blacklisted_networks
        (which would make is_blacklisted() return False for
        a network that IS actually blacklisted).
        """
        if os.path.exists(self.filepath):
            try:
                with open(self.filepath) as f:
                    data = json.load(f)
                # Make sure required keys exist
                data.setdefault("blacklisted_networks", [])
                data.setdefault("entries", [])
                data.setdefault("metadata", {})

                # ── REPAIR: rebuild quick-lookup from entries ──
                # entries had the SSID but blacklisted_networks
                # did not, so is_blacklisted() returned False.
                rebuilt = list({
                    e["ssid"] for e in data["entries"]
                    if "ssid" in e
                })
                if set(n.lower() for n in rebuilt) != set(
                    n.lower()
                    for n in data["blacklisted_networks"]
                ):
                    logger.warning(
                        "Blacklist desync detected! "
                        "blacklisted_networks had %d entries "
                        "but entries has %d. Repairing.",
                        len(data["blacklisted_networks"]),
                        len(rebuilt),
                    )
                    data["blacklisted_networks"] = rebuilt
                    data["metadata"]["total_entries"] = len(
                        data["entries"]
                    )
                    # Save the repaired file immediately
                    os.makedirs(
                        os.path.dirname(self.filepath),
                        exist_ok=True,
                    )
                    with open(self.filepath, "w") as f:
                        json.dump(data, f, indent=2)
                    logger.info(
                        "Blacklist repaired. Networks: %s",
                        rebuilt,
                    )

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