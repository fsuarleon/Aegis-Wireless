<div align="center">

# Aegis Wireless

### WiFi Security Analysis Tool for Windows

*Scan nearby networks, analyze risk, and enforce policy — all from your system tray.*

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Windows-0078D4?logo=windows&logoColor=white)
![Status](https://img.shields.io/badge/Status-v1.0-brightgreen)
![License](https://img.shields.io/badge/Use-Educational%20%26%20Defensive-informational)
![Build](https://img.shields.io/badge/Build-PyInstaller-FFD43B)

</div>

---

## Overview

Aegis Wireless is a desktop security tool that continuously monitors the WiFi networks around you and the one you're connected to. It detects weak encryption, open networks, suspicious ports, evil-twin access points, and missing VPNs — then scores every network from 0 (deadly) to 100 (safe).

It runs quietly in the Windows system tray, sends toast notifications when something's wrong, and can automatically disconnect from dangerous networks and block them at the OS level so your device can't reconnect.

A classic terminal UI is also included for manual audits and demos.

---

## Features

- **WiFi scanning** — enumerates nearby networks with SSID, signal strength, encryption type, channel, and band using native OS commands (no extra drivers needed).
- **Port scanning** — multi-threaded TCP port scanner with quick-scan and full-scan modes. Flags dangerous services (Telnet, SMB, RDP, VNC, etc.).
- **802.11 frame inspection** — optional deep inspection using Scapy. Parses RSN and WPA IEs from raw beacons to detect downgrade attacks, TKIP-only APs, and evil-twin BSSID mismatches.
- **Risk engine** — combines encryption quality, open ports, hidden SSIDs, signal anomalies, and blacklist status into a single safety score (SAFE / MODERATE / DANGEROUS).
- **Real-time connection monitor** — watches active WiFi connections and enforces policy automatically: scan, score, disconnect, and blacklist if it fails.
- **OS-level enforcement** — adds `netsh wlan` filters on Windows (and equivalent commands on Linux/macOS) so blocked networks actually stay blocked.
- **VPN status detection** — checks for active VPN interfaces and warns when policy requires one.
- **Blacklist manager** — persistent JSON-backed list of untrusted SSIDs with automatic OS-level blocking.
- **Local logging** — human-readable `.log` files and machine-readable `.json` files per day. Everything stays on your machine; nothing is sent to the cloud.
- **System tray UI** — minimal menu for end users, expanded menu for IT admins via `admin_mode`.
- **Toast notifications** — Windows-native toasts for dangerous networks, open networks, missing VPN, and enforcement actions. Rate-limited with a cooldown.
- **Run on startup** — registers a Windows registry entry (or LaunchAgent / autostart `.desktop` on other platforms) so Aegis launches silently on login.
- **Policy-driven config** — every behavior is controlled by `config/settings.json`. See the full [settings guide](config/SETTINGS_GUIDE.md).

---

## Requirements

- **OS:** Windows 10 or 11 (primary target). Core scanning works on Linux/macOS; tray features and OS-level blocking are Windows-focused.
- **Python:** 3.10 or newer (the bundled build uses 3.13).
- **Privileges:** some features (OS-level network blocking, registering on startup) require running as Administrator.

### Python dependencies

```
pystray     # system tray icon
Pillow      # icon rendering
plyer       # cross-platform notifications
winotify    # Windows toast notifications
pyinstaller # for building the .exe
```

Scapy is optional and only needed for the frame-level 802.11 inspector.

---

## Installation

### Option 1 — One-click installer (recommended)

Double-click `install.bat`. It will:

1. Check that Python and pip are installed.
2. Install all dependencies.
3. Build `dist/AegisWireless.exe` with PyInstaller.
4. Register Aegis to launch in tray mode on startup.
5. Start the app.

Run it as Administrator the first time so the startup registration and OS-level firewall rules can be applied.

### Option 2 — Manual install

```bat
pip install pystray Pillow plyer winotify pyinstaller
python build.py
```

The finished executable is at `dist\AegisWireless.exe`.

### Option 3 — Run from source

```bat
pip install pystray Pillow plyer winotify
python main.py          :: tray mode (default)
python main.py --cli    :: terminal menu
```

You can also double-click `aegis_tray.pyw` for a windowless tray launch without building an exe.

---

## Usage

### Tray mode (default)

Once launched, Aegis sits in the system tray. Right-click the icon for the menu:

**User menu** (`admin_mode: false`)
- Status
- Last scan time
- Scan Now
- Exit

**Admin menu** (`admin_mode: true`)
- Everything above, plus:
- Full Audit
- VPN Status
- View Logs
- Run on Startup toggle
- Notifications toggle
- Open Terminal UI

Background scans run every 15 minutes by default (configurable).

### Terminal mode

Run `python main.py --cli` for the interactive menu:

```
1 | Scan WiFi Networks
2 | Scan Ports on a Device
3 | Analyze Network Risk
4 | Manage Blacklist
5 | View Scan Logs
6 | Check VPN Status
7 | Full Network Audit (scan + analyze all)
8 | Switch to System Tray Mode
9 | Configure Run on Startup
0 | Exit
```

The Full Audit option runs every check end-to-end and produces a summary table.

---

## Project Structure

```
Aegis-Wireless/
├── main.py                 # Terminal + tray entry point
├── aegis_tray.pyw          # Windowless tray launcher
├── tray_agent.py           # Standalone background agent
├── build.py                # PyInstaller build script
├── install.bat             # One-click installer
├── AegisWireless.spec      # PyInstaller spec file
│
├── scanner/
│   ├── wifi_scan.py        # WiFi network enumeration
│   ├── port_probe.py       # Threaded TCP port scanner
│   └── frame_inspector.py  # 802.11 beacon/RSN parser (Scapy)
│
├── core/
│   ├── engine.py           # Risk scoring engine
│   └── blacklist.py        # Blacklist manager
│
├── network/
│   ├── monitor.py          # Real-time connection monitor
│   ├── enforcement.py      # Disconnect + OS-level block
│   └── vpn_tunnel.py       # VPN detection
│
├── ui/
│   ├── tray.py             # System tray application
│   ├── notifications.py    # Toast notifications
│   └── startup.py          # Run-on-startup registration
│
├── api/
│   └── telemetry.py        # Local logging (text + JSON)
│
├── config/
│   ├── settings.json       # All runtime configuration
│   ├── blacklist.json      # Persistent blacklist
│   └── SETTINGS_GUIDE.md   # Full config reference
│
├── assets/                 # Icons
├── logs/                   # Daily scan logs
├── build/                  # PyInstaller build output
└── dist/                   # Final .exe
```

---

## Configuration

Every setting lives in `config/settings.json`. A few of the important ones:

| Setting | Purpose |
|---|---|
| `admin_mode` | `true` shows the full tray menu, `false` shows the minimal user menu |
| `policy.require_vpn` | Warn when no VPN is active |
| `policy.minimum_encryption` | Flag anything below this (`WPA2`, `WPA3`, etc.) |
| `policy.auto_enforce_disconnect` | Auto-disconnect from DANGEROUS networks |
| `policy.max_acceptable_risk_score` | Networks below this score are DANGEROUS (default `40`) |
| `policy.scan_interval_minutes` | Background scan frequency |
| `policy.blocked_ssids` / `trusted_ssids` | Always-bad / always-good allow lists |
| `notifications.*` | Fine-grained toggles for each toast type |
| `tray.show_exit_button` | Lock users out of closing the app |

See [`config/SETTINGS_GUIDE.md`](config/SETTINGS_GUIDE.md) for the full reference.

---

## How It Works

```
           +-----------------+
           |   Tray / CLI    |
           +--------+--------+
                    |
                    v
           +--------+--------+         +------------------+
           |   WiFi Scanner  |  -----> | Frame Inspector  |
           |  (netsh/nmcli)  |         |    (Scapy RSN)   |
           +--------+--------+         +--------+---------+
                    |                           |
                    v                           v
           +--------+---------------------------+-------+
           |               Risk Engine                  |
           |  encryption + ports + hidden + signal +    |
           |  blacklist  -->  safety score 0-100        |
           +--------+-----------------------------------+
                    |
         +----------+----------+
         v          v          v
   +-----+-----+ +--+----+ +---+------+
   | Notifier  | | Log   | | Enforcer |
   | (toasts)  | | (JSON)| |  (netsh) |
   +-----------+ +-------+ +----------+
```

The risk engine pulls configuration from `settings.json` on every scan, so policy changes take effect without restarting the app.

---

## Building from Source

```bat
python build.py
```

This wraps PyInstaller with the correct hidden imports and bundled data folders. Output: `dist\AegisWireless.exe` (a single portable executable, ~16 MB).

The build script auto-attaches `assets\aegis_icon.ico` as the exe icon if it exists.

---

## Logging & Privacy

- All logs are written to the `logs/` folder under the install directory.
- Two files per day: `aegis_YYYY-MM-DD.log` (text) and `aegis_YYYY-MM-DD.json` (structured).
- **No telemetry is sent over the network.** Aegis makes zero outbound requests.
- Old logs are pruned automatically based on `logging.max_log_files`.

---

## Legal Notice

> Aegis Wireless is for **educational and defensive use only**.
>
> - Do not attempt to initiate attacks based on any network as a result of potential vulnerability Aegis Wireless may find.
> - Network analysis preformed by Aegis Wireless is intened strictly for the use of personal device security.
> - This tool does **not** perform any attacks. It observes publicly broadcast information and scans local devices; it does not attempt exploitation, credential capture, or deauthentication.

The authors assume no liability for misuse.

---

## Roadmap

- Real VPN client integration (WireGuard / OpenVPN)
- Multi-AP correlation for evil-twin fingerprinting
- Per-SSID historical risk trends in a small web dashboard
- Signed installer (MSIX) with code-signing certificate

---

## Acknowledgments

Built as a student capstone project. Standing on the shoulders of `pystray`, `Pillow`, `plyer`, `winotify`, `PyInstaller`, and `Scapy`.
