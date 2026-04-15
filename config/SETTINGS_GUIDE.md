# Aegis Wireless — Settings Guide

All configuration is in `config/settings.json`. This guide explains every setting.

---

## `admin_mode`

Controls tray menu complexity.

| Value   | Behavior |
|---------|----------|
| `false` | Users see: Status, Last Scan, Scan Now, Exit |
| `true`  | Adds: Full Audit, VPN Status, View Logs, Run on Startup, Notifications, Terminal UI |

Set `false` for end-user deployments, `true` for IT admin/testing machines.

---

## `policy`

IT security policies enforced automatically in the background. Users cannot override these.

| Key | Type | Description |
|-----|------|-------------|
| `require_vpn` | bool | Every scan checks for an active VPN. Toast warns if missing. `true` for corporate, `false` for personal. |
| `minimum_encryption` | string | Lowest acceptable WiFi encryption. Options: `Open`, `WEP`, `WPA`, `WPA2`, `WPA3`. Networks below this are flagged. |
| `allow_open_networks` | bool | `false` = open (unencrypted) networks trigger alerts. Always `false` for corporate. |
| `max_acceptable_risk_score` | int | Networks scoring below this (0–100) are classified DANGEROUS. Higher = stricter. Default `40`. |
| `auto_enforce_disconnect` | bool | `true` = auto-disconnect from DANGEROUS networks. `false` = warn only. Can disrupt connectivity. |
| `blocked_ssids` | array | SSIDs always flagged as dangerous. Example: `["FreeAirportWifi", "HotelGuest"]`. |
| `trusted_ssids` | array | SSIDs always considered safe (skip risk analysis). Example: `["CorpWifi-5G"]`. |
| `auto_scan_on_start` | bool | Run a WiFi scan immediately on tray icon launch. |
| `scan_interval_minutes` | int | Background scan interval in minutes. `0` = disable. `5–10` for high-security, `15–30` normal. |
| `org_name` | string | Organization name shown in tray header. Leave `""` for no branding. |

---

## `scan_settings`

Technical parameters for port scanning. Only modify if you understand networking.

| Key | Type | Description |
|-----|------|-------------|
| `default_port_range` | array | Range for Full Scan: `[1, 1024]` = well-known ports. `[1, 65535]` = all ports (much slower). |
| `common_ports` | array | Ports checked during Quick Scan. Add ports your org cares about (e.g., `8080`, `27017`). |
| `scan_timeout_seconds` | float | Wait time per port. `0.5` fast networks, `1.0` balanced, `2.0` high-latency. |
| `max_threads` | int | Simultaneous port checks. `20` low-power, `50` default, `100` fast networks. |

---

## `risk_thresholds`

Define what the risk engine considers dangerous. These feed into the safety score calculation.

| Key | Type | Description |
|-----|------|-------------|
| `open_port_warning` | int | Flag devices with more than this many open ports. Default `5`. |
| `dangerous_ports` | array | Ports that should never be open on public networks. Each reduces safety score. |
| `safe_encryption_types` | array | Encryption types considered secure. Networks not in this list lose risk points. |

---

## `notifications`

Control which toast notifications are shown. IT admins can suppress specific categories.

| Key | Type | Description |
|-----|------|-------------|
| `enabled` | bool | Master switch. `false` = no toasts at all. |
| `cooldown_seconds` | int | Minimum time between same-type notifications. Prevents spam. Default `30`. |
| `on_dangerous_network` | bool | Toast when a network scores DANGEROUS. Most critical alert. |
| `on_open_network` | bool | Toast when unencrypted networks are nearby. |
| `on_blacklisted_network` | bool | Toast when a blocked SSID is detected. |
| `on_vpn_missing` | bool | Toast when no VPN is detected (only if `require_vpn` is also `true`). |
| `on_scan_complete` | bool | Summary toast after every scan. Disable for silent background mode. |
| `on_startup` | bool | Toast when Aegis starts. Disable for fully silent launch. |
| `on_connection_blocked` | bool | Toast when a connection is blocked and disconnected. |
| `on_connection_allowed` | bool | Toast when a connection passes security checks. |

---

## `tray`

System tray icon behavior and user permissions.

| Key | Type | Description |
|-----|------|-------------|
| `run_on_startup` | bool | Whether Aegis starts on login. Set by installer — don't edit manually. |
| `show_exit_button` | bool | `false` = users can't close Aegis from tray (need Task Manager). |
| `user_can_disable_notifications` | bool | `false` = hide the Notifications toggle from users. Recommended. |
| `user_can_toggle_startup` | bool | `false` = hide the Run on Startup toggle from users. Recommended. |

---

## `logging`

Control where and how scan logs are stored.

| Key | Type | Description |
|-----|------|-------------|
| `log_directory` | string | Folder for logs, relative to install dir. Use absolute path for centralized logging. |
| `log_format` | string | Python logging format string for `.log` text files. |
| `max_log_files` | int | Daily log files to keep before deletion. `30` = one month. `0` = keep forever (not recommended). |
