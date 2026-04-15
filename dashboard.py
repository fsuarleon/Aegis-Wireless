"""
dashboard.py — Aegis Wireless Web Dashboard
=============================================
WHAT THIS DOES:
    Runs a local web server on your computer that serves a
    beautiful dashboard in your browser. The dashboard calls
    the same Python modules as the CLI tool.

HOW TO RUN:
    1. Install Flask:  pip install flask
    2. Run:            python dashboard.py
    3. Open browser:   http://127.0.0.1:5000

HOW TO STOP:
    Press Ctrl+C in the terminal.

NOTE:
    This runs ONLY on your local machine. Nobody else can
    access it. It's not a public website.
"""

import sys
import os
import json
from datetime import datetime

# Add project root to path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# Check for Flask
try:
    from flask import Flask, render_template_string, jsonify, request
except ImportError:
    print("[!] Flask is not installed.")
    print("    Install it by running:")
    print("    pip install flask")
    sys.exit(1)

# Import our modules
from scanner.wifi_scan import WiFiScanner
from scanner.port_probe import PortScanner
from core.engine import RiskEngine
from core.blacklist import BlacklistManager
from network.vpn_tunnel import VPNStatus
from api.telemetry import AegisLogger

# ── Create Flask app ────────────────────────────────────────
app = Flask(__name__)

# Create module instances
wifi_scanner = WiFiScanner()
port_scanner = PortScanner()
risk_engine = RiskEngine()
blacklist = BlacklistManager()
logger = AegisLogger()

# Cache for scan results
scan_cache = {
    "wifi_networks": [],
    "assessments": [],
    "port_report": None,
    "last_scan_time": None,
}

# ── HTML TEMPLATE ───────────────────────────────────────────
DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Aegis Wireless — Dashboard</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
<style>
* { margin:0; padding:0; box-sizing:border-box; }

:root {
    --bg-deep: #0a0e17;
    --bg-card: #111827;
    --bg-card-hover: #1a2332;
    --border: #1e293b;
    --border-glow: #22d3ee33;
    --text-primary: #f1f5f9;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --cyan: #22d3ee;
    --cyan-dim: #22d3ee44;
    --green: #34d399;
    --green-bg: #34d39915;
    --yellow: #fbbf24;
    --yellow-bg: #fbbf2415;
    --red: #f87171;
    --red-bg: #f8717115;
    --purple: #a78bfa;
}

body {
    background: var(--bg-deep);
    color: var(--text-primary);
    font-family: 'Outfit', sans-serif;
    min-height: 100vh;
    overflow-x: hidden;
}

/* ── Animated background grid ── */
body::before {
    content: '';
    position: fixed; top: 0; left: 0; right: 0; bottom: 0;
    background-image:
        linear-gradient(var(--border) 1px, transparent 1px),
        linear-gradient(90deg, var(--border) 1px, transparent 1px);
    background-size: 60px 60px;
    opacity: 0.3;
    z-index: 0;
    animation: gridShift 20s linear infinite;
}
@keyframes gridShift { to { background-position: 60px 60px; } }

/* ── Glow orbs ── */
body::after {
    content: '';
    position: fixed; top: -200px; right: -200px;
    width: 600px; height: 600px;
    background: radial-gradient(circle, var(--cyan-dim) 0%, transparent 70%);
    z-index: 0;
    animation: orbFloat 8s ease-in-out infinite alternate;
}
@keyframes orbFloat {
    0% { transform: translate(0, 0); }
    100% { transform: translate(-80px, 80px); }
}

/* ── Layout ── */
.app { position: relative; z-index: 1; max-width: 1280px; margin: 0 auto; padding: 24px; }

/* ── Header ── */
.header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 20px 0 32px;
    border-bottom: 1px solid var(--border);
    margin-bottom: 32px;
}
.header-left { display: flex; align-items: center; gap: 16px; }
.shield-icon {
    width: 48px; height: 48px;
    background: linear-gradient(135deg, var(--cyan), var(--purple));
    border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    font-size: 24px; font-weight: 700; color: var(--bg-deep);
    box-shadow: 0 0 30px var(--cyan-dim);
}
.header h1 {
    font-family: 'JetBrains Mono', monospace;
    font-size: 22px; font-weight: 700;
    letter-spacing: -0.5px;
}
.header h1 span { color: var(--cyan); }
.header-subtitle { font-size: 13px; color: var(--text-muted); margin-top: 2px; }
.vpn-badge {
    padding: 8px 16px; border-radius: 20px;
    font-size: 13px; font-weight: 500;
    display: flex; align-items: center; gap: 8px;
}
.vpn-on { background: var(--green-bg); color: var(--green); border: 1px solid #34d39933; }
.vpn-off { background: var(--red-bg); color: var(--red); border: 1px solid #f8717133; }

/* ── Stat cards row ── */
.stats-row {
    display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px;
    margin-bottom: 32px;
}
.stat-card {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 20px;
    transition: all 0.3s ease;
}
.stat-card:hover {
    border-color: var(--cyan);
    box-shadow: 0 0 20px var(--cyan-dim);
    transform: translateY(-2px);
}
.stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-bottom: 8px; }
.stat-value { font-family: 'JetBrains Mono', monospace; font-size: 32px; font-weight: 700; }
.stat-sub { font-size: 12px; color: var(--text-secondary); margin-top: 4px; }
.stat-safe .stat-value { color: var(--green); }
.stat-warn .stat-value { color: var(--yellow); }
.stat-danger .stat-value { color: var(--red); }
.stat-info .stat-value { color: var(--cyan); }

/* ── Action buttons ── */
.actions {
    display: flex; gap: 12px; margin-bottom: 32px; flex-wrap: wrap;
}
.btn {
    padding: 12px 24px; border-radius: 8px; border: 1px solid var(--border);
    background: var(--bg-card); color: var(--text-primary);
    font-family: 'Outfit', sans-serif; font-size: 14px; font-weight: 500;
    cursor: pointer; transition: all 0.2s;
    display: flex; align-items: center; gap: 8px;
}
.btn:hover { border-color: var(--cyan); background: var(--bg-card-hover); }
.btn:disabled { opacity: 0.5; cursor: not-allowed; }
.btn-primary {
    background: linear-gradient(135deg, #0e7490, #0891b2);
    border-color: var(--cyan); color: white;
}
.btn-primary:hover {
    box-shadow: 0 0 25px var(--cyan-dim);
    transform: translateY(-1px);
}
.btn .icon { font-size: 16px; }

/* ── Scan progress ── */
.scan-progress {
    display: none; align-items: center; gap: 12px;
    padding: 16px 20px; background: var(--bg-card);
    border: 1px solid var(--cyan); border-radius: 10px;
    margin-bottom: 24px;
    animation: borderPulse 2s ease-in-out infinite;
}
@keyframes borderPulse {
    0%, 100% { border-color: var(--cyan); box-shadow: 0 0 10px var(--cyan-dim); }
    50% { border-color: var(--purple); box-shadow: 0 0 20px #a78bfa33; }
}
.scan-progress.active { display: flex; }
.spinner {
    width: 20px; height: 20px;
    border: 2px solid var(--border);
    border-top-color: var(--cyan);
    border-radius: 50%;
    animation: spin 0.8s linear infinite;
}
@keyframes spin { to { transform: rotate(360deg); } }
.scan-progress-text { font-size: 14px; color: var(--text-secondary); }

/* ── Two column layout ── */
.content-grid {
    display: grid; grid-template-columns: 1fr 1fr; gap: 24px;
    margin-bottom: 32px;
}

/* ── Panel (card container) ── */
.panel {
    background: var(--bg-card);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
}
.panel-header {
    display: flex; align-items: center; justify-content: space-between;
    padding: 16px 20px;
    border-bottom: 1px solid var(--border);
    font-weight: 600; font-size: 15px;
}
.panel-header .count {
    background: var(--bg-deep); padding: 4px 10px;
    border-radius: 6px; font-size: 12px; color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
}
.panel-body { padding: 0; max-height: 420px; overflow-y: auto; }
.panel-body::-webkit-scrollbar { width: 4px; }
.panel-body::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }

/* ── Network list items ── */
.network-item {
    display: flex; align-items: center; gap: 14px;
    padding: 14px 20px;
    border-bottom: 1px solid var(--border);
    transition: background 0.15s;
    cursor: default;
}
.network-item:last-child { border-bottom: none; }
.network-item:hover { background: var(--bg-card-hover); }

.risk-dot {
    width: 10px; height: 10px; border-radius: 50%; flex-shrink: 0;
}
.risk-dot.safe { background: var(--green); box-shadow: 0 0 8px var(--green); }
.risk-dot.moderate { background: var(--yellow); box-shadow: 0 0 8px var(--yellow); }
.risk-dot.dangerous { background: var(--red); box-shadow: 0 0 8px var(--red); animation: dangerPulse 1.5s infinite; }
@keyframes dangerPulse {
    0%, 100% { box-shadow: 0 0 8px var(--red); }
    50% { box-shadow: 0 0 16px var(--red); }
}

.network-info { flex: 1; min-width: 0; }
.network-name {
    font-weight: 600; font-size: 14px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
}
.network-meta { font-size: 12px; color: var(--text-muted); margin-top: 2px; }

.network-score {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700; font-size: 16px;
    text-align: right; flex-shrink: 0;
}
.score-safe { color: var(--green); }
.score-moderate { color: var(--yellow); }
.score-dangerous { color: var(--red); }

.network-badge {
    font-size: 11px; padding: 3px 8px; border-radius: 4px;
    font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px;
    flex-shrink: 0;
}
.badge-safe { background: var(--green-bg); color: var(--green); }
.badge-moderate { background: var(--yellow-bg); color: var(--yellow); }
.badge-dangerous { background: var(--red-bg); color: var(--red); }

/* ── Signal bar ── */
.signal-bar {
    display: flex; gap: 2px; align-items: flex-end; height: 16px; flex-shrink: 0;
}
.signal-bar .bar {
    width: 4px; border-radius: 1px;
    background: var(--border);
}
.signal-bar .bar.active { background: var(--cyan); }
.signal-bar .bar:nth-child(1) { height: 4px; }
.signal-bar .bar:nth-child(2) { height: 7px; }
.signal-bar .bar:nth-child(3) { height: 10px; }
.signal-bar .bar:nth-child(4) { height: 14px; }
.signal-bar .bar:nth-child(5) { height: 16px; }

/* ── Port list ── */
.port-item {
    display: flex; align-items: center; gap: 12px;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 13px;
}
.port-item:last-child { border-bottom: none; }
.port-num {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 600; color: var(--cyan);
    min-width: 50px;
}
.port-service { flex: 1; color: var(--text-secondary); }
.port-risk { color: var(--yellow); font-size: 12px; }

/* ── Blacklist ── */
.blacklist-item {
    display: flex; align-items: center; justify-content: space-between;
    padding: 12px 20px;
    border-bottom: 1px solid var(--border);
}
.blacklist-item:last-child { border-bottom: none; }
.bl-name { font-weight: 600; font-size: 14px; }
.bl-reason { font-size: 12px; color: var(--text-muted); margin-top: 2px; }
.bl-remove {
    background: none; border: 1px solid var(--border);
    color: var(--red); padding: 4px 10px; border-radius: 6px;
    cursor: pointer; font-size: 12px;
    font-family: 'Outfit', sans-serif;
    transition: all 0.2s;
}
.bl-remove:hover { background: var(--red-bg); border-color: var(--red); }

/* ── Blacklist add form ── */
.bl-add-form {
    display: flex; gap: 8px; padding: 12px 20px;
    border-top: 1px solid var(--border);
}
.bl-input {
    flex: 1; padding: 8px 12px; border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg-deep); color: var(--text-primary);
    font-family: 'Outfit', sans-serif; font-size: 13px;
}
.bl-input:focus { outline: none; border-color: var(--cyan); }

/* ── Empty state ── */
.empty-state {
    padding: 40px 20px; text-align: center;
    color: var(--text-muted); font-size: 14px;
}
.empty-state .empty-icon { font-size: 32px; margin-bottom: 12px; opacity: 0.5; }

/* ── Findings detail ── */
.findings-panel { grid-column: 1 / -1; }
.finding-item {
    display: flex; gap: 12px; padding: 14px 20px;
    border-bottom: 1px solid var(--border);
}
.finding-sev {
    font-size: 11px; padding: 3px 8px; border-radius: 4px;
    font-weight: 700; text-transform: uppercase;
    flex-shrink: 0; height: fit-content; margin-top: 2px;
}
.sev-high { background: var(--red-bg); color: var(--red); }
.sev-medium { background: var(--yellow-bg); color: var(--yellow); }
.sev-low { background: #22d3ee15; color: var(--cyan); }
.finding-text { font-size: 13px; color: var(--text-secondary); line-height: 1.5; }
.finding-text strong { color: var(--text-primary); font-weight: 600; }
.finding-rec { font-size: 12px; color: var(--text-muted); margin-top: 6px; }

/* ── Log Viewer ── */
.log-viewer { grid-column: 1 / -1; margin-top: 8px; }
.log-toolbar {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 20px; border-bottom: 1px solid var(--border);
    flex-wrap: wrap;
}
.log-select {
    padding: 7px 12px; border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg-deep); color: var(--text-primary);
    font-family: 'Outfit', sans-serif; font-size: 13px;
    cursor: pointer;
}
.log-select:focus { outline: none; border-color: var(--cyan); }
.log-filter-group { display: flex; gap: 6px; margin-left: auto; }
.log-filter-btn {
    padding: 5px 12px; border-radius: 6px; border: 1px solid var(--border);
    background: transparent; color: var(--text-muted); font-size: 12px;
    font-family: 'Outfit', sans-serif; cursor: pointer; transition: all 0.2s;
}
.log-filter-btn:hover { border-color: var(--cyan); color: var(--text-secondary); }
.log-filter-btn.active { background: var(--cyan-dim); border-color: var(--cyan); color: var(--cyan); }
.log-entries { max-height: 520px; overflow-y: auto; }
.log-entries::-webkit-scrollbar { width: 4px; }
.log-entries::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
.log-entry {
    display: flex; gap: 12px; padding: 10px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 13px; align-items: flex-start;
    transition: background 0.15s;
}
.log-entry:hover { background: var(--bg-card-hover); }
.log-entry:last-child { border-bottom: none; }
.log-time {
    font-family: 'JetBrains Mono', monospace; font-size: 12px;
    color: var(--text-muted); white-space: nowrap; min-width: 75px;
    flex-shrink: 0;
}
.log-type-badge {
    font-size: 10px; padding: 2px 8px; border-radius: 4px;
    font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px;
    flex-shrink: 0; min-width: 70px; text-align: center;
}
.log-type-wifi { background: #22d3ee15; color: var(--cyan); }
.log-type-port { background: #a78bfa15; color: var(--purple); }
.log-type-risk { background: var(--yellow-bg); color: var(--yellow); }
.log-type-enforce { background: var(--red-bg); color: var(--red); }
.log-type-blacklist { background: #f8717115; color: var(--red); }
.log-type-message { background: #34d39915; color: var(--green); }
.log-msg { color: var(--text-secondary); line-height: 1.5; word-break: break-word; }
.log-msg strong { color: var(--text-primary); font-weight: 600; }
.log-detail {
    margin-top: 6px; padding: 8px 12px; border-radius: 6px;
    background: var(--bg-deep); font-family: 'JetBrains Mono', monospace;
    font-size: 11px; color: var(--text-muted); line-height: 1.6;
    white-space: pre-wrap; max-height: 200px; overflow-y: auto;
}
.log-detail::-webkit-scrollbar { width: 3px; }
.log-detail::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
.log-session-header {
    padding: 10px 20px; background: var(--bg-deep);
    border-bottom: 1px solid var(--border);
    font-size: 12px; color: var(--text-muted);
    font-family: 'JetBrains Mono', monospace;
    display: flex; justify-content: space-between; align-items: center;
}
.log-session-header .session-id {
    color: var(--cyan); font-weight: 600;
}
.log-stats-row {
    display: flex; gap: 16px; padding: 12px 20px;
    border-bottom: 1px solid var(--border);
    font-size: 12px;
}
.log-stat { display: flex; align-items: center; gap: 4px; }
.log-stat-num {
    font-family: 'JetBrains Mono', monospace;
    font-weight: 700; font-size: 14px;
}
.log-expand-btn {
    background: none; border: none; color: var(--cyan);
    cursor: pointer; font-size: 12px; padding: 2px 6px;
    font-family: 'Outfit', sans-serif; opacity: 0.7;
    transition: opacity 0.2s;
}
.log-expand-btn:hover { opacity: 1; }

/* ── Footer ── */
.footer {
    text-align: center; padding: 24px;
    font-size: 12px; color: var(--text-muted);
    border-top: 1px solid var(--border); margin-top: 16px;
}
.footer span { color: var(--cyan); }

/* ── Responsive ── */
@media (max-width: 768px) {
    .stats-row { grid-template-columns: repeat(2, 1fr); }
    .content-grid { grid-template-columns: 1fr; }
    .header { flex-direction: column; align-items: flex-start; gap: 12px; }
}

/* ── Load animation ── */
.fade-in { animation: fadeIn 0.4s ease-out; }
@keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }
</style>
</head>
<body>
<div class="app">

    <!-- ── Header ── -->
    <header class="header fade-in">
        <div class="header-left">
            <div class="shield-icon">A</div>
            <div>
                <h1>AEGIS <span>WIRELESS</span></h1>
                <div class="header-subtitle">WiFi Security Analysis Dashboard — v1.0</div>
            </div>
        </div>
        <div id="vpnBadge" class="vpn-badge vpn-off">
            <span id="vpnDot">&#9679;</span>
            <span id="vpnText">Checking VPN...</span>
        </div>
    </header>

    <!-- ── Stats Row ── -->
    <div class="stats-row fade-in">
        <div class="stat-card stat-info">
            <div class="stat-label">Networks Found</div>
            <div class="stat-value" id="statTotal">—</div>
            <div class="stat-sub" id="statTime">No scan yet</div>
        </div>
        <div class="stat-card stat-safe">
            <div class="stat-label">Safe</div>
            <div class="stat-value" id="statSafe">—</div>
            <div class="stat-sub">Score 70+</div>
        </div>
        <div class="stat-card stat-warn">
            <div class="stat-label">Moderate</div>
            <div class="stat-value" id="statModerate">—</div>
            <div class="stat-sub">Score 40–69</div>
        </div>
        <div class="stat-card stat-danger">
            <div class="stat-label">Dangerous</div>
            <div class="stat-value" id="statDangerous">—</div>
            <div class="stat-sub">Score 0–39</div>
        </div>
    </div>

    <!-- ── Actions ── -->
    <div class="actions fade-in">
        <button class="btn btn-primary" onclick="runFullAudit()" id="btnAudit">
            <span class="icon">&#9776;</span> Full Network Audit
        </button>
        <button class="btn" onclick="runWifiScan()" id="btnWifi">
            <span class="icon">&#9678;</span> WiFi Scan
        </button>
        <button class="btn" onclick="runPortScan()" id="btnPort">
            <span class="icon">&#9881;</span> Port Scan
        </button>
        <button class="btn" onclick="checkVPN()">
            <span class="icon">&#9740;</span> VPN Check
        </button>
    </div>

    <!-- ── Progress bar ── -->
    <div class="scan-progress" id="scanProgress">
        <div class="spinner"></div>
        <span class="scan-progress-text" id="scanText">Scanning networks...</span>
    </div>

    <!-- ── Two columns: Networks + Ports ── -->
    <div class="content-grid fade-in">

        <!-- Network List -->
        <div class="panel">
            <div class="panel-header">
                <span>Detected Networks</span>
                <span class="count" id="netCount">0</span>
            </div>
            <div class="panel-body" id="networkList">
                <div class="empty-state">
                    <div class="empty-icon">&#9678;</div>
                    Click "WiFi Scan" or "Full Audit" to detect nearby networks
                </div>
            </div>
        </div>

        <!-- Port Scan / Blacklist -->
        <div class="panel">
            <div class="panel-header">
                <span id="rightPanelTitle">Blacklisted Networks</span>
                <span class="count" id="rightCount">0</span>
            </div>
            <div class="panel-body" id="rightPanel">
                <div class="empty-state">
                    <div class="empty-icon">&#9940;</div>
                    No blacklisted networks yet
                </div>
            </div>
            <div class="bl-add-form" id="blAddForm">
                <input class="bl-input" id="blNameInput" placeholder="Network name (SSID)">
                <input class="bl-input" id="blReasonInput" placeholder="Reason">
                <button class="btn" onclick="addToBlacklist()" style="padding:8px 14px; font-size:13px;">Add</button>
            </div>
        </div>

        <!-- Findings (full width) -->
        <div class="panel findings-panel" id="findingsPanel" style="display:none">
            <div class="panel-header">
                <span>Risk Findings</span>
                <span class="count" id="findingsCount">0</span>
            </div>
            <div class="panel-body" id="findingsList"></div>
        </div>

    </div>

    <!-- ── Log Viewer (full width) ── -->
    <div class="panel log-viewer fade-in" id="logViewerPanel">
        <div class="panel-header">
            <span>&#128466; Activity Logs</span>
            <span class="count" id="logCount">0</span>
        </div>
        <div class="log-toolbar">
            <select class="log-select" id="logDateSelect" onchange="loadLogForDate()">
                <option value="">Loading dates...</option>
            </select>
            <div class="log-filter-group">
                <button class="log-filter-btn active" data-filter="all" onclick="filterLogs('all', this)">All</button>
                <button class="log-filter-btn" data-filter="wifi" onclick="filterLogs('wifi', this)">WiFi</button>
                <button class="log-filter-btn" data-filter="port" onclick="filterLogs('port', this)">Ports</button>
                <button class="log-filter-btn" data-filter="risk" onclick="filterLogs('risk', this)">Risk</button>
                <button class="log-filter-btn" data-filter="enforce" onclick="filterLogs('enforce', this)">Enforce</button>
                <button class="log-filter-btn" data-filter="blacklist" onclick="filterLogs('blacklist', this)">Blacklist</button>
            </div>
        </div>
        <div class="log-entries" id="logEntries">
            <div class="empty-state">
                <div class="empty-icon">&#128466;</div>
                Select a date to browse activity logs
            </div>
        </div>
    </div>

    <footer class="footer">
        <span>AEGIS WIRELESS</span> — Educational & Defensive Use Only — Florida International University — CIS 4951 Capstone II
    </footer>

</div>

<script>
// ── API helper ──
async function api(endpoint, method='GET', body=null) {
    const opts = { method, headers: {'Content-Type':'application/json'} };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(endpoint, opts);
    return res.json();
}

// ── Show/hide progress ──
function showProgress(text) {
    document.getElementById('scanProgress').classList.add('active');
    document.getElementById('scanText').textContent = text;
}
function hideProgress() {
    document.getElementById('scanProgress').classList.remove('active');
}

// ── Update stats cards ──
function updateStats(data) {
    document.getElementById('statTotal').textContent = data.total || 0;
    document.getElementById('statSafe').textContent = data.safe || 0;
    document.getElementById('statModerate').textContent = data.moderate || 0;
    document.getElementById('statDangerous').textContent = data.dangerous || 0;
    document.getElementById('statTime').textContent = data.time || 'Just now';
}

// ── Build signal bar HTML ──
function signalBar(strength) {
    let bars = '';
    for (let i = 1; i <= 5; i++) {
        const active = strength >= i * 20 ? 'active' : '';
        bars += '<div class="bar ' + active + '"></div>';
    }
    return '<div class="signal-bar">' + bars + '</div>';
}

// ── Render network list ──
function renderNetworks(assessments) {
    const container = document.getElementById('networkList');
    const countEl = document.getElementById('netCount');

    if (!assessments || assessments.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">&#9678;</div>No networks found. Is WiFi enabled?</div>';
        countEl.textContent = '0';
        return;
    }

    countEl.textContent = assessments.length;
    let html = '';
    assessments.forEach(a => {
        const level = a.risk_level.toLowerCase();
        const scoreClass = 'score-' + level;
        const badgeClass = 'badge-' + level;
        html += '<div class="network-item">'
            + '<div class="risk-dot ' + level + '"></div>'
            + '<div class="network-info">'
            + '<div class="network-name">' + escHtml(a.ssid) + '</div>'
            + '<div class="network-meta">' + escHtml(a.encryption) + '</div>'
            + '</div>'
            + signalBar(a.signal || 0)
            + '<div class="network-score ' + scoreClass + '">' + a.safety_score + '</div>'
            + '<div class="network-badge ' + badgeClass + '">' + a.risk_level + '</div>'
            + '</div>';
    });
    container.innerHTML = html;
}

// ── Render findings ──
function renderFindings(assessments) {
    const panel = document.getElementById('findingsPanel');
    const list = document.getElementById('findingsList');
    const count = document.getElementById('findingsCount');

    let allFindings = [];
    assessments.forEach(a => {
        (a.findings || []).forEach(f => {
            allFindings.push({...f, ssid: a.ssid});
        });
    });

    if (allFindings.length === 0) {
        panel.style.display = 'none';
        return;
    }

    panel.style.display = 'block';
    count.textContent = allFindings.length;

    let html = '';
    allFindings.forEach(f => {
        const sevClass = 'sev-' + f.severity;
        html += '<div class="finding-item">'
            + '<div class="finding-sev ' + sevClass + '">' + f.severity + '</div>'
            + '<div><div class="finding-text"><strong>' + escHtml(f.ssid) + '</strong> — ' + escHtml(f.description) + '</div>'
            + '<div class="finding-rec">' + escHtml(f.recommendation) + '</div></div>'
            + '</div>';
    });
    list.innerHTML = html;
}

// ── Render port results ──
function renderPorts(report) {
    const panel = document.getElementById('rightPanel');
    const title = document.getElementById('rightPanelTitle');
    const count = document.getElementById('rightCount');
    const form = document.getElementById('blAddForm');

    if (!report) return;

    title.textContent = 'Open Ports — ' + report.target;
    count.textContent = report.open_port_count;
    form.style.display = 'none';

    if (report.open_port_count === 0) {
        panel.innerHTML = '<div class="empty-state"><div class="empty-icon">&#9881;</div>No open ports found — looking good!</div>';
        return;
    }

    let html = '';
    report.open_ports.forEach(p => {
        html += '<div class="port-item">'
            + '<span class="port-num">:' + p.port + '</span>'
            + '<span class="port-service">' + escHtml(p.service) + '</span>'
            + '<span class="port-risk">' + escHtml(p.risk_note) + '</span>'
            + '</div>';
    });
    panel.innerHTML = html;
}

// ── Blacklist ──
async function loadBlacklist() {
    const data = await api('/api/blacklist');
    const panel = document.getElementById('rightPanel');
    const count = document.getElementById('rightCount');
    const title = document.getElementById('rightPanelTitle');
    const form = document.getElementById('blAddForm');

    title.textContent = 'Blacklisted Networks';
    form.style.display = 'flex';
    count.textContent = data.entries.length;

    if (data.entries.length === 0) {
        panel.innerHTML = '<div class="empty-state"><div class="empty-icon">&#9940;</div>No blacklisted networks yet</div>';
        return;
    }

    let html = '';
    data.entries.forEach(e => {
        html += '<div class="blacklist-item">'
            + '<div><div class="bl-name">' + escHtml(e.ssid) + '</div>'
            + '<div class="bl-reason">' + escHtml(e.reason || 'No reason') + '</div></div>'
            + '<button class="bl-remove" onclick="removeFromBlacklist(&#39;' + escHtml(e.ssid) + '&#39;)">Remove</button>'
            + '</div>';
    });
    panel.innerHTML = html;
}

async function addToBlacklist() {
    const name = document.getElementById('blNameInput').value.trim();
    const reason = document.getElementById('blReasonInput').value.trim();
    if (!name) return;
    await api('/api/blacklist/add', 'POST', {ssid: name, reason: reason});
    document.getElementById('blNameInput').value = '';
    document.getElementById('blReasonInput').value = '';
    loadBlacklist();
}

async function removeFromBlacklist(ssid) {
    await api('/api/blacklist/remove', 'POST', {ssid: ssid});
    loadBlacklist();
}

// ── VPN Check ──
async function checkVPN() {
    const data = await api('/api/vpn');
    const badge = document.getElementById('vpnBadge');
    const text = document.getElementById('vpnText');
    if (data.active) {
        badge.className = 'vpn-badge vpn-on';
        text.textContent = 'VPN Active';
    } else {
        badge.className = 'vpn-badge vpn-off';
        text.textContent = 'No VPN';
    }
}

// ── WiFi Scan ──
async function runWifiScan() {
    showProgress('Scanning nearby WiFi networks...');
    disableButtons(true);
    try {
        const data = await api('/api/scan/wifi');
        renderNetworks(data.assessments);
        renderFindings(data.assessments);
        updateStats(data.stats);
        loadBlacklist();
    } catch(e) {
        alert('Scan failed: ' + e.message);
    }
    hideProgress();
    disableButtons(false);
}

// ── Port Scan ──
async function runPortScan() {
    showProgress('Scanning local ports (127.0.0.1)...');
    disableButtons(true);
    try {
        const data = await api('/api/scan/ports');
        renderPorts(data.report);
    } catch(e) {
        alert('Port scan failed: ' + e.message);
    }
    hideProgress();
    disableButtons(false);
}

// ── Full Audit ──
async function runFullAudit() {
    showProgress('Running full network audit...');
    disableButtons(true);
    try {
        const data = await api('/api/audit');
        renderNetworks(data.assessments);
        renderFindings(data.assessments);
        updateStats(data.stats);
        renderPorts(data.port_report);
        checkVPN();
    } catch(e) {
        alert('Audit failed: ' + e.message);
    }
    hideProgress();
    disableButtons(false);
}

function disableButtons(disabled) {
    document.querySelectorAll('.btn').forEach(b => b.disabled = disabled);
}

function escHtml(s) {
    if (!s) return '';
    return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Log Viewer ──
let _allLogEntries = [];
let _currentFilter = 'all';

async function loadLogDates() {
    try {
        const data = await api('/api/logs/dates');
        const select = document.getElementById('logDateSelect');
        if (!data.dates || data.dates.length === 0) {
            select.innerHTML = '<option value="">No logs found</option>';
            return;
        }
        let html = '<option value="">— Select a date —</option>';
        data.dates.forEach(d => {
            html += '<option value="' + d + '">' + d + '</option>';
        });
        select.innerHTML = html;
        // Auto-select most recent date
        select.value = data.dates[data.dates.length - 1];
        loadLogForDate();
    } catch(e) {
        console.error('Failed to load log dates', e);
    }
}

async function loadLogForDate() {
    const date = document.getElementById('logDateSelect').value;
    const container = document.getElementById('logEntries');
    const countEl = document.getElementById('logCount');
    if (!date) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">&#128466;</div>Select a date to browse activity logs</div>';
        countEl.textContent = '0';
        return;
    }
    try {
        const data = await api('/api/logs/read?date=' + date);
        _allLogEntries = data.entries || [];
        countEl.textContent = _allLogEntries.length;
        renderLogEntries(_allLogEntries);
    } catch(e) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">&#9888;</div>Failed to load logs</div>';
    }
}

function filterLogs(filter, btn) {
    _currentFilter = filter;
    document.querySelectorAll('.log-filter-btn').forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    if (filter === 'all') {
        renderLogEntries(_allLogEntries);
    } else {
        renderLogEntries(_allLogEntries.filter(e => e.type === filter));
    }
}

function renderLogEntries(entries) {
    const container = document.getElementById('logEntries');
    const countEl = document.getElementById('logCount');
    countEl.textContent = entries.length;

    if (entries.length === 0) {
        container.innerHTML = '<div class="empty-state"><div class="empty-icon">&#128466;</div>No log entries found for this filter</div>';
        return;
    }

    let html = '';
    let lastSession = null;

    entries.forEach((entry, idx) => {
        // Show session separator
        if (entry.session_id && entry.session_id !== lastSession) {
            lastSession = entry.session_id;
            html += '<div class="log-session-header">'
                + '<span>Session <span class="session-id">#' + entry.session_id + '</span></span>'
                + '<span>' + escHtml(entry.session_start || '') + '</span>'
                + '</div>';
        }

        const typeClass = 'log-type-' + entry.type;
        const typeLabels = {wifi:'WiFi', port:'Port', risk:'Risk', enforce:'Enforce', blacklist:'Blacklist', message:'Info'};
        const typeLabel = typeLabels[entry.type] || entry.type;

        html += '<div class="log-entry" data-type="' + entry.type + '">'
            + '<span class="log-time">' + escHtml(entry.time || '') + '</span>'
            + '<span class="log-type-badge ' + typeClass + '">' + typeLabel + '</span>'
            + '<div class="log-msg"><strong>' + escHtml(entry.title || '') + '</strong><br>' + escHtml(entry.summary || '');

        // Expandable detail
        if (entry.detail) {
            const detailId = 'logDetail' + idx;
            html += '<br><button class="log-expand-btn" onclick="toggleLogDetail(\'' + detailId + '\', this)">&#9660; Details</button>'
                + '<div class="log-detail" id="' + detailId + '" style="display:none">' + escHtml(entry.detail) + '</div>';
        }

        html += '</div></div>';
    });

    container.innerHTML = html;
}

function toggleLogDetail(id, btn) {
    const el = document.getElementById(id);
    if (el.style.display === 'none') {
        el.style.display = 'block';
        btn.innerHTML = '&#9650; Hide';
    } else {
        el.style.display = 'none';
        btn.innerHTML = '&#9660; Details';
    }
}

// ── Init ──
checkVPN();
loadBlacklist();
loadLogDates();
</script>
</body>
</html>
"""


# ── API ROUTES ──────────────────────────────────────────────

@app.route("/")
def index():
    """Serve the dashboard HTML."""
    return render_template_string(DASHBOARD_HTML)


@app.route("/api/scan/wifi")
def api_wifi_scan():
    """Run a WiFi scan and return assessed results."""
    networks = wifi_scanner.scan()
    scan_cache["wifi_networks"] = networks
    scan_cache["last_scan_time"] = datetime.now().isoformat()

    # Assess each network
    assessments = []
    for net in networks:
        a = risk_engine.analyze(net)
        assessment_dict = a.to_dict()
        assessment_dict["signal"] = net.signal_strength
        assessments.append(assessment_dict)

    scan_cache["assessments"] = assessments

    # Log
    logger.log_wifi_scan(wifi_scanner.get_results_as_dicts())
    for a_dict in assessments:
        logger.log_assessment(a_dict)

    # Stats
    safe = sum(1 for a in assessments
               if a["risk_level"] == "SAFE")
    moderate = sum(1 for a in assessments
                   if a["risk_level"] == "MODERATE")
    dangerous = sum(1 for a in assessments
                    if a["risk_level"] == "DANGEROUS")

    return jsonify({
        "assessments": assessments,
        "stats": {
            "total": len(assessments),
            "safe": safe,
            "moderate": moderate,
            "dangerous": dangerous,
            "time": datetime.now().strftime("%I:%M %p"),
        }
    })


@app.route("/api/scan/ports")
def api_port_scan():
    """Run a port scan on localhost."""
    report = port_scanner.quick_scan("127.0.0.1")
    scan_cache["port_report"] = report.to_dict()
    logger.log_port_scan(report.to_dict())

    return jsonify({"report": report.to_dict()})


@app.route("/api/audit")
def api_full_audit():
    """Run full audit: WiFi + ports + VPN."""
    # WiFi scan
    networks = wifi_scanner.scan()
    scan_cache["wifi_networks"] = networks
    scan_cache["last_scan_time"] = datetime.now().isoformat()

    # Port scan
    report = port_scanner.quick_scan("127.0.0.1")
    scan_cache["port_report"] = report.to_dict()

    # Assess all networks
    assessments = []
    for net in networks:
        a = risk_engine.analyze(net, report)
        assessment_dict = a.to_dict()
        assessment_dict["signal"] = net.signal_strength
        assessments.append(assessment_dict)

    scan_cache["assessments"] = assessments

    # Log everything
    logger.log_wifi_scan(wifi_scanner.get_results_as_dicts())
    logger.log_port_scan(report.to_dict())
    for a_dict in assessments:
        logger.log_assessment(a_dict)
    logger.log_message("Full audit completed via dashboard")

    # Stats
    safe = sum(1 for a in assessments
               if a["risk_level"] == "SAFE")
    moderate = sum(1 for a in assessments
                   if a["risk_level"] == "MODERATE")
    dangerous = sum(1 for a in assessments
                    if a["risk_level"] == "DANGEROUS")

    return jsonify({
        "assessments": assessments,
        "port_report": report.to_dict(),
        "stats": {
            "total": len(assessments),
            "safe": safe,
            "moderate": moderate,
            "dangerous": dangerous,
            "time": datetime.now().strftime("%I:%M %p"),
        }
    })


@app.route("/api/vpn")
def api_vpn():
    """Check VPN status."""
    active = VPNStatus.is_vpn_active()
    return jsonify({"active": active})


@app.route("/api/blacklist")
def api_blacklist():
    """Get all blacklist entries."""
    return jsonify({
        "entries": blacklist.get_all(),
        "networks": blacklist.get_network_names(),
    })


@app.route("/api/blacklist/add", methods=["POST"])
def api_blacklist_add():
    """Add a network to the blacklist."""
    data = request.get_json()
    ssid = data.get("ssid", "").strip()
    reason = data.get("reason", "").strip()
    if ssid:
        blacklist.add(ssid, reason=reason)
        logger.log_blacklist_change("added", ssid, reason)
        # Reload the risk engine's blacklist
        risk_engine.blacklisted_networks = (
            risk_engine._load_blacklist()
        )
    return jsonify({"ok": True})


@app.route("/api/blacklist/remove", methods=["POST"])
def api_blacklist_remove():
    """Remove a network from the blacklist."""
    data = request.get_json()
    ssid = data.get("ssid", "").strip()
    if ssid:
        blacklist.remove(ssid)
        logger.log_blacklist_change("removed", ssid)
        risk_engine.blacklisted_networks = (
            risk_engine._load_blacklist()
        )
    return jsonify({"ok": True})


@app.route("/api/logs/dates")
def api_log_dates():
    """List available log dates."""
    log_dir = os.path.join(PROJECT_ROOT, "logs")
    if not os.path.isdir(log_dir):
        return jsonify({"dates": []})

    dates = sorted(set(
        f.replace("aegis_", "").rsplit(".", 1)[0]
        for f in os.listdir(log_dir)
        if f.startswith("aegis_") and f.endswith(".json")
    ))
    return jsonify({"dates": dates})


@app.route("/api/logs/read")
def api_log_read():
    """Read and flatten a JSON log file into timeline entries."""
    date = request.args.get("date", "")
    if not date:
        return jsonify({"entries": [], "error": "No date specified"})

    log_path = os.path.join(PROJECT_ROOT, "logs", f"aegis_{date}.json")
    if not os.path.exists(log_path):
        return jsonify({"entries": [], "error": "Log not found"})

    try:
        with open(log_path, encoding="utf-8") as f:
            sessions = json.load(f)
        if not isinstance(sessions, list):
            sessions = [sessions]
    except (json.JSONDecodeError, IOError):
        return jsonify({"entries": [], "error": "Log file corrupt"})

    entries = []
    for s_idx, session in enumerate(sessions, 1):
        s_start = session.get("session_start", "")
        s_label = str(s_idx)

        # WiFi scans
        for scan in session.get("wifi_scans", []):
            ts = scan.get("timestamp", "")
            nets = scan.get("networks", [])
            count = scan.get("network_count", len(nets))
            detail_lines = []
            for n in nets:
                enc = n.get("encryption", "?")
                sig = n.get("signal_strength", 0)
                detail_lines.append(
                    f"{n.get('ssid','?'):<25} {enc:<12} {sig}%"
                )
            entries.append({
                "type": "wifi",
                "time": _short_time(ts),
                "title": f"WiFi Scan — {count} network(s)",
                "summary": ", ".join(
                    n.get("ssid", "?") for n in nets[:5]
                ) + ("..." if len(nets) > 5 else ""),
                "detail": "\n".join(detail_lines) if detail_lines else None,
                "session_id": s_label,
                "session_start": _short_time(s_start),
                "sort_ts": ts,
            })

        # Port scans
        for scan in session.get("port_scans", []):
            ts = scan.get("timestamp", "")
            target = scan.get("target", "?")
            open_count = scan.get("open_port_count", 0)
            total = scan.get("total_scanned", 0)
            detail_lines = []
            for p in scan.get("open_ports", []):
                detail_lines.append(
                    f":{p.get('port','?'):<6} "
                    f"{p.get('service','Unknown'):<15} "
                    f"{p.get('risk_note','')}"
                )
            entries.append({
                "type": "port",
                "time": _short_time(ts),
                "title": f"Port Scan — {target}",
                "summary": f"{open_count} open / {total} scanned",
                "detail": "\n".join(detail_lines) if detail_lines else None,
                "session_id": s_label,
                "session_start": _short_time(s_start),
                "sort_ts": ts,
            })

        # Assessments
        for a in session.get("assessments", []):
            ts = a.get("timestamp", "")
            ssid = a.get("ssid", "?")
            score = a.get("safety_score", "?")
            level = a.get("risk_level", "?")
            findings = a.get("findings", [])
            detail_lines = []
            for f in findings:
                sev = f.get("severity", "?").upper()
                detail_lines.append(
                    f"[{sev}] {f.get('description','')}"
                )
                detail_lines.append(
                    f"  → {f.get('recommendation','')}"
                )
            entries.append({
                "type": "risk",
                "time": _short_time(ts),
                "title": f"{ssid} — {level} ({score}/100)",
                "summary": f"{len(findings)} finding(s)" if findings
                           else "No issues detected",
                "detail": "\n".join(detail_lines) if detail_lines else None,
                "session_id": s_label,
                "session_start": _short_time(s_start),
                "sort_ts": ts,
            })

        # Enforcement actions
        for e in session.get("enforcement_actions", []):
            ts = e.get("timestamp", "")
            entries.append({
                "type": "enforce",
                "time": _short_time(ts),
                "title": f"{e.get('action','?').upper()} — {e.get('ssid','?')}",
                "summary": e.get("details", ""),
                "detail": None,
                "session_id": s_label,
                "session_start": _short_time(s_start),
                "sort_ts": ts,
            })

        # Blacklist changes
        for b in session.get("blacklist_changes", []):
            ts = b.get("timestamp", "")
            entries.append({
                "type": "blacklist",
                "time": _short_time(ts),
                "title": f"Blacklist {b.get('action','?')} — {b.get('ssid','?')}",
                "summary": b.get("reason", "No reason"),
                "detail": None,
                "session_id": s_label,
                "session_start": _short_time(s_start),
                "sort_ts": ts,
            })

    # Sort all entries chronologically
    entries.sort(key=lambda x: x.get("sort_ts", ""))
    # Remove sort key from output
    for e in entries:
        e.pop("sort_ts", None)

    return jsonify({"entries": entries})


def _short_time(iso_str: str) -> str:
    """Convert ISO timestamp to short 'HH:MM:SS' display."""
    if not iso_str:
        return ""
    try:
        dt = datetime.fromisoformat(iso_str)
        return dt.strftime("%I:%M:%S %p")
    except (ValueError, TypeError):
        return iso_str[:19]


# ── ENTRY POINT ─────────────────────────────────────────────

if __name__ == "__main__":
    print()
    print("  ======================================")
    print("   AEGIS WIRELESS — Web Dashboard")
    print("  ======================================")
    print()
    print("  Dashboard running at:")
    print("  http://127.0.0.1:5000")
    print()
    print("  Open this URL in your browser.")
    print("  Press Ctrl+C to stop the server.")
    print()

    app.run(
        host="127.0.0.1",
        port=5000,
        debug=False
    )