"""
build.py — Compile Aegis Wireless into AegisWireless.exe
Run once:   python build.py
Creates:    dist/AegisWireless.exe
"""

import PyInstaller.__main__
import os

app_dir = os.path.dirname(os.path.abspath(__file__))
icon_path = os.path.join(app_dir, "assets", "aegis_icon.ico")

args = [
    os.path.join(app_dir, "aegis_tray.pyw"),
    "--name=AegisWireless",
    "--onefile",
    "--noconsole",
    "--add-data", f"config{os.pathsep}config",
    "--add-data", f"assets{os.pathsep}assets",
    "--add-data", f"ui{os.pathsep}ui",
    "--add-data", f"scanner{os.pathsep}scanner",
    "--add-data", f"core{os.pathsep}core",
    "--add-data", f"network{os.pathsep}network",
    "--add-data", f"api{os.pathsep}api",
    "--hidden-import", "ui",
    "--hidden-import", "ui.tray",
    "--hidden-import", "ui.notifications",
    "--hidden-import", "ui.startup",
    "--hidden-import", "scanner.wifi_scan",
    "--hidden-import", "scanner.port_probe",
    "--hidden-import", "core.engine",
    "--hidden-import", "core.blacklist",
    "--hidden-import", "network.enforcement",
    "--hidden-import", "network.vpn_tunnel",
    "--hidden-import", "api.telemetry",
    "--hidden-import", "winotify",
    "--hidden-import", "plyer",
    "--hidden-import", "pystray",
]

if os.path.isfile(icon_path):
    args.append(f"--icon={icon_path}")

PyInstaller.__main__.run(args)

print("\n  Done! Your exe is at:  dist/AegisWireless.exe")