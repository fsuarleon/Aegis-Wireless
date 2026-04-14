"""
aegis_tray.pyw — Windowless Tray Launcher
============================================
Double-click this file to start Aegis Wireless in system tray
mode with NO console window.

The .pyw extension makes Windows use pythonw.exe automatically.
"""

import sys
import os

# ── Add project root to path ──
_DIR = os.path.dirname(os.path.abspath(__file__))
if _DIR not in sys.path:
    sys.path.insert(0, _DIR)

from ui.tray import AegisTray

if __name__ == "__main__":
    tray = AegisTray()
    tray.run()