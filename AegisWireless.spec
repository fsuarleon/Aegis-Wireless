# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\rylan\\downloads\\Aegis_Wireless\\aegis_tray.pyw'],
    pathex=[],
    binaries=[],
    datas=[('config', 'config'), ('assets', 'assets'), ('ui', 'ui'), ('scanner', 'scanner'), ('core', 'core'), ('network', 'network'), ('api', 'api')],
    hiddenimports=['ui', 'ui.tray', 'ui.notifications', 'ui.startup', 'scanner.wifi_scan', 'scanner.port_probe', 'core.engine', 'core.blacklist', 'network.enforcement', 'network.vpn_tunnel', 'api.telemetry', 'winotify', 'plyer', 'pystray'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AegisWireless',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['C:\\Users\\rylan\\downloads\\Aegis_Wireless\\assets\\aegis_icon.ico'],
)
