@echo off
title Aegis Wireless — Installer
color 0B

echo.
echo  =============================================
echo       AEGIS WIRELESS — INSTALLER
echo       WiFi Security Analysis Tool
echo  =============================================
echo.

:: ── Check for Python ──
echo  [1/5] Checking for Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: Python is not installed or not in PATH.
    echo  Download Python from: https://www.python.org/downloads/
    echo  IMPORTANT: Check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo  Found: %%i
echo.

:: ── Check for pip ──
echo  [2/5] Checking for pip...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo  Installing pip...
    python -m ensurepip --upgrade
)
echo  pip is available.
echo.

:: ── Install dependencies ──
echo  [3/5] Installing dependencies...
echo.
python -m pip install --upgrade pip >nul 2>&1
python -m pip install pystray Pillow plyer winotify pyinstaller
echo.
echo  Dependencies installed.
echo.

:: ── Generate icon ──
echo  [4/5] Generating application icon...
if not exist "assets" mkdir assets
if not exist "assets\aegis_icon.ico" (
    python generate_icon.py 2>nul
    if exist "assets\aegis_icon.ico" (
        echo  Icon generated successfully.
    ) else (
        echo  Icon generation skipped (generate_icon.py not found).
        echo  The app will use a built-in fallback icon.
    )
) else (
    echo  Icon already exists — skipping.
)
echo.

:: ── Register startup ──
echo  [5/5] Configuring startup...
python -c "import sys; sys.path.insert(0,'.'); from ui.startup import StartupManager; ok=StartupManager.enable(); print('  Startup registered.' if ok else '  Startup registration skipped.')" 2>nul
echo.

:: ── Done ──
echo  =============================================
echo       INSTALLATION COMPLETE
echo  =============================================
echo.
echo  How to launch:
echo    Double-click:  aegis_tray.pyw
echo    Terminal mode:  python main.py --cli
echo    Build EXE:      python build.py
echo.
echo  Aegis will also start automatically on login.
echo.

:: ── Launch now? ──
set /p LAUNCH="  Launch Aegis Wireless now? (Y/N): "
if /i "%LAUNCH%"=="Y" (
    echo.
    echo  Starting Aegis Wireless...
    start "" pythonw aegis_tray.pyw
)

echo.
pause