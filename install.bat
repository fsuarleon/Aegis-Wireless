@echo off
setlocal EnableDelayedExpansion
title Aegis Wireless Installer
color 0B
cd /d "%~dp0"

echo.
echo  =============================================
echo       AEGIS WIRELESS INSTALLER
echo       WiFi Security Analysis Tool
echo  =============================================
echo.

:: ─────────────────────────────────────────────
:: 1. PYTHON CHECK
:: ─────────────────────────────────────────────
echo  [1/6] Checking for Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  ERROR: Python is not installed or not in PATH.
    echo  Download from: https://www.python.org/downloads/
    echo  IMPORTANT: Check "Add Python to PATH" during install.
    echo.
    pause
    exit /b 1
)
for /f "tokens=*" %%i in ('python --version 2^>^&1') do echo  Found: %%i
echo.

:: ─────────────────────────────────────────────
:: 2. PIP CHECK
:: ─────────────────────────────────────────────
echo  [2/6] Checking for pip...
python -m pip --version >nul 2>&1
if errorlevel 1 (
    echo  pip not found — installing...
    python -m ensurepip --upgrade >nul 2>&1
    python -m pip --version >nul 2>&1
    if errorlevel 1 (
        echo  ERROR: Could not install pip. Please install it manually.
        pause
        exit /b 1
    )
)
echo  pip is ready.
echo.

:: ─────────────────────────────────────────────
:: 3. INSTALL DEPENDENCIES
:: ─────────────────────────────────────────────
echo  [3/6] Installing dependencies...
python -m pip install --upgrade pip >nul 2>&1
python -m pip install pystray Pillow plyer winotify pyinstaller
if errorlevel 1 (
    echo.
    echo  ERROR: Dependency installation failed.
    echo  Try running this script as Administrator.
    pause
    exit /b 1
)
echo.
echo  All dependencies installed.
echo.

:: ─────────────────────────────────────────────
:: 4. GENERATE ICON (if missing)
:: ─────────────────────────────────────────────
echo  [4/6] Checking application icon...
if not exist "assets" mkdir assets
if not exist "assets\aegis_icon.ico" (
    if exist "generate_icon.py" (
        python generate_icon.py >nul 2>&1
        if exist "assets\aegis_icon.ico" (
            echo  Icon generated.
        ) else (
            echo  Icon generation failed — app will use fallback.
        )
    ) else (
        echo  No icon generator found — app will use fallback.
    )
) else (
    echo  Icon already exists.
)
echo.

:: ─────────────────────────────────────────────
:: 5. BUILD EXE
:: ─────────────────────────────────────────────
echo  [5/6] Building AegisWireless.exe...
echo  This may take a minute or two...
echo.
python build.py
if errorlevel 1 (
    echo.
    echo  ERROR: Build failed. Check the output above for details.
    pause
    exit /b 1
)

if not exist "dist\AegisWireless.exe" (
    echo.
    echo  ERROR: Build completed but AegisWireless.exe was not found.
    pause
    exit /b 1
)
echo.
echo  Build successful: dist\AegisWireless.exe
echo.

:: ─────────────────────────────────────────────
:: 6. REGISTER STARTUP + LAUNCH
:: ─────────────────────────────────────────────
echo  [6/6] Registering startup and launching...
python -c "import sys; sys.path.insert(0,'.'); from ui.startup import StartupManager; ok=StartupManager.enable(); print('  Startup registered.' if ok else '  Startup skipped (non-critical).')" 2>nul
echo.

echo  =============================================
echo       INSTALLATION COMPLETE
echo  =============================================
echo.
echo  Launching Aegis Wireless...
echo.

start "" "%~dp0dist\AegisWireless.exe"

timeout /t 3 /nobreak >nul
exit /b 0
