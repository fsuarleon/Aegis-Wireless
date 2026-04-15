@echo off
title Aegis Wireless — Launcher
color 0B
:menu
echo.
echo  ===================================================
echo       AEGIS WIRELESS — Launcher
echo  ===================================================
echo.
echo    1  |  CLI Tool         (terminal menu)
echo    2  |  Web Dashboard    (browser GUI)
echo    3  |  System Tray      (background agent)
echo    4  |  Exit
echo.
set /p choice="  Enter choice (1-4): "

if "%choice%"=="1" goto cli
if "%choice%"=="2" goto dashboard
if "%choice%"=="3" goto tray
if "%choice%"=="4" exit /b
echo  Invalid choice. Try again.
goto menu

:cli
cd /d "C:\Users\rylan\Downloads\Test Enviorment\Aegis_Wireless\"
python main.py
goto menu

:dashboard
cd /d "C:\Users\rylan\Downloads\Test Enviorment\Aegis_Wireless\"
echo  Starting dashboard... opening browser.
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000
python dashboard.py
goto menu

:tray
cd /d "C:\Users\rylan\Downloads\Test Enviorment\Aegis_Wireless\"
start /min python tray_agent.py
echo  Tray agent started. Check your taskbar.
timeout /t 3 /nobreak >nul
goto menu
