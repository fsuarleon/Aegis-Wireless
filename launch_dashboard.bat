@echo off
title Aegis Wireless — Web Dashboard
cd /d "C:\Users\rylan\Downloads\Test Enviorment\Aegis_Wireless\"
echo.
echo  Starting Aegis Wireless Dashboard...
echo  Your browser will open automatically.
echo  Press Ctrl+C in this window to stop.
echo.
timeout /t 2 /nobreak >nul
start http://127.0.0.1:5000
python dashboard.py
pause
