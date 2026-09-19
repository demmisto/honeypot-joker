@echo off
title HoneyTrap - Honeypot Framework
color 0A

echo.
echo  ================================================
echo   HoneyTrap - Honeypot Framework
echo  ================================================
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo  [!] Python not found. Please install Python 3.9+
    pause
    exit /b 1
)

:: Install dependencies
echo  [*] Installing dependencies...
pip install -r requirements.txt -q

:: Check for admin (needed for ports below 1024 if desired)
echo.
echo  [*] Starting HoneyTrap...
echo  [*] Admin rights may be required for ports below 1024
echo.

python honeypot.py

pause
