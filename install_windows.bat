@echo off
echo Installing NIDS (Network Intrusion Detection System)...
echo.

echo [1/4] Checking Python installation...
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python is not installed. Please install Python 3.8+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

echo [2/4] Installing required packages...
pip install -r requirements.txt
if %ERRORLEVEL% NEQ 0 (
    echo Failed to install required packages.
    pause
    exit /b 1
)

echo [3/4] Creating desktop shortcut...
echo [InternetShortcut] > "%USERPROFILE%\Desktop\NIDS.lnk"
echo URL=http://localhost:5000 >> "%USERPROFILE%\Desktop\NIDS.lnk"

echo [4/4] Installation complete!
echo.
echo To start NIDS, double-click 'start_nids.bat' on your desktop.
echo.
pause
