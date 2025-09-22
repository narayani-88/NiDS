@echo off
echo Starting NIDS (Network Intrusion Detection System)...
echo Please wait, this may take a moment...
echo.

start http://localhost:5000

python -m flask run --host=0.0.0.0 --port=5000

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo Failed to start NIDS. Make sure all dependencies are installed.
    echo Run 'install_windows.bat' first if you haven't already.
    pause
    exit /b 1
)
