@echo off
echo Creating NIDS standalone executable...
echo This may take a few minutes...

:: Install PyInstaller if not installed
pip install pyinstaller

:: Create the executable
pyinstaller --onefile --windowed --name NIDS --add-data "templates;templates" --add-data "static;static" --icon=static/favicon.ico app.py

echo.
echo Build complete! Find NIDS.exe in the 'dist' folder.
pause
