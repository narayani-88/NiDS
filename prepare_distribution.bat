@echo off
echo Preparing NIDS Distribution Package...
echo.

:: Create distribution directory
if not exist "dist" mkdir dist
if not exist "installer" mkdir installer

:: 1. Install required packages
echo [1/4] Installing required packages...
pip install -r requirements.txt
pip install pyinstaller

:: 2. Build the executable
echo [2/4] Building standalone executable...
call build_executable.bat

:: 3. Create installer
echo [3/4] Creating installer (requires Inno Setup)...
"C:\Program Files (x86)\Inno Setup 6\ISCC.exe" create_installer.iss

:: 4. Create ZIP package
echo [4/4] Creating ZIP package...
powershell Compress-Archive -Path "dist\NIDS.exe","templates\*","static\*" -DestinationPath "dist\NIDS-Portable.zip" -Force

echo.
echo Distribution package ready!
echo.
echo Files created:
echo - installer\NIDS-Setup.exe  (For end users)
echo - dist\NIDS-Portable.zip    (Portable version)
echo.
pause
