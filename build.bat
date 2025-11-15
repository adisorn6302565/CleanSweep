@echo off
REM Build CleanSweep single-file executable with PyInstaller
set ICON=assets\app.ico
set ICON_FLAG=

if exist "%ICON%" (
  set ICON_FLAG=--icon="%ICON%"
) else (
  echo [WARN] Icon file not found at %ICON%. Building without custom icon.
)

pyinstaller --name CleanSweep --onefile --windowed %ICON_FLAG% main.py

echo.
echo Build finished. Check the dist\ directory for CleanSweep.exe
echo.
