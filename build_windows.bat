@echo off
REM Build the Argus Windows desktop app (Argus.exe + zip).
REM Needs: Windows, Python 3 (py launcher), internet for pip.
REM Run by double-clicking this file in the repo folder.
setlocal
cd /d "%~dp0"

if not exist ".venv-desktop\Scripts\python.exe" (
    py -3 -m venv .venv-desktop
    if errorlevel 1 exit /b 1
)

".venv-desktop\Scripts\python.exe" -m pip install --upgrade pip
if errorlevel 1 exit /b 1
".venv-desktop\Scripts\python.exe" -m pip install -r ArgusDesktop-requirements.txt
if errorlevel 1 exit /b 1
".venv-desktop\Scripts\pyinstaller.exe" --noconfirm --clean ArgusDesktop.spec
if errorlevel 1 exit /b 1

powershell -NoProfile -Command "Compress-Archive -Path 'dist\Argus' -DestinationPath 'dist\Argus-Windows.zip' -Force"
if errorlevel 1 exit /b 1

echo.
echo Build complete: dist\Argus-Windows.zip
echo Extract the zip and run Argus\Argus.exe
endlocal
