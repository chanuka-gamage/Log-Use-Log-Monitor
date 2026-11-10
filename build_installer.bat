@echo off
rem ============================================================================
rem  LOG USE - one-click builder.  Double-click this file on a Windows 10/11 PC.
rem  It installs every Python library, builds the app, and creates the setup EXE:
rem        installer_output\LOG-USE-Setup.exe
rem ============================================================================
setlocal EnableDelayedExpansion
set "SILENT=0"
if /i "%~1"=="/silent" set "SILENT=1"
cd /d "%~dp0"
rem Double-clicking this file starts the invisible builder (no console, no pip output).
rem Use "build_installer.bat /show" only if you want to watch the console.
if /i not "%~1"=="/silent" if /i not "%~1"=="/show" (
  start "" wscript.exe "%~dp0Build_LOG_USE_Setup.vbs"
  exit /b 0
)
title LOG USE - building installer

echo.
echo [1/5] Looking for Python 3.11 / 3.12 / 3.13 ...
set "PY="
for %%V in (3.12 3.11 3.13) do (
  if not defined PY (
    py -%%V -c "import sys" >nul 2>&1 && set "PY=py -%%V"
  )
)
if not defined PY (
  echo Python was not found. Installing Python 3.12 with winget ...
  winget install -e --id Python.Python.3.12 --silent --accept-package-agreements --accept-source-agreements
  set "PY=py -3.12"
)
%PY% -c "import tkinter" >nul 2>&1
if errorlevel 1 (
  echo ERROR: this Python has no Tkinter. Re-install Python from python.org and keep "tcl/tk" ticked.
  call :fail & exit /b 1
)

echo.
echo [2/5] Creating virtual environment and installing ALL Python libraries ...
if not exist ".venv" %PY% -m venv .venv
call ".venv\Scripts\activate.bat"
python -m pip install --quiet --disable-pip-version-check --upgrade pip
pip install --quiet --disable-pip-version-check --no-input -r requirements.txt
if errorlevel 1 ( echo ERROR: library installation failed. & call :fail & exit /b 1 )

echo.
echo [3/5] Building LOG USE.exe (Python + all libraries are bundled inside) ...
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist
pyinstaller --log-level ERROR --noconfirm --clean --onedir --windowed --name "LOG USE" ^
  --icon "assets\log_use.ico" --version-file version_info.txt --add-data "assets;assets" ^
  --collect-all cv2 --hidden-import psutil --hidden-import winreg ^
  main.py
if errorlevel 1 ( echo ERROR: PyInstaller failed. & call :fail & exit /b 1 )

echo.
echo [4/5] Looking for Inno Setup ...
set "ISCC="
for %%P in ("%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "%ProgramFiles%\Inno Setup 6\ISCC.exe" "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe") do (
  if exist %%P set "ISCC=%%~P"
)
if not defined ISCC (
  echo Installing Inno Setup with winget ...
  winget install -e --id JRSoftware.InnoSetup --silent --accept-package-agreements --accept-source-agreements
  for %%P in ("%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" "%ProgramFiles%\Inno Setup 6\ISCC.exe" "%LocalAppData%\Programs\Inno Setup 6\ISCC.exe") do (
    if exist %%P set "ISCC=%%~P"
  )
)
if not defined ISCC (
  echo ERROR: Inno Setup not found. Install it from https://jrsoftware.org/isdl.php and run this file again.
  call :fail & exit /b 1
)

echo.
echo [5/5] Creating the setup installer ...
"%ISCC%" installer.iss
if errorlevel 1 ( echo ERROR: Inno Setup failed. & call :fail & exit /b 1 )

echo.
echo [6/6] Creating the Windows App Installer package (MSIX) ...
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0build_msix.ps1" -Root "%~dp0."
if errorlevel 1 echo MSIX_FAILED: the App Installer package could not be created. See the PowerShell error above. The classic LOG-USE-Setup.exe is still ready.

echo.
echo ============================================================================
echo  DONE.  Your installer is:  %~dp0installer_output\LOG-USE-Setup.exe
echo ============================================================================
if "%SILENT%"=="0" ( explorer "%~dp0installer_output" & pause )
exit /b 0

:fail
if "%SILENT%"=="0" pause
exit /b 1
