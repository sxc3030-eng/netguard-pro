@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title NetGuard Pro v3.0.0
cd /d "%~dp0"

echo.
echo  +============================================+
echo  !      NetGuard Pro v3.0.0                   !
echo  !      Surveillance Reseau                   !
echo  +============================================+
echo.

:: Check for embedded Python first (installer version)
if exist "%~dp0python\python.exe" (
    echo [OK] Python embarque detecte
    set "PY=%~dp0python\python.exe"
    set "PYW=%~dp0python\pythonw.exe"
    goto :launch
)

:: Check system Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python n'est pas installe ou pas dans le PATH.
    echo     Telechargez Python: https://www.python.org/downloads/
    echo.
    echo     Ou installez NetGuard Pro avec l'installateur:
    echo     installer\build_installer.bat
    pause
    exit /b 1
)

set "PY=python"
set "PYW=pythonw"

:: Install dependencies
echo [*] Verification des dependances...
%PY% -m pip install --quiet --no-warn-script-location scapy websockets pywebview pystray Pillow psutil >nul 2>&1
echo [OK] Dependances verifiees

:launch
echo [*] Demarrage de NetGuard Pro...
echo.

:: Use pythonw to avoid flashing console window after launch
:: But first run with python to show any startup errors
%PY% "%~dp0netguard.py"

:: If we get here, the program exited
echo.
echo [!] NetGuard Pro s'est arrete.
pause
