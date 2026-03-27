@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title HoneyPot Agent v1.0.0
cd /d "%~dp0"

echo.
echo  +============================================+
echo  !   HoneyPot Agent v1.0.0                   !
echo  !   Detection Intrusion                      !
echo  +============================================+
echo.

if exist "%~dp0python\python.exe" (
    set "PY=%~dp0python\python.exe"
    goto :launch
)

python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python non installe.
    pause & exit /b 1
)
set "PY=python"

echo [*] Verification des dependances...
%PY% -m pip install --quiet --no-warn-script-location websockets >nul 2>&1

:launch
echo [*] Demarrage HoneyPot Agent...
%PY% "%~dp0honeypot\honeypot.py"
pause
