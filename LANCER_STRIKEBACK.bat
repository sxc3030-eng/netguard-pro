@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title StrikeBack RedTeam v1.0.0
cd /d "%~dp0"

echo.
echo  +============================================+
echo  !   StrikeBack RedTeam v1.0.0               !
echo  !   Reponse Active                           !
echo  +============================================+
echo.

:: Check for embedded Python first
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
%PY% -m pip install --quiet --no-warn-script-location websockets psutil >nul 2>&1

:launch
echo [*] Demarrage StrikeBack RedTeam...
%PY% "%~dp0strikeback\strikeback.py"
pause
