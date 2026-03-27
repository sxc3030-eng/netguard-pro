@echo off
:: NetGuard Pro Suite v3.0.0 — Silent Startup (no flashing windows)
:: Launches all modules minimized with pythonw (no console)
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
cd /d "%~dp0"

:: Check for pythonw (no console window)
where pythonw >nul 2>&1
if errorlevel 1 (
    :: Fallback: use python with start /min
    set "PY=python"
    set "LAUNCH=start "" /min /b"
) else (
    set "PY=pythonw"
    set "LAUNCH=start "" /b"
)

:: Also check for embedded Python (installer version)
if exist "%~dp0python\pythonw.exe" (
    set "PY=%~dp0python\pythonw.exe"
    set "LAUNCH=start "" /b"
)

:: 1. NetGuard Pro (main backend + dashboard)
%LAUNCH% "%PY%" "%~dp0netguard.py"

:: Small delay between launches to avoid port conflicts
ping -n 2 127.0.0.1 >nul 2>&1

:: 2. MailShield Pro
if exist "%~dp0mailshield\mailshield.py" (
    %LAUNCH% "%PY%" "%~dp0mailshield\mailshield.py"
)

:: 3. CleanGuard
if exist "%~dp0cleanguard\cleanguard.py" (
    %LAUNCH% "%PY%" "%~dp0cleanguard\cleanguard.py"
)

:: 4. Sentinel OS
if exist "%~dp0sentinel\cortex.py" (
    %LAUNCH% "%PY%" "%~dp0sentinel\cortex.py"
)

:: 5. VPNGuard
if exist "%~dp0vpnguard\vpnguard.py" (
    %LAUNCH% "%PY%" "%~dp0vpnguard\vpnguard.py"
)

:: Exit silently (no pause, no visible window)
exit
