@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title CleanGuard Pro v1.0.0

echo.
echo  ╔══════════════════════════════════════════╗
echo  ║      CleanGuard Pro v1.0.0               ║
echo  ║      Nettoyeur + Antivirus               ║
echo  ╚══════════════════════════════════════════╝
echo.

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [!] Python n'est pas installe ou pas dans le PATH.
    echo     Telechargez Python: https://www.python.org/downloads/
    pause
    exit /b 1
)

:: Install dependencies (pywebview for native window)
echo [*] Verification des dependances...
python -m pip install websockets psutil watchdog pywebview pystray Pillow >nul 2>&1

:: Launch CleanGuard (pywebview opens its own window, no browser needed)
echo [*] Demarrage de CleanGuard Pro...
cd /d "%~dp0cleanguard"
python "%~dp0cleanguard\cleanguard.py"

pause
