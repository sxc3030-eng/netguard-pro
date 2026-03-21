@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
set PYTHONIOENCODING=utf-8
title MailShield Pro - Client Email Securise
color 0B
echo.
echo  ========================================
echo       MailShield Pro v2.0.0
echo       Client Email Securise
echo  ========================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [!] Python n'est pas installe ou pas dans le PATH.
    echo     Telechargez Python sur https://python.org
    pause
    exit /b 1
)

:: Install dependencies silently
echo [*] Verification des dependances...
python -c "import websockets" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installation de websockets...
    pip install websockets >nul 2>&1
)
python -c "import msal" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] Installation de msal...
    pip install msal >nul 2>&1
)
echo [+] Dependances OK.

:: Kill any existing MailShield on ports 8800/8801
echo [*] Nettoyage des anciennes instances...
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8800 " ^| findstr "LISTENING" 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)
for /f "tokens=5" %%a in ('netstat -ano ^| findstr ":8801 " ^| findstr "LISTENING" 2^>nul') do (
    taskkill /PID %%a /F >nul 2>&1
)
timeout /t 1 >nul 2>&1

echo.
echo [+] Demarrage de MailShield Pro...
echo [+] Le dashboard s'ouvrira dans votre navigateur.
echo [+] Appuyez sur Ctrl+C pour arreter.
echo.

cd /d "%~dp0mailshield"
python "%~dp0mailshield\mailshield.py"

echo.
echo [!] MailShield s'est arrete.
echo.
pause
