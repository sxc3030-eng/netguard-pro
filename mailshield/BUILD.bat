@echo off
title MailShield Pro - Build Executable
echo.
echo  ==========================================
echo  |  MailShield Pro - Build v2.0.0         |
echo  ==========================================
echo.

:: Check Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERREUR] Python non trouve. Installez Python 3.9+
    pause
    exit /b 1
)

:: Install dependencies
echo [1/3] Installation des dependances...
pip install -r requirements.txt --quiet
pip install pyinstaller --quiet

:: Build
echo [2/3] Construction de l'executable...
pyinstaller --onefile ^
    --name MailShieldPro ^
    --add-data "mailshield_dashboard.html;." ^
    --add-data "mailshield_settings.json;." ^
    --hidden-import msal ^
    --hidden-import websockets ^
    --hidden-import asyncio ^
    --clean ^
    --noconfirm ^
    mailshield.py

if %errorlevel% neq 0 (
    echo.
    echo [ERREUR] La construction a echoue.
    pause
    exit /b 1
)

:: Copy config file to dist
echo [3/3] Preparation du package...
copy mailshield_settings.json dist\ >nul 2>&1
copy mailshield_dashboard.html dist\ >nul 2>&1

echo.
echo  ==========================================
echo  |  BUILD TERMINE !                       |
echo  |  Executable: dist\MailShieldPro.exe    |
echo  ==========================================
echo.
echo  Pour distribuer, copiez le dossier 'dist'
echo  avec les fichiers suivants :
echo    - MailShieldPro.exe
echo    - mailshield_settings.json
echo    - mailshield_dashboard.html
echo.
pause
