@echo off
chcp 65001 >nul 2>&1
set PYTHONUTF8=1
title VPN Guard Pro v1.0.0

echo.
echo  ============================================
echo    VPN Guard Pro v1.0.0
echo    VPN WireGuard + Protection
echo  ============================================
echo.

:: -----------------------------------------------
:: ETAPE 1 : Verifier droits administrateur
:: -----------------------------------------------
net session >nul 2>&1
if %errorLevel% neq 0 (
    echo  [!] Droits administrateur requis pour WireGuard.
    echo  [*] Relancement en mode administrateur...
    echo.
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b 0
)
echo  [OK] Droits administrateur confirmes.

:: -----------------------------------------------
:: ETAPE 2 : Verifier Python
:: -----------------------------------------------
python --version >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [!] Python n'est pas installe ou pas dans le PATH.
    echo      Telechargez Python: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)
echo  [OK] Python detecte.

:: -----------------------------------------------
:: ETAPE 3 : Verifier / Installer WireGuard
:: -----------------------------------------------
echo.
echo  [*] Verification de WireGuard...

:: Verifier si wg.exe est dans le PATH
where wg >nul 2>&1
if %errorLevel% equ 0 (
    echo  [OK] WireGuard est installe.
    goto :wg_ready
)

:: Verifier dans Program Files
if exist "C:\Program Files\WireGuard\wg.exe" (
    echo  [OK] WireGuard trouve dans C:\Program Files\WireGuard
    goto :add_path
)

:: WireGuard non trouve - installation automatique
echo.
echo  [!] WireGuard n'est pas installe.
echo  [*] Installation automatique via winget...
echo.

winget install WireGuard.WireGuard --accept-package-agreements --accept-source-agreements --silent 2>nul
if %errorLevel% equ 0 (
    echo.
    echo  [OK] WireGuard installe avec succes !
    timeout /t 3 >nul
    goto :add_path
)

:: Fallback si winget echoue
echo.
echo  [!] Installation automatique echouee.
echo  [*] Tentative de telechargement direct...
echo.

set "WG_INSTALLER=%TEMP%\wireguard-installer.exe"
powershell -Command "try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://download.wireguard.com/windows-client/wireguard-installer.exe' -OutFile '%WG_INSTALLER%' -UseBasicParsing } catch { exit 1 }" 2>nul
if exist "%WG_INSTALLER%" (
    echo  [*] Installateur telecharge, lancement...
    start /wait "" "%WG_INSTALLER%" /S
    timeout /t 3 >nul
    if exist "C:\Program Files\WireGuard\wg.exe" (
        echo  [OK] WireGuard installe !
        del "%WG_INSTALLER%" 2>nul
        goto :add_path
    )
    del "%WG_INSTALLER%" 2>nul
)

:: Tout a echoue
echo.
echo  ---------------------------------------------------
echo    WireGuard n'a pas pu etre installe.
echo.
echo    Installation manuelle :
echo    1. Allez sur https://www.wireguard.com/install/
echo    2. Telechargez le MSI Windows
echo    3. Installez-le
echo    4. Relancez ce script
echo  ---------------------------------------------------
echo.
pause
exit /b 1

:add_path
:: Ajouter au PATH si necessaire
where wg >nul 2>&1
if %errorLevel% neq 0 (
    echo  [*] Ajout de WireGuard au PATH...
    setx PATH "%PATH%;C:\Program Files\WireGuard" /M >nul 2>&1
    set "PATH=%PATH%;C:\Program Files\WireGuard"
    echo  [OK] PATH mis a jour.
)

:wg_ready
echo  [OK] WireGuard pret.

:: -----------------------------------------------
:: ETAPE 4 : Installer dependances Python
:: -----------------------------------------------
echo.
echo  [*] Verification des dependances Python...
python -m pip install websockets pywebview psutil pystray Pillow cryptography >nul 2>&1
echo  [OK] Dependances Python installees.

:: -----------------------------------------------
:: ETAPE 5 : Lancer VPN Guard Pro
:: -----------------------------------------------
echo.
echo  ============================================
echo    Tout est pret ! Lancement...
echo  ============================================
echo.

cd /d "%~dp0vpnguard"
python "%~dp0vpnguard\vpnguard.py"

pause
