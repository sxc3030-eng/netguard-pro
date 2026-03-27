@echo off
chcp 65001 >nul 2>&1
title NetGuard Pro — Installation WireGuard
color 0B

:: ── Vérification droits admin ────────────────────────────
net session >nul 2>&1
if errorlevel 1 (
    echo.
    echo  [!] Ce script necessite les droits administrateur.
    echo      Clic-droit ^> Executer en tant qu'administrateur
    echo.
    pause
    exit /b 1
)

echo.
echo  +============================================+
echo  !   NetGuard Pro — Installation WireGuard    !
echo  !   VPN Tunnel Integration                   !
echo  +============================================+
echo.

:: ── Vérifier si déjà installé ────────────────────────────
where wg >nul 2>&1
if not errorlevel 1 (
    echo  [OK] WireGuard est deja installe.
    wg --version 2>nul
    echo.
    goto :setup_keys
)

:: ── Vérifier si wireguard.exe existe dans Program Files ──
if exist "C:\Program Files\WireGuard\wg.exe" (
    echo  [OK] WireGuard trouve dans Program Files.
    goto :add_path
)

:: ── Installation via winget ──────────────────────────────
echo  [1/3] Installation de WireGuard via winget...
echo.
winget install WireGuard.WireGuard --accept-package-agreements --accept-source-agreements 2>nul
if errorlevel 1 (
    echo.
    echo  [!] winget n'a pas pu installer WireGuard.
    echo      Telechargez manuellement: https://www.wireguard.com/install/
    echo      Puis relancez ce script.
    echo.
    pause
    exit /b 1
)

echo.
echo  [OK] WireGuard installe avec succes.

:add_path
:: ── Ajouter au PATH si absent ────────────────────────────
echo  [2/3] Configuration du PATH...
echo %PATH% | findstr /i "WireGuard" >nul 2>&1
if errorlevel 1 (
    setx PATH "%PATH%;C:\Program Files\WireGuard" /M >nul 2>&1
    set "PATH=%PATH%;C:\Program Files\WireGuard"
    echo  [OK] WireGuard ajoute au PATH systeme.
) else (
    echo  [OK] WireGuard deja dans le PATH.
)

:: ── Vérification ─────────────────────────────────────────
echo  [3/3] Verification...
"C:\Program Files\WireGuard\wg.exe" --version 2>nul
if errorlevel 1 (
    echo  [!] wg.exe non trouve. Redemarrez le PC puis relancez.
    pause
    exit /b 1
)
echo  [OK] WireGuard fonctionne.

:setup_keys
echo.
echo  +============================================+
echo  !   Configuration des cles serveur           !
echo  +============================================+
echo.

:: ── Générer les clés serveur si absentes ─────────────────
set "WG_DIR=%~dp0..\wireguard"
if not exist "%WG_DIR%" mkdir "%WG_DIR%"

:: Vérifier si wg0.conf a déjà une clé privée
findstr /i "PrivateKey" "%WG_DIR%\wg0.conf" >nul 2>&1
if not errorlevel 1 (
    findstr /i "VOTRE_CLE_PRIVEE\|YOUR_PRIVATE_KEY\|^PrivateKey = $" "%WG_DIR%\wg0.conf" >nul 2>&1
    if errorlevel 1 (
        echo  [OK] Cles serveur deja configurees.
        goto :done
    )
)

echo  [*] Generation des cles serveur WireGuard...

:: Générer clé privée
"C:\Program Files\WireGuard\wg.exe" genkey > "%WG_DIR%\server_private.key" 2>nul
if errorlevel 1 (
    echo  [!] Erreur generation cle privee. Essai via Python...
    goto :python_keys
)

:: Générer clé publique
type "%WG_DIR%\server_private.key" | "C:\Program Files\WireGuard\wg.exe" pubkey > "%WG_DIR%\server_public.key" 2>nul

set /p PRIV_KEY=<"%WG_DIR%\server_private.key"
set /p PUB_KEY=<"%WG_DIR%\server_public.key"

echo  [OK] Cle privee: %WG_DIR%\server_private.key
echo  [OK] Cle publique: %PUB_KEY%

:: Écrire wg0.conf
(
echo [Interface]
echo PrivateKey = %PRIV_KEY%
echo Address = 10.0.0.1/24
echo ListenPort = 51820
echo DNS = 1.1.1.1, 8.8.8.8
echo.
echo # Les peers seront ajoutes via le dashboard NetGuard Pro
) > "%WG_DIR%\wg0.conf"

echo  [OK] Configuration serveur ecrite: %WG_DIR%\wg0.conf
goto :done

:python_keys
:: Fallback: générer les clés via Python
cd /d "%~dp0.."
python -c "
import os, base64
try:
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    privkey = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    pub_b64 = base64.b64encode(privkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()
except ImportError:
    import subprocess
    subprocess.check_call(['pip', 'install', 'cryptography', '-q'])
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
    privkey = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(privkey.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())).decode()
    pub_b64 = base64.b64encode(privkey.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)).decode()

with open('wireguard/server_private.key', 'w') as f: f.write(priv_b64)
with open('wireguard/server_public.key', 'w') as f: f.write(pub_b64)
conf = f'''[Interface]
PrivateKey = {priv_b64}
Address = 10.0.0.1/24
ListenPort = 51820
DNS = 1.1.1.1, 8.8.8.8

# Les peers seront ajoutes via le dashboard NetGuard Pro
'''
with open('wireguard/wg0.conf', 'w') as f: f.write(conf)
print(f'  [OK] Cles generees via Python (cryptography)')
print(f'  [OK] Cle publique: {pub_b64}')
"

:done
echo.
echo  +============================================+
echo  !   INSTALLATION TERMINEE                    !
echo  +============================================+
echo.
echo   WireGuard est pret pour NetGuard Pro.
echo   Ouvrez le dashboard ^> onglet WireGuard
echo   pour ajouter des peers et demarrer le VPN.
echo.
pause
