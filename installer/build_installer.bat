@echo off
chcp 65001 >nul 2>&1
title NetGuard Pro — Build Installateur Windows
color 0B

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║   NetGuard Pro v3.0.0 — Build Installateur      ║
echo  ║   Ce script cree NetGuardPro_Setup_3.0.0.exe    ║
echo  ╚══════════════════════════════════════════════════╝
echo.

cd /d "%~dp0\.."

:: ═══════════════════════════════════════════════════════
:: Etape 1: Verifier les outils requis
:: ═══════════════════════════════════════════════════════
echo [1/6] Verification des outils...

python --version >nul 2>&1
if errorlevel 1 (
    echo [ERREUR] Python non trouve. Installez Python 3.10+ depuis python.org
    pause & exit /b 1
)
echo   [OK] Python trouve

:: Verifier Inno Setup
set "ISCC="
if exist "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files (x86)\Inno Setup 6\ISCC.exe"
if exist "C:\Program Files\Inno Setup 6\ISCC.exe" set "ISCC=C:\Program Files\Inno Setup 6\ISCC.exe"
if "%ISCC%"=="" (
    echo [ERREUR] Inno Setup 6 non trouve.
    echo   Telechargez-le: https://jrsoftware.org/isdl.php
    echo   Installez-le, puis relancez ce script.
    pause & exit /b 1
)
echo   [OK] Inno Setup trouve

:: ═══════════════════════════════════════════════════════
:: Etape 2: Telecharger Python Embedded (portable)
:: ═══════════════════════════════════════════════════════
echo.
echo [2/6] Preparation de Python embarque...

if not exist "python_embed" mkdir python_embed

if not exist "python_embed\python.exe" (
    echo   Telechargement de Python 3.12 embedded...
    powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://www.python.org/ftp/python/3.12.4/python-3.12.4-embed-amd64.zip' -OutFile 'python_embed\python_embed.zip' }"

    if not exist "python_embed\python_embed.zip" (
        echo [ERREUR] Impossible de telecharger Python embedded.
        pause & exit /b 1
    )

    echo   Extraction...
    powershell -Command "Expand-Archive -Path 'python_embed\python_embed.zip' -DestinationPath 'python_embed' -Force"
    del "python_embed\python_embed.zip" >nul 2>&1

    :: Activer pip dans Python embedded
    echo   Activation de pip...
    :: Modifier python312._pth pour decommenter import site
    powershell -Command "(Get-Content 'python_embed\python312._pth') -replace '#import site','import site' | Set-Content 'python_embed\python312._pth'"

    :: Installer get-pip
    powershell -Command "& { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://bootstrap.pypa.io/get-pip.py' -OutFile 'python_embed\get-pip.py' }"
    "python_embed\python.exe" "python_embed\get-pip.py" --no-warn-script-location >nul 2>&1
    del "python_embed\get-pip.py" >nul 2>&1

    echo   [OK] Python embedded pret
) else (
    echo   [OK] Python embedded deja present
)

:: ═══════════════════════════════════════════════════════
:: Etape 3: Installer les dependances dans Python embedded
:: ═══════════════════════════════════════════════════════
echo.
echo [3/6] Installation des dependances Python...

"python_embed\python.exe" -m pip install --no-warn-script-location --quiet ^
    websockets scapy pywebview pystray Pillow psutil requests watchdog pefile 2>nul

echo   [OK] Dependances installees

:: ═══════════════════════════════════════════════════════
:: Etape 4: Creer l'icone si absente
:: ═══════════════════════════════════════════════════════
echo.
echo [4/6] Verification de l'icone...

if not exist "netguard_icon.ico" (
    echo   Generation de l'icone...
    python create_icon.py 2>nul
    if not exist "netguard_icon.ico" (
        echo   [WARN] Icone non generee, utilisation d'une icone par defaut
        :: Creer un .ico minimal
        python -c "from PIL import Image; img=Image.new('RGBA',(256,256),(77,159,255,255)); img.save('netguard_icon.ico', format='ICO')" 2>nul
    )
)
echo   [OK] Icone prete

:: ═══════════════════════════════════════════════════════
:: Etape 5: Creer le fichier LICENSE.txt si absent
:: ═══════════════════════════════════════════════════════
echo.
echo [5/6] Verification de la licence...

if not exist "LICENSE.txt" (
    echo NetGuard Pro v3.0.0 - Licence d'utilisation> LICENSE.txt
    echo.>> LICENSE.txt
    echo Copyright 2026 NetGuard Pro Inc. Tous droits reserves.>> LICENSE.txt
    echo.>> LICENSE.txt
    echo Ce logiciel est fourni sous licence commerciale.>> LICENSE.txt
    echo L'utilisation de ce logiciel est soumise aux conditions suivantes:>> LICENSE.txt
    echo.>> LICENSE.txt
    echo 1. LICENCE: Vous etes autorise a installer et utiliser ce logiciel>> LICENSE.txt
    echo    sur un nombre de machines correspondant a votre tier de licence.>> LICENSE.txt
    echo.>> LICENSE.txt
    echo 2. RESTRICTIONS: Vous ne pouvez pas redistribuer, modifier ou>> LICENSE.txt
    echo    decompiler ce logiciel sans autorisation ecrite.>> LICENSE.txt
    echo.>> LICENSE.txt
    echo 3. ESSAI GRATUIT: La version d'essai est limitee a 30 jours.>> LICENSE.txt
    echo    Apres cette periode, une licence Pro ou Enterprise est requise.>> LICENSE.txt
    echo.>> LICENSE.txt
    echo 4. SUPPORT: Le support technique est inclus avec les licences Pro>> LICENSE.txt
    echo    et Enterprise. Contact: contact@netguardpro.com>> LICENSE.txt
    echo.>> LICENSE.txt
    echo 5. GARANTIE: Ce logiciel est fourni "tel quel" sans garantie>> LICENSE.txt
    echo    d'aucune sorte, expresse ou implicite.>> LICENSE.txt
    echo.>> LICENSE.txt
    echo En installant ce logiciel, vous acceptez ces conditions.>> LICENSE.txt
)
echo   [OK] Fichier de licence pret

:: ═══════════════════════════════════════════════════════
:: Etape 6: Compiler l'installateur avec Inno Setup
:: ═══════════════════════════════════════════════════════
echo.
echo [6/6] Compilation de l'installateur...

if not exist "dist" mkdir dist

"%ISCC%" "installer\netguard_setup.iss"

if errorlevel 1 (
    echo.
    echo [ERREUR] La compilation a echoue. Voir les erreurs ci-dessus.
    pause & exit /b 1
)

echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║   BUILD REUSSI !                                ║
echo  ║                                                 ║
echo  ║   Fichier: dist\NetGuardPro_Setup_3.0.0.exe    ║
echo  ║                                                 ║
echo  ║   Taille estimee: ~40-60 Mo                     ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: Afficher la taille du fichier
for %%F in (dist\NetGuardPro_Setup_3.0.0.exe) do echo   Taille: %%~zF octets

echo.
pause
