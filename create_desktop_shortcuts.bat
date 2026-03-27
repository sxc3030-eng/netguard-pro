@echo off
chcp 65001 >nul 2>&1
title NetGuard Pro — Creation des raccourcis Bureau
cd /d "%~dp0"

echo.
echo  =============================================
echo    NetGuard Pro — Raccourcis Bureau
echo  =============================================
echo.

set "DESKTOP=%USERPROFILE%\OneDrive\Desktop"
if not exist "%DESKTOP%" set "DESKTOP=%USERPROFILE%\Desktop"

set "BASE=%~dp0"

:: Detect Python
set "PYW=pythonw"
if exist "%BASE%python\pythonw.exe" set "PYW=%BASE%python\pythonw.exe"

echo [*] Creation des raccourcis sur: %DESKTOP%
echo.

:: Create shortcuts via PowerShell (most reliable on Windows)

:: 1. StrikeBack (Red Team)
if exist "%BASE%strikeback\strikeback.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\StrikeBack RedTeam.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%strikeback\strikeback.py\"'; $s.WorkingDirectory = '%BASE%strikeback'; $s.Description = 'StrikeBack RedTeam - Reponse Active'; $s.Save()"
    echo   [OK] StrikeBack RedTeam
) else (
    echo   [--] StrikeBack non trouve
)

:: 2. HoneyPot Agent
if exist "%BASE%honeypot\honeypot.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\HoneyPot Agent.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%honeypot\honeypot.py\"'; $s.WorkingDirectory = '%BASE%honeypot'; $s.Description = 'HoneyPot Agent - Detection Intrusion'; $s.Save()"
    echo   [OK] HoneyPot Agent
) else (
    echo   [--] HoneyPot non trouve
)

:: 3. File Integrity Monitor
if exist "%BASE%fim\file_integrity_monitor.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\File Integrity Monitor.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%fim\file_integrity_monitor.py\"'; $s.WorkingDirectory = '%BASE%fim'; $s.Description = 'File Integrity Monitor - Surveillance Fichiers'; $s.Save()"
    echo   [OK] File Integrity Monitor
) else (
    echo   [--] FIM non trouve
)

:: 4. Session Recorder
if exist "%BASE%recorder\recorder.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Session Recorder.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%recorder\recorder.py\"'; $s.WorkingDirectory = '%BASE%recorder'; $s.Description = 'Session Recorder - Enregistrement Sessions'; $s.Save()"
    echo   [OK] Session Recorder
) else (
    echo   [--] Recorder non trouve
)

:: 5. NetGuard Pro (update if exists)
if exist "%BASE%netguard.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\NetGuard Pro.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%netguard.py\"'; $s.WorkingDirectory = '%BASE%'; $s.Description = 'NetGuard Pro - Surveillance Reseau'; $s.Save()"
    echo   [OK] NetGuard Pro (mis a jour)
)

:: 6. Sentinel OS (update if exists)
if exist "%BASE%sentinel\cortex.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Sentinel OS.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%sentinel\cortex.py\"'; $s.WorkingDirectory = '%BASE%sentinel'; $s.Description = 'Sentinel OS - Orchestrateur Central'; $s.Save()"
    echo   [OK] Sentinel OS (mis a jour)
)

:: 7. VPN Guard Pro (update if exists)
if exist "%BASE%vpnguard\vpnguard.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\VPN Guard Pro.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%vpnguard\vpnguard.py\"'; $s.WorkingDirectory = '%BASE%vpnguard'; $s.Description = 'VPN Guard Pro - VPN WireGuard'; $s.Save()"
    echo   [OK] VPN Guard Pro (mis a jour)
)

:: 8. CleanGuard Pro (update if exists)
if exist "%BASE%cleanguard\cleanguard.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\CleanGuard Pro.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%cleanguard\cleanguard.py\"'; $s.WorkingDirectory = '%BASE%cleanguard'; $s.Description = 'CleanGuard Pro - Antimalware'; $s.Save()"
    echo   [OK] CleanGuard Pro (mis a jour)
)

:: 9. MailShield Pro (update if exists)
if exist "%BASE%mailshield\mailshield.py" (
    powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\MailShield Pro.lnk'); $s.TargetPath = '%PYW%'; $s.Arguments = '\"%BASE%mailshield\mailshield.py\"'; $s.WorkingDirectory = '%BASE%mailshield'; $s.Description = 'MailShield Pro - Securite Email'; $s.Save()"
    echo   [OK] MailShield Pro (mis a jour)
)

:: 10. Dashboard (HTML shortcut)
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\NetGuard Dashboard.lnk'); $s.TargetPath = '%BASE%netguard_dashboard.html'; $s.Description = 'NetGuard Pro Dashboard'; $s.Save()"
echo   [OK] NetGuard Dashboard

:: 11. Suite Launcher (all at once)
powershell -Command "$ws = New-Object -ComObject WScript.Shell; $s = $ws.CreateShortcut('%DESKTOP%\Lancer Suite NetGuard.lnk'); $s.TargetPath = '%BASE%startup_all.bat'; $s.WorkingDirectory = '%BASE%'; $s.Description = 'Lancer toute la suite NetGuard Pro'; $s.Save()"
echo   [OK] Lancer Suite NetGuard

echo.
echo  =============================================
echo    Tous les raccourcis ont ete crees !
echo  =============================================
echo.
echo  Raccourcis sur le bureau:
echo    - NetGuard Pro (IDS/Firewall)
echo    - Sentinel OS (Orchestrateur)
echo    - VPN Guard Pro (VPN)
echo    - CleanGuard Pro (Antimalware)
echo    - MailShield Pro (Email)
echo    - StrikeBack RedTeam (Reponse Active)
echo    - HoneyPot Agent (Pieges)
echo    - File Integrity Monitor (Fichiers)
echo    - Session Recorder (Enregistrement)
echo    - NetGuard Dashboard (Web UI)
echo    - Lancer Suite NetGuard (Tout)
echo.
pause
