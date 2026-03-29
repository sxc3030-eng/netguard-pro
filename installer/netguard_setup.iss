; NetGuard Pro v3.0.0 — Inno Setup Installer Script
; Compile with Inno Setup 6.x : https://jrsoftware.org/isdl.php
; Produit: NetGuardPro_Setup_3.0.0.exe

#define MyAppName "NetGuard Pro"
#define MyAppVersion "3.0.0"
#define MyAppPublisher "NetGuard Pro Inc."
#define MyAppURL "https://sxc3030-eng.github.io/netguard-pro"
#define MyAppExeName "NetGuardPro.exe"

[Setup]
AppId={{A1B2C3D4-E5F6-7890-ABCD-EF1234567890}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
DefaultDirName={autopf}\NetGuard Pro
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
LicenseFile=..\LICENSE.txt
OutputDir=..\dist
OutputBaseFilename=NetGuardPro_Setup_{#MyAppVersion}
SetupIconFile=..\netguard_icon.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
WizardSizePercent=120
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
UninstallDisplayIcon={app}\netguard_icon.ico
UninstallDisplayName={#MyAppName}
VersionInfoVersion={#MyAppVersion}.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription=NetGuard Pro - Suite de Cybersecurite
VersionInfoProductName={#MyAppName}
MinVersion=10.0

[Languages]
Name: "french"; MessagesFile: "compiler:Languages\French.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[Messages]
french.BeveledLabel=NetGuard Pro - Cybersecurite Professionnelle
english.BeveledLabel=NetGuard Pro - Professional Cybersecurity

[CustomMessages]
french.InstallingPython=Installation de Python embarque...
french.InstallingDeps=Installation des dependances...
french.ConfiguringFirewall=Configuration du pare-feu Windows...
french.CreatingService=Creation du service Windows...
french.LaunchAfterInstall=Lancer NetGuard Pro apres l'installation
french.CreateDesktopIcon=Creer un raccourci sur le Bureau
french.InstallService=Installer comme service Windows (demarrage automatique)
french.ComponentMain=NetGuard Pro (IDS/Firewall)
french.ComponentSentinel=Sentinel OS (Orchestrateur)
french.ComponentVPN=VPN Guard Pro (WireGuard)
french.ComponentClean=CleanGuard (Anti-malware)
french.ComponentMail=MailShield Pro (Securite email)
french.ComponentHoney=HoneyPot Agent (Detection intrusion)
french.ComponentFIM=File Integrity Monitor
french.ComponentRecorder=Session Recorder
french.ComponentStrike=StrikeBack (Reponse active)
english.InstallingPython=Installing embedded Python...
english.InstallingDeps=Installing dependencies...
english.ConfiguringFirewall=Configuring Windows Firewall...
english.CreatingService=Creating Windows service...
english.LaunchAfterInstall=Launch NetGuard Pro after installation
english.CreateDesktopIcon=Create a desktop shortcut
english.InstallService=Install as Windows service (auto-start)
english.ComponentMain=NetGuard Pro (IDS/Firewall)
english.ComponentSentinel=Sentinel OS (Orchestrator)
english.ComponentVPN=VPN Guard Pro (WireGuard)
english.ComponentClean=CleanGuard (Anti-malware)
english.ComponentMail=MailShield Pro (Email Security)
english.ComponentHoney=HoneyPot Agent (Intrusion Detection)
english.ComponentFIM=File Integrity Monitor
english.ComponentRecorder=Session Recorder
english.ComponentStrike=StrikeBack (Active Response)

[Types]
Name: "full"; Description: "Installation complete (recommandee)"
Name: "pro"; Description: "Pro — 15 applications"
Name: "minimal"; Description: "Installation minimale (IDS seulement)"
Name: "custom"; Description: "Installation personnalisee"; Flags: iscustom

[Components]
Name: "main"; Description: "{cm:ComponentMain}"; Types: full pro minimal custom; Flags: fixed
Name: "sentinel"; Description: "{cm:ComponentSentinel}"; Types: full pro
Name: "vpnguard"; Description: "{cm:ComponentVPN}"; Types: full pro
Name: "cleanguard"; Description: "{cm:ComponentClean}"; Types: full pro
Name: "mailshield"; Description: "{cm:ComponentMail}"; Types: full pro
Name: "honeypot"; Description: "{cm:ComponentHoney}"; Types: full
Name: "fim"; Description: "{cm:ComponentFIM}"; Types: full
Name: "recorder"; Description: "{cm:ComponentRecorder}"; Types: full
Name: "strikeback"; Description: "{cm:ComponentStrike}"; Types: full

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "Options:"
Name: "autostart"; Description: "{cm:InstallService}"; GroupDescription: "Options:"
Name: "firewall"; Description: "Configurer le pare-feu Windows"; GroupDescription: "Options:"; Flags: checkedonce

[Files]
; Python embedded (pre-packaged)
Source: "..\python_embed\*"; DestDir: "{app}\python"; Flags: ignoreversion recursesubdirs createallsubdirs
; Main application
Source: "..\netguard.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\license_manager.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\startup_utils.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\netguard_tray.py"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\netguard_settings.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
Source: "..\netguard_users.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
Source: "..\netguard_license.json"; DestDir: "{app}"; Flags: ignoreversion onlyifdoesntexist
; All HTML dashboards
Source: "..\*.html"; DestDir: "{app}"; Flags: ignoreversion
; Icon
Source: "..\netguard_icon.ico"; DestDir: "{app}"; Flags: ignoreversion
; Sentinel
Source: "..\sentinel\*"; DestDir: "{app}\sentinel"; Components: sentinel; Flags: ignoreversion recursesubdirs createallsubdirs
; VPN Guard
Source: "..\vpnguard\*"; DestDir: "{app}\vpnguard"; Components: vpnguard; Flags: ignoreversion recursesubdirs createallsubdirs
; CleanGuard
Source: "..\cleanguard\*"; DestDir: "{app}\cleanguard"; Components: cleanguard; Flags: ignoreversion recursesubdirs createallsubdirs
; MailShield
Source: "..\mailshield\*"; DestDir: "{app}\mailshield"; Components: mailshield; Flags: ignoreversion recursesubdirs createallsubdirs
; HoneyPot
Source: "..\honeypot\*"; DestDir: "{app}\honeypot"; Components: honeypot; Flags: ignoreversion recursesubdirs createallsubdirs
; FIM
Source: "..\fim\*"; DestDir: "{app}\fim"; Components: fim; Flags: ignoreversion recursesubdirs createallsubdirs
; Recorder
Source: "..\recorder\*"; DestDir: "{app}\recorder"; Components: recorder; Flags: ignoreversion recursesubdirs createallsubdirs
; StrikeBack
Source: "..\strikeback\*"; DestDir: "{app}\strikeback"; Components: strikeback; Flags: ignoreversion recursesubdirs createallsubdirs
; WireGuard configs
Source: "..\wireguard\*"; DestDir: "{app}\wireguard"; Components: vpnguard; Flags: ignoreversion recursesubdirs createallsubdirs
; Reports & captures dirs
Source: "..\reports\files\*"; DestDir: "{app}\reports\files"; Flags: ignoreversion recursesubdirs createallsubdirs
; Batch launchers (hidden, used internally)
Source: "..\*.bat"; DestDir: "{app}"; Flags: ignoreversion
Source: "..\*.sh"; DestDir: "{app}"; Flags: ignoreversion
; Post-install setup script
Source: "post_install.bat"; DestDir: "{app}\installer"; Flags: ignoreversion deleteafterinstall

[Dirs]
Name: "{app}\captures"
Name: "{app}\reports"
Name: "{app}\backups"
Name: "{app}\logs"

[Icons]
Name: "{group}\NetGuard Pro"; Filename: "{app}\python\pythonw.exe"; Parameters: """{app}\netguard.py"""; WorkingDir: "{app}"; IconFilename: "{app}\netguard_icon.ico"; Comment: "Lancer NetGuard Pro"
Name: "{group}\NetGuard Pro Dashboard"; Filename: "{app}\netguard_dashboard.html"; IconFilename: "{app}\netguard_icon.ico"
Name: "{group}\Guide d'utilisation"; Filename: "{app}\netguard_help.html"
Name: "{group}\Desinstaller NetGuard Pro"; Filename: "{uninstallexe}"; IconFilename: "{app}\netguard_icon.ico"
Name: "{autodesktop}\NetGuard Pro"; Filename: "{app}\python\pythonw.exe"; Parameters: """{app}\netguard.py"""; WorkingDir: "{app}"; IconFilename: "{app}\netguard_icon.ico"; Tasks: desktopicon

[Run]
; Install Python dependencies silently
Filename: "{app}\python\python.exe"; Parameters: "-m pip install --no-warn-script-location --quiet websockets scapy pywebview pystray Pillow psutil requests watchdog pefile"; WorkingDir: "{app}"; StatusMsg: "{cm:InstallingDeps}"; Flags: runhidden waituntilterminated
; Configure firewall rules
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""NetGuard Pro"" dir=in action=allow program=""{app}\python\pythonw.exe"" enable=yes"; StatusMsg: "{cm:ConfiguringFirewall}"; Tasks: firewall; Flags: runhidden waituntilterminated
Filename: "netsh"; Parameters: "advfirewall firewall add rule name=""NetGuard Pro WS"" dir=in action=allow protocol=TCP localport=8765 enable=yes"; Tasks: firewall; Flags: runhidden waituntilterminated
; Launch after install
Filename: "{app}\python\pythonw.exe"; Parameters: """{app}\netguard.py"""; WorkingDir: "{app}"; Description: "{cm:LaunchAfterInstall}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Remove firewall rules
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""NetGuard Pro"""; Flags: runhidden
Filename: "netsh"; Parameters: "advfirewall firewall delete rule name=""NetGuard Pro WS"""; Flags: runhidden

[UninstallDelete]
Type: filesandordirs; Name: "{app}\logs"
Type: filesandordirs; Name: "{app}\captures"
Type: filesandordirs; Name: "{app}\__pycache__"

[Code]
var
  LicenseKeyPage: TInputQueryWizardPage;
  ProgressPage: TOutputProgressWizardPage;

procedure InitializeWizard;
begin
  { License key input page }
  LicenseKeyPage := CreateInputQueryPage(wpSelectTasks,
    'Cle de Licence',
    'Entrez votre cle de licence NetGuard Pro (optionnel)',
    'Si vous avez une cle de licence Pro ou Enterprise, entrez-la ci-dessous.' + #13#10 +
    'Format: NGPRO-XXXX-XXXX-XXXX-XXXX' + #13#10 + #13#10 +
    'Laissez vide pour utiliser la version d''essai gratuite (30 jours).');
  LicenseKeyPage.Add('Cle de licence:', False);
  LicenseKeyPage.Values[0] := '';
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  LicenseKey: String;
  SettingsFile: String;
  SettingsContent: String;
begin
  if CurStep = ssPostInstall then
  begin
    { Save license key if provided }
    LicenseKey := Trim(LicenseKeyPage.Values[0]);
    if LicenseKey <> '' then
    begin
      SettingsFile := ExpandConstant('{app}\netguard_settings.json');
      if FileExists(SettingsFile) then
      begin
        if LoadStringFromFile(SettingsFile, SettingsContent) then
        begin
          { Simple injection — add license_key field }
          StringChangeEx(SettingsContent, '"rules":', '"license_key": "' + LicenseKey + '",' + #13#10 + '  "rules":', True);
          SaveStringToFile(SettingsFile, SettingsContent, False);
        end;
      end;
    end;

    { Create autostart registry entry if selected }
    if IsTaskSelected('autostart') then
    begin
      RegWriteStringValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run',
        'NetGuardPro',
        ExpandConstant('"{app}\python\pythonw.exe" "{app}\netguard.py"'));
    end;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
  begin
    RegDeleteValue(HKCU, 'Software\Microsoft\Windows\CurrentVersion\Run', 'NetGuardPro');
  end;
end;
