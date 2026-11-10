; Inno Setup script for LOG USE 2.0  -  compile with build_installer.bat (or ISCC.exe installer.iss)
#define MyAppName "LOG USE"
#define MyAppVersion "2.0.0"
#define MyAppPublisher "LOG USE"
#define MyAppExeName "LOG USE.exe"

[Setup]
AppId={{A5C7B0F2-6E36-4D72-9A5A-10A0B0000001}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\LOG USE
DefaultGroupName=LOG USE
OutputDir=installer_output
OutputBaseFilename=LOG-USE-Setup
SetupIconFile=assets\log_use.ico
WizardImageFile=assets\wizard_large_100.bmp,assets\wizard_large_200.bmp
WizardSmallImageFile=assets\wizard_small_100.bmp,assets\wizard_small_200.bmp
WizardImageStretch=no
AppCopyright=Copyright (C) 2026 LOG USE
AppComments=Personal Cybersecurity Monitor
VersionInfoVersion=2.0.0.0
VersionInfoCompany=LOG USE
VersionInfoDescription=LOG USE Setup
VersionInfoProductName=LOG USE
VersionInfoProductVersion=2.0.0
DisableProgramGroupPage=yes
DisableReadyPage=no
UsePreviousAppDir=yes
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Administrator rights are needed once, to enable Windows sign-in auditing and to let you
; read the Security log. The app itself runs as a normal user.
PrivilegesRequired=admin
InfoBeforeFile=assets\install_notice.txt
CloseApplications=yes
ShowLanguageDialog=no
SetupLogging=no

[Files]
; The whole PyInstaller folder: LOG USE.exe + Python runtime + every library (requests, OpenCV, psutil ...)
Source: "dist\LOG USE\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "docs\LOG_USE_User_Guide.pdf"; DestDir: "{app}\docs"; Flags: ignoreversion
Source: "docs\LOG_USE_User_Guide.docx"; DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
Name: "{group}\LOG USE"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\LOG USE - User Guide"; Filename: "{app}\docs\LOG_USE_User_Guide.pdf"
Name: "{group}\Uninstall LOG USE"; Filename: "{uninstallexe}"
Name: "{autodesktop}\LOG USE"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Tasks]
Name: "desktopicon"; Description: "Create a desktop shortcut"; GroupDescription: "Additional icons:"
Name: "autostart"; Description: "Start LOG USE (visibly) every time I sign in to Windows - needed for the sign-in camera prompt"; GroupDescription: "Windows sign-in monitoring:"
Name: "winaudit"; Description: "Turn on Windows sign-in auditing and allow me to read the Security log"; GroupDescription: "Windows sign-in monitoring:"

[Run]
; --- Windows authentication events (4624 / 4625 / 4634 / 4647 / 4800 / 4801) ---
Filename: "{sys}\auditpol.exe"; Parameters: "/set /subcategory:{{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable"; Flags: runhidden waituntilterminated; Tasks: winaudit; StatusMsg: "Enabling Windows sign-in auditing..."
Filename: "{sys}\auditpol.exe"; Parameters: "/set /subcategory:{{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable"; Flags: runhidden waituntilterminated; Tasks: winaudit
Filename: "{sys}\auditpol.exe"; Parameters: "/set /subcategory:{{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable"; Flags: runhidden waituntilterminated; Tasks: winaudit
; Add the installing user to the built-in "Event Log Readers" group (SID S-1-5-32-573, any Windows language)
Filename: "{sys}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""Add-LocalGroupMember -SID 'S-1-5-32-573' -Member '{username}' -ErrorAction SilentlyContinue"""; Flags: runhidden waituntilterminated; Tasks: winaudit; StatusMsg: "Allowing you to read sign-in events..."
; --- Start at Windows sign-in (per-user Run key written as the original, non-elevated user) ---
Filename: "{app}\{#MyAppExeName}"; Parameters: "--enable-autostart"; Flags: runhidden waituntilterminated runasoriginaluser; Tasks: autostart
; --- Camera privacy page (Windows needs YOU to switch the camera permission on) ---
Filename: "ms-settings:privacy-webcam"; Description: "Open Windows camera privacy settings (turn ON 'Let desktop apps access your camera')"; Flags: shellexec postinstall skipifsilent runasoriginaluser unchecked
Filename: "{app}\docs\LOG_USE_User_Guide.pdf"; Description: "Open the User Guide"; Flags: shellexec postinstall skipifsilent runasoriginaluser
Filename: "{app}\{#MyAppExeName}"; Description: "Launch LOG USE"; Flags: nowait postinstall skipifsilent runasoriginaluser

[UninstallRun]
Filename: "{app}\{#MyAppExeName}"; Parameters: "--disable-autostart"; Flags: runhidden waituntilterminated; RunOnceId: "RemoveAutostart"

[Code]
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usPostUninstall then
    MsgBox('Your LOG USE data (sign-in history, website history, photos, reports) was kept in:' + #13#10 +
           ExpandConstant('{localappdata}\LOG USE') + #13#10 + 'Delete that folder if you want to remove it.',
           mbInformation, MB_OK);
end;
