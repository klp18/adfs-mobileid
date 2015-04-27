
#define MyAppName "Mobile ID Authentication Provider for ADFS"
#define MyAppShortName "Mobile ID for ADFS"
#define MyAppAbb "MobileIdAdfs"
#define MyAppVersion "1.0"
#define MyAppFullVersion "1.0.0.0"

[Setup]
AppId={{609C382B-1D2D-40F5-B2ED-742C603AD022}
AppName={#MyAppName}
AppVersion={#MyAppFullVersion}
AppPublisher=Swisscom Ltd.
AppPublisherURL=https://www.swisscom.com/
AppSupportURL=https://github.com/SCS-CBU-CED-IAM/adfs-mobileid
AppUpdatesURL=https://github.com/SCS-CBU-CED-IAM/adfs-mobileid/tree/master/binaries
; AppUpdatesURL=http://goo.gl/cp1BCU
AppCopyright=(C) 2015, Swisscom Ltd.
DefaultDirName={pf}\{#MyAppAbb}\v{#MyAppVersion}
DefaultGroupName={#MyAppName}
LicenseFile=..\LICENSE
;InfoAfterFile=post_install.txt
OutputDir=..\binaries
OutputBaseFilename=midadfs_setup_{#MyAppFullVersion}
Compression=lzma
SolidCompression=yes
SetupLogging=yes
PrivilegesRequired=admin
OutputManifestFile=Manifest.txt
VersionInfoVersion={#MyAppFullVersion}
UninstallFilesDir={app}\inst
MinVersion=6.3.9200
;SignTool= TODO

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\binaries\*.dll"; DestDir: "{app}\lib"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\AuthnAdapter\spin.min.js"; DestDir: "{app}\lib"
;Source: "..\samples\MobileId.Adfs.AuthnAdapter-template.xml"; DestDir: "{commonappdata}\{#MyAppAbb}\v{#MyAppVersion}"
Source: "..\samples\MobileId.Adfs.AuthnAdapter-template.xml"; DestDir: "{app}"; DestName: "MobileId.Adfs.AuthnAdapter.xml"
Source: "..\Admin\*.psm1"; DestDir: "{app}\lib"
Source: "..\Admin\*.ps1"; DestDir: "{app}"
Source: "..\Admin\*.cmd"; DestDir: "{app}"
Source: "..\certs\mobileid-ca-ssl.crt"; DestDir: "{app}\certs"
Source: "..\3RD_PARTY.md"; DestDir: "{app}\license"
Source: "..\LICENSE"; DestDir: "{app}\license"; DestName: "MobileId_LICENSE.txt"
Source: "install_midadfs.cmd"; DestDir: "{app}"; Flags: deleteafterinstall

;[Icons]
;Name: "{group}\v{#MyAppVersion}\Uninstall"; Filename: "{uninstallexe}"

[Run]
; We redirect logs to files for troubleshooting purpose, so nothing is displayed in console
Filename: "{app}\install_midadfs.cmd"; WorkingDir: "{app}"; Parameters: ".\inst\setup_trace.log .\inst\setup.log"; StatusMsg: "Registering Mobile ID in ADFS..."; Flags: shellexec waituntilterminated runhidden

[UninstallDelete]
Name: "{app}\inst\setup.log"; Type: files
Name: "{app}\inst\setup_trace.log"; Type: files

[UninstallRun]
; we don't keep uninstall log but display them in console
Filename: "{app}\unregister_midadfs.cmd"; WorkingDir: "{app}"; StatusMsg: "Unregistering Mobile ID from ADFS..."; Flags: shellexec waituntilterminated

