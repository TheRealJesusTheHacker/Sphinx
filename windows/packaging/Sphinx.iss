; Sphinx — Windows installer (Inno Setup 6)
;
; Builds dist\SphinxSetup.exe from the PyInstaller one-file
; Sphinx.exe. Compile from the windows/ directory, after the exe
; exists in dist\:
;   iscc packaging\Sphinx.iss
; CI (.github/workflows/sphinx-windows.yml) does exactly this, and
; so does packaging\build-portable.ps1 when Inno Setup is installed.
;
; The uninstall discipline — read before editing:
;   * Before anything is removed, the uninstaller runs the
;     installed Sphinx.exe with --restore-dns, which puts back the
;     DNS settings Sphinx holds (verifying each) and retires its
;     saved record only when the restore verifies. If the restore
;     fails, uninstall ABORTS with a plain-language explanation:
;     Sphinx never strands a machine with its DNS pointed at a
;     filter that is being removed.
;   * The per-user sign-in entry (the task below, or the same value
;     managed from inside the app) is removed on uninstall.
;   * The user's data folder (%LOCALAPPDATA%\Sphinx) is left in
;     place: it holds their lists, entries, and settings. Removing
;     the app must not quietly delete the user's data. The saved
;     DNS record inside it is retired by the verified restore
;     above — and only by that.

#define AppVersion "0.3.0"
; Keep AppVersion in step with sphinx_win.__version__.

[Setup]
AppId={{BA5723BE-C29C-46D2-91C1-8346D9F14A6D}
AppName=Sphinx
AppVersion={#AppVersion}
AppVerName=Sphinx {#AppVersion}
AppPublisher=Sentinel Safeguard LLC
DefaultDirName={autopf}\Sphinx
DefaultGroupName=Sphinx
DisableProgramGroupPage=yes
OutputDir=..\dist
OutputBaseFilename=SphinxSetup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64compatible
CloseApplications=yes
UninstallDisplayName=Sphinx (Sentinel Safeguard)

[Tasks]
Name: "startatlogin"; Description: "Start Sphinx automatically when I sign in"; GroupDescription: "Startup:"; Flags: unchecked
Name: "desktopicon"; Description: "Put a shortcut on the desktop"; GroupDescription: "Shortcuts:"; Flags: unchecked

[Files]
Source: "..\dist\Sphinx.exe"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
Name: "{group}\Sphinx"; Filename: "{app}\Sphinx.exe"
Name: "{autodesktop}\Sphinx"; Filename: "{app}\Sphinx.exe"; Tasks: desktopicon

[Registry]
; The sign-in entry: the same Run value the app manages from its
; "Start Sphinx when I sign in" checkbox — one mechanism, two
; writers, never two entries. Removed again on uninstall.
Root: HKCU; Subkey: "Software\Microsoft\Windows\CurrentVersion\Run"; ValueType: string; ValueName: "Sphinx"; ValueData: """{app}\Sphinx.exe"" --autostart"; Tasks: startatlogin; Flags: uninsdeletevalue

[Code]
function InitializeUninstall(): Boolean;
var
  ResultCode: Integer;
begin
  Result := True;
  { Put back the DNS settings Sphinx holds before a single file is
    removed. Sphinx.exe --restore-dns exits 0 when the settings are
    restored (or none are held) and 3 when the restore could not be
    verified — in which case the saved record is kept and removing
    Sphinx now could leave this machine's DNS pointing at a filter
    that no longer exists. Abort, in plain language, instead. }
  if Exec(ExpandConstant('{app}\Sphinx.exe'), '--restore-dns', '',
          SW_HIDE, ewWaitUntilTerminated, ResultCode) then
  begin
    if ResultCode <> 0 then
    begin
      MsgBox('Sphinx could not put back your saved DNS settings, so ' +
             'it has not been removed.' + #13#10 + #13#10 +
             'Open Sphinx and turn it off (or use "Restore saved DNS ' +
             'settings" if it offers it), then uninstall again. ' +
             'Nothing was changed.', mbError, MB_OK);
      Result := False;
    end;
  end;
  { If the exe could not be run at all there is no working Sphinx
    left to restore with; the install is already broken by hand, and
    blocking removal would strand the installer instead of the
    machine. Proceed. }
end;
