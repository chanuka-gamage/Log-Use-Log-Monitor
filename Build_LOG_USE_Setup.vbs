' Double-click this file. No black command window appears.
' It builds LOG-USE-Setup.exe silently (no start message) and shows one message when finished.
Option Explicit
Dim sh, fso, here, logf, rc, msg
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
logf = here & "\build_log.txt"
sh.CurrentDirectory = here
rc = sh.Run("cmd /c """"" & here & "\build_installer.bat"" /silent > """ & logf & """ 2>&1""", 0, True)
Dim haveExe, haveMsix
haveExe = fso.FileExists(here & "\installer_output\LOG-USE-Setup.exe")
haveMsix = fso.FileExists(here & "\installer_output\LOG-USE.msix") And fso.FileExists(here & "\installer_output\Install_LOG_USE.vbs")
If rc = 0 And haveExe And haveMsix Then
  MsgBox "Done!" & vbCrLf & vbCrLf & "To see the Windows App Installer window, open the folder that will appear and double-click:" & vbCrLf & "Install_LOG_USE.vbs" & vbCrLf & vbCrLf & "(Classic setup: LOG-USE-Setup.exe)", vbInformation, "LOG USE"
  sh.Run "explorer """ & here & "\installer_output""", 1, False
ElseIf rc = 0 And haveExe Then
  MsgBox "The classic installer LOG-USE-Setup.exe is ready, but the Windows App Installer package (MSIX) could NOT be created, so that window will not appear." & vbCrLf & vbCrLf & "Reason: see the end of build_log.txt (usually the Windows SDK is missing). Install the 'Windows 10/11 SDK' and double-click this file again.", vbExclamation, "LOG USE"
  sh.Run "explorer """ & here & "\installer_output""", 1, False
Else
  MsgBox "The build did not finish. Details were saved in:" & vbCrLf & logf, vbExclamation, "LOG USE"
End If
