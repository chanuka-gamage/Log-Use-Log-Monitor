' Double-click to install LOG USE. No console window is shown: you get the standard Windows
' "Install LOG USE?" window (App Installer) with a progress bar.
Option Explicit
Dim sh, fso, here
Set sh = CreateObject("WScript.Shell")
Set fso = CreateObject("Scripting.FileSystemObject")
here = fso.GetParentFolderName(WScript.ScriptFullName)
sh.Run "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File """ & here & "\trust_and_install.ps1"" -Dir """ & here & """", 0, False
