# Trusts the LOG USE publisher certificate (one UAC prompt) and opens the Windows App Installer window.
param([string]$Dir = $PSScriptRoot)
$cer = Join-Path $Dir 'LOG-USE.cer'
$pkg = Join-Path $Dir 'LOG-USE.msix'
$thumb = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $cer).Thumbprint
if (-not (Test-Path "Cert:\LocalMachine\TrustedPeople\$thumb")) {
  Start-Process powershell -Verb RunAs -WindowStyle Hidden -Wait -ArgumentList @(
    '-NoProfile','-ExecutionPolicy','Bypass','-WindowStyle','Hidden','-Command',
    "Import-Certificate -FilePath '$cer' -CertStoreLocation Cert:\LocalMachine\TrustedPeople | Out-Null")
}
Start-Process $pkg
