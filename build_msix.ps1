# Packs dist\LOG USE into a signed MSIX = the Windows "Install LOG USE?" App Installer window.
# Called automatically by build_installer.bat / the GitHub workflow (hidden, no console shown to users).
param([string]$Root = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
Set-Location $Root
$out    = Join-Path $Root 'installer_output'
$layout = Join-Path $Root 'msix_layout'
$pfx    = Join-Path $Root 'LOG-USE-signing.pfx'
$pfxPw  = 'loguse-local'
New-Item -ItemType Directory -Force $out | Out-Null
if (-not (Test-Path 'dist\LOG USE\LOG USE.exe')) { throw 'dist\LOG USE\LOG USE.exe not found - build the app first.' }

# --- layout --------------------------------------------------------------
Remove-Item $layout -Recurse -Force -ErrorAction SilentlyContinue
Copy-Item 'dist\LOG USE' $layout -Recurse
Copy-Item 'msix\AppxManifest.xml' $layout
Copy-Item 'msix\Assets' (Join-Path $layout 'Assets') -Recurse

# --- Windows SDK tools (makeappx / signtool) ---------------------------------
function Find-Kit {
  Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\bin\*\x64\makeappx.exe" -ErrorAction SilentlyContinue |
    Sort-Object FullName -Descending | Select-Object -First 1
}
$kit = Find-Kit
if (-not $kit) {
  winget install -e --id Microsoft.WindowsSDK.10.0.22621 --silent --accept-package-agreements --accept-source-agreements | Out-Null
  $kit = Find-Kit
}
if (-not $kit) { throw 'Windows SDK (makeappx.exe) not found.' }
$makeappx = $kit.FullName
$signtool = Join-Path $kit.DirectoryName 'signtool.exe'

# --- signing certificate (subject must match Identity/@Publisher in the manifest) ---
if (-not (Test-Path $pfx)) {
  $c = New-SelfSignedCertificate -Type Custom -Subject 'CN=LOG USE' -KeyUsage DigitalSignature `
        -FriendlyName 'LOG USE' -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable `
        -NotAfter (Get-Date).AddYears(5) `
        -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.3', '2.5.29.19={text}')
  Export-PfxCertificate -Cert $c -FilePath $pfx -Password (ConvertTo-SecureString $pfxPw -AsPlainText -Force) | Out-Null
  Remove-Item "Cert:\CurrentUser\My\$($c.Thumbprint)" -ErrorAction SilentlyContinue
}
$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($pfx, $pfxPw)
[IO.File]::WriteAllBytes((Join-Path $out 'LOG-USE.cer'), $cert.Export('Cert'))

# --- pack + sign -----------------------------------------------------------
$pkg = Join-Path $out 'LOG-USE.msix'
& $makeappx pack /d $layout /p $pkg /o | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'makeappx failed' }
& $signtool sign /fd SHA256 /f $pfx /p $pfxPw $pkg | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'signtool failed' }

# --- one-click installer helpers ---------------------------------------------
Copy-Item 'msix\trust_and_install.ps1' $out -Force
Copy-Item 'msix\Install_LOG_USE.vbs' $out -Force
Remove-Item $layout -Recurse -Force -ErrorAction SilentlyContinue
