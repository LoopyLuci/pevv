<#
.SYNOPSIS
  Packs the PEVV desktop app as an MSIX (the only install form Windows 11 accepts for a passkey provider).

.DESCRIPTION
  Needs: a release build made with the feature (see below), and makeappx.exe from the Windows SDK.
  Writes only under desktop/src-tauri/target/msix and installs or registers nothing. It does not create,
  import or trust a certificate: signing needs one you supply.

    npm run build:desktop-web
    npx tauri build --no-bundle --features win-passkey-provider
    pwsh desktop/src-tauri/windows/msix/build-msix.ps1 -Publisher "CN=Your Name, O=Your Org, C=XX"

  (`tauri build` rather than plain `cargo build`: it embeds the web UI. `--no-bundle` skips NSIS and MSI.)

  The package is unsigned unless you pass -PfxPath. Windows refuses unsigned packages. Publisher MUST be
  identical to the Subject of the certificate you sign with.

.PARAMETER Publisher
  The certificate subject, e.g. "CN=Example, O=Example, C=US". Required.
.PARAMETER PfxPath
  A code-signing .pfx you supply. Optional: leave it out to produce an unsigned package.
.PARAMETER PfxPassword
  Its password, as a SecureString (Read-Host -AsSecureString).
.PARAMETER Version
  Four-part package version. Default: the app version with ".0" added.
.PARAMETER ExeDir
  Folder holding pevv-desktop.exe (and pevv.exe, pevv-native-host.exe). Default: src-tauri/target/release.
.PARAMETER TimestampUrl
  An RFC 3161 timestamp server for signing (optional).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$Publisher,
  [string]$PublisherDisplayName = 'PEVV',
  [string]$IdentityName = 'Luciverse.PEVV',
  [string]$Version,
  [string]$ExeDir,
  [string]$PfxPath,
  [securestring]$PfxPassword,
  [string]$TimestampUrl
)
$ErrorActionPreference = 'Stop'

$here = $PSScriptRoot
$tauri = (Resolve-Path (Join-Path $here '..\..')).Path
if (-not $ExeDir) { $ExeDir = Join-Path $tauri 'target\release' }
$out = Join-Path $tauri 'target\msix'
$layout = Join-Path $out 'layout'

if ($Publisher -notmatch '^\s*[A-Za-z]+=') { throw "Publisher must be a certificate subject such as 'CN=Name, O=Org, C=XX'." }
if (-not $Version) {
  $conf = Get-Content (Join-Path $tauri 'tauri.conf.json') -Raw | ConvertFrom-Json
  $Version = "$($conf.version).0"
}
if ($Version -notmatch '^\d+\.\d+\.\d+\.\d+$') { throw "Version must have four numbers, e.g. 0.1.0.0 (got '$Version')." }

# makeappx.exe: the newest Windows SDK that has one.
$kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
$makeappx = Get-ChildItem -Path $kits -Filter makeappx.exe -Recurse -ErrorAction SilentlyContinue |
  Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
if (-not $makeappx) { throw "makeappx.exe not found under $kits. Install the Windows SDK." }

if (-not (Test-Path (Join-Path $ExeDir 'pevv-desktop.exe'))) { throw "pevv-desktop.exe not found in $ExeDir. Build first (see .DESCRIPTION)." }

# A fresh layout, inside the repository's target folder only.
if (-not ([IO.Path]::GetFullPath($layout)).StartsWith($tauri)) { throw 'Refusing to write outside the repository.' }
if (Test-Path $layout) { Remove-Item -LiteralPath $layout -Recurse -Force }
New-Item -ItemType Directory -Force -Path (Join-Path $layout 'Assets') | Out-Null

foreach ($f in 'pevv-desktop.exe', 'pevv.exe', 'pevv-native-host.exe') {
  $p = Join-Path $ExeDir $f
  if (Test-Path $p) { Copy-Item -LiteralPath $p -Destination $layout }
}
foreach ($a in 'StoreLogo.png', 'Square150x150Logo.png', 'Square44x44Logo.png') {
  Copy-Item -LiteralPath (Join-Path $tauri "icons\$a") -Destination (Join-Path $layout 'Assets')
}

$esc = { param($s) [Security.SecurityElement]::Escape($s) }
$xml = (Get-Content (Join-Path $here 'AppxManifest.xml') -Raw).
  Replace('@IDENTITY_NAME@', (& $esc $IdentityName)).
  Replace('@PUBLISHER@', (& $esc $Publisher)).
  Replace('@VERSION@', $Version).
  Replace('@PUBLISHER_DISPLAY_NAME@', (& $esc $PublisherDisplayName))
[IO.File]::WriteAllText((Join-Path $layout 'AppxManifest.xml'), $xml, (New-Object Text.UTF8Encoding($false)))

$msix = Join-Path $out "PEVV_${Version}_x64.msix"
if (Test-Path $msix) { Remove-Item -LiteralPath $msix -Force }
& $makeappx.FullName pack /d $layout /p $msix /o
if ($LASTEXITCODE -ne 0) { throw "makeappx failed ($LASTEXITCODE)." }

if ($PfxPath) {
  $signtool = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -match '\\x64\\' } | Sort-Object FullName -Descending | Select-Object -First 1
  if (-not $signtool) { throw 'signtool.exe not found in the Windows SDK.' }
  $signArgs = @('sign', '/fd', 'SHA256', '/f', $PfxPath)
  if ($PfxPassword) {
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
    try { $signArgs += @('/p', [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
  }
  if ($TimestampUrl) { $signArgs += @('/tr', $TimestampUrl, '/td', 'SHA256') }
  $signArgs += $msix
  & $signtool.FullName @signArgs
  if ($LASTEXITCODE -ne 0) { throw "signtool failed ($LASTEXITCODE)." }
  Write-Host "Signed: $msix"
} else {
  Write-Host "Built (UNSIGNED): $msix"
  Write-Host 'Windows will not install an unsigned package. Sign it with a certificate you supply (-PfxPath) whose subject equals -Publisher.'
}
