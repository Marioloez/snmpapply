# install.ps1 — Windows installer for snmpapply.
# Detects the platform, downloads the matching binary from GitHub Releases,
# verifies its checksum and drops snmpapply.exe in the current folder, plus the
# example templates. Then create inventory.json + .env next to it and run it.
#
#   irm https://raw.githubusercontent.com/Marioloez/snmpapply/main/install.ps1 | iex
#
# Pin a version with:  $env:VERSION="v1.0.0"; irm https://.../install.ps1 | iex

$ErrorActionPreference = 'Stop'
# Windows PowerShell 5.1 defaults to TLS 1.0; GitHub requires 1.2+. Silencing the
# progress bar makes Invoke-WebRequest downloads fast on 5.1 instead of crawling.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$ProgressPreference = 'SilentlyContinue'

$Repo = 'Marioloez/snmpapply'
$Version = if ($env:VERSION) { $env:VERSION } else { 'latest' }

# Only a windows/amd64 build is published; it also runs on ARM64 Windows under
# x64 emulation, so it's the right asset for every Windows machine.
$asset = 'snmpapply-windows-amd64.exe'

$base = if ($Version -eq 'latest') {
  "https://github.com/$Repo/releases/latest/download"
} else {
  "https://github.com/$Repo/releases/download/$Version"
}

Write-Host "Descargando $asset ($Version)..."
Invoke-WebRequest -UseBasicParsing -Uri "$base/$asset" -OutFile $asset

# Verify the checksum if SHA256SUMS is published alongside the binaries.
$sums = $null
try { $sums = (Invoke-WebRequest -UseBasicParsing -Uri "$base/SHA256SUMS").Content } catch {}
if ($sums) {
  $line = ($sums -split "`n" | Where-Object { $_ -match [regex]::Escape($asset) } | Select-Object -First 1)
  if ($line) {
    $expected = (($line -split '\s+') | Where-Object { $_ })[0].ToLower()
    $actual = (Get-FileHash -Path $asset -Algorithm SHA256).Hash.ToLower()
    if ($actual -ne $expected) {
      Remove-Item $asset -ErrorAction SilentlyContinue
      throw "checksum FALLO: esperado $expected, obtenido $actual"
    }
    Write-Host "checksum OK"
  }
}

Move-Item -Force $asset 'snmpapply.exe'

# Drop the example templates too, from raw (real filenames preserved — GitHub
# release assets can't start with a dot). Best-effort; an existing file is kept.
$raw = "https://raw.githubusercontent.com/$Repo/main"
foreach ($tpl in @('.env.example', 'inventory.example.json')) {
  if (Test-Path $tpl) { continue }
  try {
    Invoke-WebRequest -UseBasicParsing -Uri "$raw/$tpl" -OutFile $tpl
    Write-Host "plantilla $tpl OK"
  } catch {}
}

Write-Host ""
Write-Host "Listo. Copia .env.example a .env e inventory.example.json a inventory.json,"
Write-Host "completalos y ejecuta: .\snmpapply.exe"
