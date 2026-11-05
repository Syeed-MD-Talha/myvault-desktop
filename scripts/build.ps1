# Builds MyVault for Windows.
#
#   powershell -ExecutionPolicy Bypass -File scripts/build.ps1
#
# Produces:
#   target\release\myvault.exe                       portable executable
#   release\MyVault.exe                              copy for distribution
#   src-tauri\target\release\...\bundle\nsis\*.exe   installer (if NSIS is available)

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

Write-Host "[1/4] Installing frontend dependencies" -ForegroundColor Cyan
& cmd /c "npm install --no-audit --no-fund"
if ($LASTEXITCODE -ne 0) { throw "npm install failed" }

Write-Host "[2/4] Building the React bundle" -ForegroundColor Cyan
& cmd /c "npm run build"
if ($LASTEXITCODE -ne 0) { throw "frontend build failed" }

Write-Host "[3/4] Compiling the Rust application" -ForegroundColor Cyan
cargo build --release -p myvault --features custom-protocol
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

$exe = Join-Path $root "target\release\myvault.exe"
$out = Join-Path $root "release"
New-Item -ItemType Directory -Force -Path $out | Out-Null
Copy-Item $exe (Join-Path $out "MyVault.exe") -Force
Write-Host "[4/4] Portable executable: $(Join-Path $out 'MyVault.exe')" -ForegroundColor Green

Write-Host "Building the NSIS installer (optional)..." -ForegroundColor Cyan
& cmd /c "npx tauri build 2>&1"
if ($LASTEXITCODE -eq 0) {
    $setup = Get-ChildItem -Path (Join-Path $root "target\release\bundle\nsis") -Filter "*setup.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($setup) {
        Copy-Item $setup.FullName (Join-Path $out "MyVault_Setup.exe") -Force
        Write-Host "Installer: $(Join-Path $out 'MyVault_Setup.exe')" -ForegroundColor Green
    }
} else {
    Write-Host "Installer not produced (NSIS tooling unavailable). The portable executable is complete." -ForegroundColor Yellow
}
