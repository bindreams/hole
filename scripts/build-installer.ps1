# Build the Hole Windows MSI installer.
#
# Prerequisites:
#   - Rust toolchain
#   - WiX v4 (dotnet tool install --global wix)
#   - uv (for fetch-v2ray-plugin.py)
#
# Usage: .\scripts\build-installer.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

Write-Host "==> Building release binaries..."
cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

Write-Host "==> Fetching v2ray-plugin and wintun..."
uv run "$Root\scripts\fetch-v2ray-plugin.py"
if ($LASTEXITCODE -ne 0) { throw "fetch-v2ray-plugin failed" }

# Collect binaries into a staging directory
$Stage = "$Root\target\release\installer-stage"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

Copy-Item "$Root\target\release\hole.exe" "$Stage\hole.exe" -Force

# v2ray-plugin: the fetch script saves with target-triple name, find the right one
$V2ray = Get-ChildItem "$Root\crates\gui\binaries\v2ray-plugin-*-windows-*.exe" | Select-Object -First 1
if (-not $V2ray) { throw "v2ray-plugin binary not found in crates\gui\binaries\" }
Copy-Item $V2ray.FullName "$Stage\v2ray-plugin.exe" -Force

# wintun.dll
$Wintun = "$Root\crates\gui\binaries\wintun.dll"
if (-not (Test-Path $Wintun)) { throw "wintun.dll not found at $Wintun" }
Copy-Item $Wintun "$Stage\wintun.dll" -Force

Write-Host "==> Building MSI installer..."
$Output = "$Root\target\release\hole.msi"
wix build "$Root\installer\hole.wxs" `
    -bindpath "BinDir=$Stage" `
    -o $Output

if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Write-Host "==> Installer built: $Output"
