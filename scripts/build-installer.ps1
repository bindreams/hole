# Build the Hole Windows MSI installer.
#
# Prerequisites:
#   - Rust toolchain
#   - Go toolchain (for building v2ray-plugin from source)
#   - WiX v4 (dotnet tool install --global wix)
#
# Usage: .\scripts\build-installer.ps1

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSCommandPath)

Write-Host "==> Building release binaries (also builds v2ray-plugin and downloads wintun via build.rs)..."
cargo build --release --workspace
if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }

# Collect binaries into a staging directory
$Stage = "$Root\target\release\installer-stage"
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

Copy-Item "$Root\target\release\hole.exe" "$Stage\hole.exe" -Force

# v2ray-plugin: built by build.rs into .cache/gui/
$V2ray = Get-ChildItem "$Root\.cache\gui\v2ray-plugin\v2ray-plugin-*-windows-*.exe" | Select-Object -First 1
if (-not $V2ray) { throw "v2ray-plugin binary not found in .cache\gui\v2ray-plugin\" }
Copy-Item $V2ray.FullName "$Stage\v2ray-plugin.exe" -Force

# wintun.dll: downloaded by build.rs into .cache/gui/
$Wintun = "$Root\.cache\gui\wintun\wintun.dll"
if (-not (Test-Path $Wintun)) { throw "wintun.dll not found at $Wintun" }
Copy-Item $Wintun "$Stage\wintun.dll" -Force

# Extract version from Cargo.toml
$CargoToml = Get-Content "$Root\crates\gui\Cargo.toml" -Raw
if ($CargoToml -match 'version\s*=\s*"(\d+\.\d+\.\d+)"') {
    $Version = $Matches[1]
} else {
    throw "Could not extract version from crates/gui/Cargo.toml"
}

Write-Host "==> Building MSI installer (version $Version)..."
$Output = "$Root\target\release\hole.msi"
wix build "$Root\installer\hole.wxs" `
    -bindpath "BinDir=$Stage" `
    -d "ProductVersion=$Version" `
    -o $Output

if ($LASTEXITCODE -ne 0) { throw "wix build failed" }

Write-Host "==> Installer built: $Output"
