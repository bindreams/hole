#!/bin/bash
# Build all crates and stage installer files.
# Called as the `before` hook by `cargo wix`.
#
# Environment variables (set by cargo-wix):
#   WIX_TARGET_DIR    — Cargo target directory
#   WIX_WORKSPACE_ROOT — Workspace root

set -euo pipefail

echo "==> Building release binaries..."
cargo build --release --workspace

stage="$WIX_TARGET_DIR/release/installer-stage"
mkdir -p "$stage"

echo "==> Staging installer files to $stage..."
cp -f "$WIX_TARGET_DIR/release/hole.exe" "$stage/hole.exe"
# Find the single v2ray-plugin binary (one per platform, built by build.rs)
v2ray=$(find .cache/gui/v2ray-plugin/ -name 'v2ray-plugin-*.exe' -type f)
if [ -z "$v2ray" ]; then echo "error: v2ray-plugin binary not found"; exit 1; fi
cp -f "$v2ray" "$stage/v2ray-plugin.exe"
cp -f .cache/gui/wintun/wintun.dll "$stage/wintun.dll"

echo "==> Staging complete"
