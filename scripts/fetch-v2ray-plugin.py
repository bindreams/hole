#!/usr/bin/env python3
"""Download v2ray-plugin and wintun binaries for bundling with Hole.

Downloads to crates/gui/binaries/ with Tauri target-triple naming convention.
Run: python scripts/fetch-v2ray-plugin.py
"""
# /// script
# requires-python = ">=3.9"
# ///

from __future__ import annotations

import hashlib
import io
import platform
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

# Configuration =====

V2RAY_PLUGIN_VERSION = "v1.3.2"
V2RAY_PLUGIN_BASE = f"https://github.com/shadowsocks/v2ray-plugin/releases/download/{V2RAY_PLUGIN_VERSION}"

WINTUN_VERSION = "0.14.1"
WINTUN_URL = f"https://www.wintun.net/builds/wintun-{WINTUN_VERSION}.zip"

# Maps (os, arch) -> (download filename, target-triple output name, is_tar_gz)
V2RAY_TARGETS: dict[tuple[str, str], tuple[str, str, bool]] = {
    ("Darwin", "arm64"): (
        f"v2ray-plugin-darwin-arm64-{V2RAY_PLUGIN_VERSION}.tar.gz",
        "v2ray-plugin-aarch64-apple-darwin",
        True,
    ),
    ("Darwin", "x86_64"): (
        f"v2ray-plugin-darwin-amd64-{V2RAY_PLUGIN_VERSION}.tar.gz",
        "v2ray-plugin-x86_64-apple-darwin",
        True,
    ),
    ("Windows", "AMD64"): (
        f"v2ray-plugin-windows-amd64-{V2RAY_PLUGIN_VERSION}.tar.gz",
        "v2ray-plugin-x86_64-pc-windows-msvc.exe",
        True,
    ),
}

BINARIES_DIR = Path(__file__).resolve().parent.parent / "crates" / "gui" / "binaries"


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def download(url: str) -> bytes:
    print(f"  Downloading {url}")
    req = urllib.request.Request(url, method="GET")
    with urllib.request.urlopen(req) as resp:
        return resp.read()


def extract_v2ray_plugin(data: bytes, output_name: str, is_tar_gz: bool) -> None:
    output_path = BINARIES_DIR / output_name

    if is_tar_gz:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
            # The archive contains a single binary
            for member in tar.getmembers():
                if member.isfile() and "v2ray-plugin" in member.name:
                    f = tar.extractfile(member)
                    assert f is not None
                    output_path.write_bytes(f.read())
                    break
            else:
                raise RuntimeError("v2ray-plugin binary not found in archive")
    else:
        # ZIP archive (not currently used but future-proofing)
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for name in zf.namelist():
                if "v2ray-plugin" in name:
                    output_path.write_bytes(zf.read(name))
                    break
            else:
                raise RuntimeError("v2ray-plugin binary not found in archive")

    # Make executable on Unix
    if not output_name.endswith(".exe"):
        output_path.chmod(0o755)

    print(f"  -> {output_path} ({sha256(output_path.read_bytes())[:12]}...)")


def fetch_wintun() -> None:
    """Download wintun.dll for Windows."""
    output_path = BINARIES_DIR / "wintun.dll"
    if output_path.exists():
        print(f"  wintun.dll already exists, skipping")
        return

    data = download(WINTUN_URL)
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        # wintun.zip contains wintun/bin/{arch}/wintun.dll
        dll_path = "wintun/bin/amd64/wintun.dll"
        output_path.write_bytes(zf.read(dll_path))

    print(f"  -> {output_path} ({sha256(output_path.read_bytes())[:12]}...)")


def main() -> None:
    os_name = platform.system()
    arch = platform.machine()
    key = (os_name, arch)

    BINARIES_DIR.mkdir(parents=True, exist_ok=True)

    print(f"Platform: {os_name}/{arch}")

    # v2ray-plugin
    if key not in V2RAY_TARGETS:
        print(f"No v2ray-plugin binary available for {os_name}/{arch}")
        sys.exit(1)

    filename, output_name, is_tar_gz = V2RAY_TARGETS[key]
    output_path = BINARIES_DIR / output_name

    if output_path.exists():
        print(f"  {output_name} already exists, skipping")
    else:
        url = f"{V2RAY_PLUGIN_BASE}/{filename}"
        data = download(url)
        extract_v2ray_plugin(data, output_name, is_tar_gz)

    # wintun (Windows only)
    if os_name == "Windows":
        print("Fetching wintun.dll...")
        fetch_wintun()

    print("Done.")


if __name__ == "__main__":
    main()
