#!/usr/bin/env python3
"""Build the Hole Windows MSI installer.

Prerequisites: Rust toolchain, Go toolchain (for v2ray-plugin).
WiX is downloaded automatically on first run.

Usage: uv run scripts/build-installer.py
"""
# /// script
# requires-python = ">=3.11"
# dependencies = ["httpx", "rich"]
# ///

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

import httpx
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn


def die(console: Console, msg: str) -> NoReturn:
    console.print(f"[bold red]Error:[/] {msg}")
    sys.exit(1)


def link_or_copy(src: Path, dst: Path) -> str:
    """Hardlink src to dst, falling back to copy. Returns method used."""
    dst.unlink(missing_ok=True)
    try:
        os.link(src, dst)
        return "hardlinked"
    except OSError:
        shutil.copy2(src, dst)
        return "copied"


# Build =====


def cargo_build(console: Console) -> None:
    console.print("[bold]Building release binaries[/] (cargo build --release --workspace)")
    result = subprocess.run(["cargo", "build", "--release", "--workspace"])
    if result.returncode != 0:
        die(console, "cargo build failed")


# Stage =====


def stage_files(root: Path, stage_dir: Path, console: Console) -> None:
    stage_dir.mkdir(parents=True, exist_ok=True)
    console.print(f"[bold]Staging installer files[/] to {stage_dir}")

    # hole.exe
    src = root / "target" / "release" / "hole.exe"
    method = link_or_copy(src, stage_dir / "hole.exe")
    console.print(f"  hole.exe ({method})")

    # v2ray-plugin.exe
    v2ray_dir = root / ".cache" / "gui" / "v2ray-plugin"
    candidates = list(v2ray_dir.glob("v2ray-plugin-*.exe"))
    if len(candidates) == 0:
        die(console, f"no v2ray-plugin binary found in {v2ray_dir}")
    if len(candidates) > 1:
        die(console, f"multiple v2ray-plugin binaries in {v2ray_dir}: {candidates}")
    method = link_or_copy(candidates[0], stage_dir / "v2ray-plugin.exe")
    console.print(f"  v2ray-plugin.exe ({method})")

    # wintun.dll
    wintun = root / ".cache" / "gui" / "wintun" / "wintun.dll"
    if not wintun.exists():
        die(console, f"wintun.dll not found at {wintun}")
    method = link_or_copy(wintun, stage_dir / "wintun.dll")
    console.print(f"  wintun.dll ({method})")


# Version =====


def get_version(root: Path, console: Console) -> str:
    cargo_toml = root / "crates" / "gui" / "Cargo.toml"
    with open(cargo_toml, "rb") as f:
        data = tomllib.load(f)

    version = data["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        die(console, f"version in {cargo_toml} is not valid semver: {version}")
    return version


# WiX toolchain =====


def ensure_wix(root: Path, console: Console) -> Path:
    """Download, cache, and extract the WiX toolchain. Returns path to wix.exe.

    Caching uses two sentinel files:
    - `<msi-name>.verified`: records the SHA256 of a successfully downloaded MSI,
      so re-downloads are skipped when the hash matches.
    - `extracted.version`: records the version of the successfully extracted toolchain,
      so re-extraction is skipped when the version matches and wix.exe is present.
    """
    toolchain_path = root / "installer" / "wix-toolchain.toml"
    try:
        with open(toolchain_path, "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        die(console, f"WiX toolchain config not found: {toolchain_path}")

    for key in ("version", "url", "sha256"):
        if key not in config:
            die(console, f"missing key '{key}' in {toolchain_path}")

    version = config["version"]
    url = config["url"]
    expected_sha256 = config["sha256"]

    cache_dir = root / ".cache" / "wix"
    cache_dir.mkdir(parents=True, exist_ok=True)
    extract_dir = cache_dir / f"wix-v{version}"
    sentinel = cache_dir / "extracted.version"

    # Fast path: already extracted and wix.exe exists
    if sentinel.exists() and sentinel.read_text().strip() == version:
        wix_exe = find_wix_exe(extract_dir)
        if wix_exe is not None:
            console.print(f"[bold]Using cached WiX v{version}[/]")
            return wix_exe

    # Download phase
    msi_path = cache_dir / f"wix-cli-x64-v{version}.msi"
    hash_sentinel = cache_dir / f"wix-cli-x64-v{version}.msi.verified"

    need_download = True
    if msi_path.exists() and hash_sentinel.exists():
        if hash_sentinel.read_text().strip() == expected_sha256:
            need_download = False

    if need_download:
        hash_sentinel.unlink(missing_ok=True)
        download_file(url, msi_path, expected_sha256, console)
        hash_sentinel.write_text(expected_sha256)

    # Extract phase
    if extract_dir.exists():
        try:
            shutil.rmtree(extract_dir)
        except PermissionError:
            die(
                console,
                f"cannot remove stale extraction directory {extract_dir} "
                "(files may be locked by another process or antivirus)",
            )
    extract_dir.mkdir(parents=True)
    extract_msi(msi_path, extract_dir, console)
    sentinel.write_text(version)

    wix_exe = find_wix_exe(extract_dir)
    if wix_exe is None:
        die(console, f"wix.exe not found in extracted directory {extract_dir}")
    return wix_exe


def download_file(url: str, dest: Path, expected_sha256: str, console: Console) -> None:
    tmp = dest.with_suffix(".tmp")
    tmp.unlink(missing_ok=True)

    with httpx.stream("GET", url, follow_redirects=True, timeout=60) as response:
        response.raise_for_status()
        total = int(response.headers.get("Content-Length", 0))

        with Progress(
            TextColumn("[bold blue]{task.description}"),
            BarColumn(),
            DownloadColumn(),
            TransferSpeedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Downloading {dest.name}", total=total)
            hasher = hashlib.sha256()
            with open(tmp, "wb") as f:
                for chunk in response.iter_bytes(chunk_size=64 * 1024):
                    f.write(chunk)
                    hasher.update(chunk)
                    progress.advance(task, len(chunk))

    actual = hasher.hexdigest()
    if actual != expected_sha256:
        tmp.unlink(missing_ok=True)
        die(console, f"SHA256 mismatch for {dest.name}: expected {expected_sha256}, got {actual}")

    tmp.replace(dest)


def extract_msi(msi_path: Path, target_dir: Path, console: Console) -> None:
    abs_target = str(target_dir.resolve())
    with console.status("Extracting WiX toolchain..."):
        try:
            # Trailing backslash on TARGETDIR is required by msiexec.
            result = subprocess.run(
                ["msiexec", "/a", str(msi_path.resolve()), f"TARGETDIR={abs_target}\\", "/qn"],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except subprocess.TimeoutExpired:
            die(console, "msiexec extraction timed out after 120 seconds")

    if result.returncode != 0:
        die(console, f"msiexec extraction failed (exit {result.returncode}): {result.stderr}")


def find_wix_exe(base_dir: Path) -> Path | None:
    return next(base_dir.rglob("wix.exe"), None)


# WiX build =====


def wix_build(
    wix_exe: Path, wxs: Path, stage_dir: Path, version: str, output: Path, console: Console
) -> None:
    console.print(f"[bold]Building MSI installer[/] (version {version})")
    result = subprocess.run(
        [
            str(wix_exe),
            "build",
            str(wxs),
            "-arch", "x64",
            "-bindpath",
            f"BinDir={stage_dir}",
            "-d",
            f"ProductVersion={version}",
            "-o",
            str(output),
        ],
    )
    if result.returncode != 0:
        die(console, "wix build failed")


# Main =====


def main() -> None:
    if platform.system() != "Windows":
        print("Error: this script is Windows-only (requires msiexec and builds a .msi)", file=sys.stderr)
        sys.exit(1)

    console = Console(stderr=True)
    root = Path(__file__).resolve().parent.parent

    cargo_build(console)

    stage_dir = root / "target" / "release" / "installer-stage"
    stage_files(root, stage_dir, console)

    version = get_version(root, console)
    wix_exe = ensure_wix(root, console)

    output = root / "target" / "release" / "hole.msi"
    wix_build(wix_exe, root / "installer" / "hole.wxs", stage_dir, version, output, console)

    console.print(f"[bold green]Installer built:[/] {output}")


if __name__ == "__main__":
    main()


# Tests (run with pytest) =====


def test_link_or_copy_hardlink(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("hello")
    dst = tmp_path / "dst.txt"

    method = link_or_copy(src, dst)
    assert method == "hardlinked"
    assert dst.read_text() == "hello"
    assert os.path.samefile(src, dst)


def test_link_or_copy_overwrites_existing(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("new")
    dst = tmp_path / "dst.txt"
    dst.write_text("old")

    link_or_copy(src, dst)
    assert dst.read_text() == "new"


def test_link_or_copy_fallback_to_copy(tmp_path: Path, monkeypatch: "pytest.MonkeyPatch") -> None:
    import pytest  # noqa: F811

    src = tmp_path / "src.txt"
    src.write_text("hello")
    dst = tmp_path / "dst.txt"

    monkeypatch.setattr(os, "link", lambda s, d: (_ for _ in ()).throw(OSError("forced")))
    method = link_or_copy(src, dst)
    assert method == "copied"
    assert dst.read_text() == "hello"


def test_get_version(tmp_path: Path) -> None:
    gui_dir = tmp_path / "crates" / "gui"
    gui_dir.mkdir(parents=True)
    (gui_dir / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "1.2.3"\n')

    console = Console(stderr=True)
    assert get_version(tmp_path, console) == "1.2.3"


def test_get_version_rejects_invalid(tmp_path: Path) -> None:
    import pytest

    gui_dir = tmp_path / "crates" / "gui"
    gui_dir.mkdir(parents=True)
    (gui_dir / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "1.2.3-beta"\n')

    console = Console(stderr=True)
    with pytest.raises(SystemExit):
        get_version(tmp_path, console)


def test_find_wix_exe_found(tmp_path: Path) -> None:
    wix = tmp_path / "sub" / "dir" / "wix.exe"
    wix.parent.mkdir(parents=True)
    wix.write_text("")

    assert find_wix_exe(tmp_path) == wix


def test_find_wix_exe_not_found(tmp_path: Path) -> None:
    assert find_wix_exe(tmp_path) is None
