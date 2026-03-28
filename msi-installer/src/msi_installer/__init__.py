"""Build the Hole Windows MSI installer.

Prerequisites: Rust toolchain, Go toolchain (for v2ray-plugin).
WiX is downloaded automatically on first run.

Usage: uv run --directory msi-installer build
"""

import hashlib
import os
import platform
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import httpx
from rich.console import Console
from rich.progress import BarColumn, DownloadColumn, Progress, TextColumn, TransferSpeedColumn

_PKG_DIR = Path(__file__).resolve().parent
WXS_PATH = _PKG_DIR / "hole.wxs"
WIX_TOOLCHAIN_PATH = _PKG_DIR / "wix-toolchain.toml"


class BuildError(Exception):
    """Raised when a build step fails."""


def _find_repo_root() -> Path:
    """Walk parents of this package until finding the repo root (.git/)."""
    p = _PKG_DIR
    while p != p.parent:
        if (p / ".git").exists():
            return p
        p = p.parent
    raise BuildError("could not find repo root (no .git/ directory found)")


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
        raise BuildError("cargo build failed")


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
        raise BuildError(f"no v2ray-plugin binary found in {v2ray_dir}")
    if len(candidates) > 1:
        raise BuildError(f"multiple v2ray-plugin binaries in {v2ray_dir}: {candidates}")
    method = link_or_copy(candidates[0], stage_dir / "v2ray-plugin.exe")
    console.print(f"  v2ray-plugin.exe ({method})")

    # wintun.dll
    wintun = root / ".cache" / "gui" / "wintun" / "wintun.dll"
    if not wintun.exists():
        raise BuildError(f"wintun.dll not found at {wintun}")
    method = link_or_copy(wintun, stage_dir / "wintun.dll")
    console.print(f"  wintun.dll ({method})")


# Version =====


def get_version(root: Path) -> str:
    cargo_toml = root / "crates" / "gui" / "Cargo.toml"
    with open(cargo_toml, "rb") as f:
        data = tomllib.load(f)

    version = data["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise BuildError(f"version in {cargo_toml} is not valid semver: {version}")
    return version


# WiX toolchain =====


def ensure_wix(root: Path, console: Console) -> Path:
    """Download, cache, and extract the WiX toolchain. Returns path to wix.exe.

    Caching uses two sentinel files:
    - ``<msi-name>.verified``: records the SHA256 of a successfully downloaded MSI,
      so re-downloads are skipped when the hash matches.
    - ``extracted.version``: records the version of the successfully extracted toolchain,
      so re-extraction is skipped when the version matches and wix.exe is present.
    """
    try:
        with open(WIX_TOOLCHAIN_PATH, "rb") as f:
            config = tomllib.load(f)
    except FileNotFoundError:
        raise BuildError(f"WiX toolchain config not found: {WIX_TOOLCHAIN_PATH}")

    for key in ("version", "url", "sha256"):
        if key not in config:
            raise BuildError(f"missing key '{key}' in {WIX_TOOLCHAIN_PATH}")

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
        _download_file(url, msi_path, expected_sha256, console)
        hash_sentinel.write_text(expected_sha256)

    # Extract phase
    if extract_dir.exists():
        try:
            shutil.rmtree(extract_dir)
        except PermissionError:
            raise BuildError(
                f"cannot remove stale extraction directory {extract_dir} "
                "(files may be locked by another process or antivirus)"
            )
    extract_dir.mkdir(parents=True)
    _extract_msi(msi_path, extract_dir, console)
    sentinel.write_text(version)

    wix_exe = find_wix_exe(extract_dir)
    if wix_exe is None:
        raise BuildError(f"wix.exe not found in extracted directory {extract_dir}")
    return wix_exe


def _download_file(url: str, dest: Path, expected_sha256: str, console: Console) -> None:
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
        raise BuildError(f"SHA256 mismatch for {dest.name}: expected {expected_sha256}, got {actual}")

    tmp.replace(dest)


def _extract_msi(msi_path: Path, target_dir: Path, console: Console) -> None:
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
            raise BuildError("msiexec extraction timed out after 120 seconds")

    if result.returncode != 0:
        raise BuildError(f"msiexec extraction failed (exit {result.returncode}): {result.stderr}")


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
        raise BuildError("wix build failed")


# Main =====


def main() -> None:
    if platform.system() != "Windows":
        print("Error: this script is Windows-only (requires msiexec and builds a .msi)", file=sys.stderr)
        sys.exit(1)

    console = Console(stderr=True)

    try:
        root = _find_repo_root()

        cargo_build(console)

        stage_dir = root / "target" / "release" / "installer-stage"
        stage_files(root, stage_dir, console)

        version = get_version(root)
        wix_exe = ensure_wix(root, console)

        output = root / "target" / "release" / "hole.msi"
        wix_build(wix_exe, WXS_PATH, stage_dir, version, output, console)

        console.print(f"[bold green]Installer built:[/] {output}")
    except BuildError as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)
