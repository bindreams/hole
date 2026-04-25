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


# Build ================================================================================================================


def cargo_build(console: Console) -> None:
    console.print("[bold]Building release binaries[/] (cargo build --release --workspace)")
    result = subprocess.run(["cargo", "build", "--release", "--workspace"])
    if result.returncode != 0:
        raise BuildError("cargo build failed")


# Stage ================================================================================================================


def stage_files(root: Path, stage_dir: Path, console: Console) -> None:
    """Stage the runnable BINDIR via the xtask `stage` subcommand.

    The canonical list of files (hole.exe + v2ray-plugin.exe + wintun.dll on
    Windows) lives in `xtask/src/bindir.rs::bindir_files()`. dev.py and this
    function both call into the same xtask subcommand, so adding a new BINDIR
    file is a one-line change in xtask and both consumers pick it up
    automatically. See issue #143.

    When invoked under the build.yaml orchestrator (`cargo xtask build
    hole-msi`), the `$XTASK` env var holds the path to the running xtask
    binary; we invoke it directly instead of going through `cargo xtask`,
    which on Windows would re-link xtask.exe and fail with ERROR_ACCESS_DENIED
    (the parent process holds an exclusive lock).
    """
    xtask_bin = os.environ.get("XTASK")
    if xtask_bin:
        cmd = [xtask_bin, "stage", "--profile", "release", "--out-dir", str(stage_dir)]
    else:
        cmd = ["cargo", "xtask", "stage", "--profile", "release", "--out-dir", str(stage_dir)]
    console.print(f"[bold]Staging installer files[/] to {stage_dir} (via {cmd[0]} stage)")
    result = subprocess.run(cmd, cwd=root)
    if result.returncode != 0:
        raise BuildError(f"xtask stage failed with exit code {result.returncode}")


# Version ==============================================================================================================


def get_version(root: Path) -> str:
    cargo_toml = root / "crates" / "hole" / "Cargo.toml"
    with open(cargo_toml, "rb") as f:
        data = tomllib.load(f)

    version = data["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise BuildError(f"version in {cargo_toml} is not valid semver: {version}")
    return version


# WiX toolchain ========================================================================================================


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
    except FileNotFoundError as e:
        raise BuildError(f"WiX toolchain config not found: {WIX_TOOLCHAIN_PATH}") from e

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
        except PermissionError as e:
            raise BuildError(
                f"cannot remove stale extraction directory {extract_dir} "
                "(files may be locked by another process or antivirus)"
            ) from e
    extract_dir.mkdir(parents=True)
    _extract_msi(msi_path, extract_dir, console)
    sentinel.write_text(version)

    wix_exe = find_wix_exe(extract_dir)
    if wix_exe is None:
        raise BuildError(f"wix.exe not found in extracted directory {extract_dir}")
    return wix_exe


def _download_and_hash(url: str, dest: Path, console: Console) -> str:
    """Download a file and return its SHA256 hex digest."""
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

    tmp.replace(dest)
    return hasher.hexdigest()


def _download_file(url: str, dest: Path, expected_sha256: str, console: Console) -> None:
    """Download a file and verify its SHA256."""
    actual = _download_and_hash(url, dest, console)
    if actual != expected_sha256:
        dest.unlink(missing_ok=True)
        raise BuildError(f"SHA256 mismatch for {dest.name}: expected {expected_sha256}, got {actual}")


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
        except subprocess.TimeoutExpired as e:
            raise BuildError("msiexec extraction timed out after 120 seconds") from e

    if result.returncode != 0:
        raise BuildError(f"msiexec extraction failed (exit {result.returncode}): {result.stderr}")


def find_wix_exe(base_dir: Path) -> Path | None:
    return next(base_dir.rglob("wix.exe"), None)


# WiX build ============================================================================================================


def wix_build(wix_exe: Path, wxs: Path, stage_dir: Path, version: str, output: Path, console: Console) -> None:
    console.print(f"[bold]Building MSI installer[/] (version {version})")
    result = subprocess.run([
        str(wix_exe),
        "build",
        str(wxs),
        "-arch",
        "x64",
        "-bindpath",
        f"BinDir={stage_dir}",
        "-d",
        f"ProductVersion={version}",
        "-o",
        str(output),
    ], )
    if result.returncode != 0:
        raise BuildError("wix build failed")


# WiX toolchain upgrade ================================================================================================

_WIX_URL_TEMPLATE = "https://github.com/wixtoolset/wix/releases/download/v{version}/wix-cli-x64.msi"


def upgrade_wix() -> None:
    """Update wix-toolchain.toml with the correct URL and SHA256 for the current version."""
    import tempfile

    console = Console(stderr=True)

    try:
        with open(WIX_TOOLCHAIN_PATH, "rb") as f:
            config = tomllib.load(f)

        version = config["version"]
        url = _WIX_URL_TEMPLATE.format(version=version)
        console.print(f"[bold]Updating WiX toolchain for v{version}[/]")

        # Download and compute SHA256
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / f"wix-cli-x64-v{version}.msi"
            sha256 = _download_and_hash(url, dest, console)

        # Check if anything changed
        old_url = config.get("url", "")
        old_sha256 = config.get("sha256", "")

        if url == old_url and sha256 == old_sha256:
            console.print("[green]Already up to date[/]")
            return

        # Update the TOML file
        text = WIX_TOOLCHAIN_PATH.read_text()
        text = re.sub(r'(url\s*=\s*")[^"]+(")', rf"\g<1>{url}\2", text)
        text = re.sub(r'(sha256\s*=\s*")[^"]+(")', rf"\g<1>{sha256}\2", text)
        WIX_TOOLCHAIN_PATH.write_text(text)

        if url != old_url:
            console.print(f"  url: {old_url} → {url}")
        if sha256 != old_sha256:
            console.print(f"  sha256: {old_sha256[:12]}… → {sha256[:12]}…")
        console.print("[bold green]Updated[/] wix-toolchain.toml")
    except BuildError as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)


# Main =================================================================================================================


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
