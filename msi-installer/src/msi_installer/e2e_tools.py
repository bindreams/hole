"""Provision the installer E2E tools: tauri-driver, msedgedriver and gsudo.

Everything lands under `<repo>/.cache/installer-e2e/`; nothing is installed system-wide and no persistent PATH is
edited. `provision_e2e_tools` returns the directories a child process needs on its PATH (`e2e_env`). A tool already
in the cache is not fetched again.

Usage: uv run --directory msi-installer provision-e2e-tools
"""

import os
import shutil
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from pathlib import Path

import httpx
from rich.console import Console

from msi_installer import _PKG_DIR, BuildError, _download_and_hash, _download_file, _find_repo_root

E2E_TOOLS_PATH = _PKG_DIR / "e2e-tools.toml"

# The WebView2 Evergreen runtime's client id in the EdgeUpdate registry.
_WEBVIEW2_CLIENT_KEY = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

# The prebuilt tauri-driver that `cargo binstall` resolves for the host: cargo-quickinstall's release asset.
_TAURI_DRIVER_URL = (
    "https://github.com/cargo-bins/cargo-quickinstall/releases/download/"
    "tauri-driver-{version}/tauri-driver-{version}-x86_64-pc-windows-msvc.tar.gz"
)


def cache_dir(root: Path) -> Path:
    return root / ".cache" / "installer-e2e"


def provision_e2e_tools(root: Path, console: Console) -> list[Path]:
    """Fetch the tools missing from the cache; return the directories to prepend to a child's PATH."""
    with open(E2E_TOOLS_PATH, "rb") as f:
        pins = tomllib.load(f)
    cache = cache_dir(root)
    cache.mkdir(parents=True, exist_ok=True)
    return [
        _ensure_tauri_driver(cache, pins["tauri-driver"], console),
        _ensure_msedgedriver(cache, console),
        _ensure_gsudo(cache, pins["gsudo"], console),
    ]


def e2e_env(base: Mapping[str, str], tool_dirs: list[Path]) -> dict[str, str]:
    """`base` with `tool_dirs` ahead of its PATH (keeping the spelling of the key `base` uses)."""
    env = dict(base)
    key = next((k for k in env if k.upper() == "PATH"), "PATH")
    env[key] = os.pathsep.join([*map(str, tool_dirs), env.get(key, "")])
    return env


# staging --------------------------------------------------------------------------------------------------------------


@contextmanager
def _staged(final: Path) -> Iterator[Path]:
    """A scratch directory beside `final`, renamed to it only when the block completes.

    A run killed mid-extract leaves no `final` for a later run to take as a finished install.
    """
    final.parent.mkdir(parents=True, exist_ok=True)
    stage = Path(tempfile.mkdtemp(prefix=f".{final.name}-", dir=final.parent))
    try:
        yield stage
        if final.exists():
            shutil.rmtree(final)
        os.replace(stage, final)
    except BaseException:
        shutil.rmtree(stage, ignore_errors=True)
        raise


def _require_file(path: Path, what: str) -> None:
    if not path.is_file():
        raise BuildError(f"{path.name} not found after extracting {what}")


# tauri-driver ---------------------------------------------------------------------------------------------------------


def _ensure_tauri_driver(cache: Path, pin: Mapping[str, str], console: Console) -> Path:
    """The prebuilt tauri-driver at a pinned version, its archive verified against the pinned sha256.

    A download that cannot succeed (no prebuilt for the version) fails once, naming the URL; only a transient network
    failure is retried (see `_download_and_hash`).
    """
    version = pin["version"]
    out = cache / f"tauri-driver-v{version}"
    if (out / "tauri-driver.exe").is_file():
        return out
    console.print(f"[bold]Installing tauri-driver {version}[/] into {out}")
    with _staged(out) as stage:
        archive = stage / "tauri-driver.tar.gz"
        _download_file(_TAURI_DRIVER_URL.format(version=version), archive, pin["sha256"], console)
        with tarfile.open(archive) as t:
            t.extractall(stage, filter="data")
        archive.unlink()
        _require_file(stage / "tauri-driver.exe", f"the tauri-driver {version} archive")
    return out


# msedgedriver ---------------------------------------------------------------------------------------------------------


def _ensure_msedgedriver(cache: Path, console: Console) -> Path:
    """The msedgedriver matching the installed WebView2 RUNTIME.

    The runner's bundled driver targets the Edge BROWSER version, but the runtime hole.exe loads auto-updates
    independently and is typically newer; a mismatched driver rejects the session with "only supports Microsoft
    Edge version N".
    """
    version = _webview2_runtime_version()
    out = cache / f"msedgedriver-{version}"
    if (out / "msedgedriver.exe").is_file():
        return out
    console.print(f"[bold]Installing msedgedriver {version}[/] (matches the WebView2 runtime)")
    with _staged(out) as stage:
        archive = stage / "edgedriver_win64.zip"
        _download_and_hash(f"https://msedgedriver.microsoft.com/{version}/edgedriver_win64.zip", archive, console)
        with zipfile.ZipFile(archive) as z:
            z.extractall(stage)
        archive.unlink()
        _require_file(stage / "msedgedriver.exe", f"the msedgedriver {version} archive")
    return out


def _webview2_runtime_version() -> str:
    import winreg  # Windows only

    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _WEBVIEW2_CLIENT_KEY) as key:
            return winreg.QueryValueEx(key, "pv")[0]
    except OSError as e:
        raise BuildError("the WebView2 runtime is not installed (no `pv` under its EdgeUpdate client key)") from e


# gsudo ----------------------------------------------------------------------------------------------------------------


def _ensure_gsudo(cache: Path, pin: Mapping[str, str], console: Console) -> Path:
    """gsudo runs the dashboard E2E at Medium integrity.

    Runners run every process at High integrity, and WebView2 Runtime 150 broke the DevTools loopback for
    High-integrity hosts (MicrosoftEdge/WebView2Feedback#5640), so tauri-driver cannot attach; real users run the
    GUI unprivileged (Medium), where 150 works.
    """
    version = pin["version"]
    out = cache / f"gsudo-v{version}"
    exe = out / "x64" / "gsudo.exe"
    if exe.is_file():
        return exe.parent
    console.print(f"[bold]Installing gsudo {version}[/]")
    with _staged(out) as stage:
        archive = stage / "gsudo.portable.zip"
        _download_and_hash(pin["url"].format(version=version), archive, console)
        with zipfile.ZipFile(archive) as z:
            z.extractall(stage)
        archive.unlink()
        _require_file(stage / "x64" / "gsudo.exe", f"the gsudo {version} archive")
    return exe.parent


def main() -> None:
    console = Console(stderr=True)
    try:
        dirs = provision_e2e_tools(_find_repo_root(), console)
    except BuildError as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)
    except httpx.HTTPStatusError as e:
        console.print(f"[bold red]Error:[/] {e.request.url} answered {e.response.status_code}")
        sys.exit(1)
    for d in dirs:
        console.print(f"  {d}")
