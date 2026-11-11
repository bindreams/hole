"""Provision the installer E2E tools: tauri-driver, msedgedriver and gsudo.

Everything lands under `<repo>/.cache/installer-e2e/`; nothing is installed system-wide and no persistent PATH is
edited. `provision_e2e_tools` returns the directories a child process needs on its PATH (`e2e_env`). A tool already
in the cache is not fetched again.

Usage: uv run --directory msi-installer provision-e2e-tools
"""

import os
import shutil
import subprocess
import sys
import tomllib
import zipfile
from collections.abc import Mapping
from pathlib import Path

from rich.console import Console
from tenacity import Retrying, retry_if_result

from msi_installer import _DOWNLOAD_WAIT, _PKG_DIR, BuildError, _download_and_hash, _find_repo_root, _nap

E2E_TOOLS_PATH = _PKG_DIR / "e2e-tools.toml"

# The WebView2 Evergreen runtime's client id in the EdgeUpdate registry.
_WEBVIEW2_CLIENT_KEY = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

# A program that cannot be run is the one failure no retry fixes.
_CANNOT_RUN = (126, 127)


def cache_dir(root: Path) -> Path:
    return root / ".cache" / "installer-e2e"


def provision_e2e_tools(root: Path, console: Console) -> list[Path]:
    """Fetch the tools missing from the cache; return the directories to prepend to a child's PATH."""
    with open(E2E_TOOLS_PATH, "rb") as f:
        pins = tomllib.load(f)
    cache = cache_dir(root)
    cache.mkdir(parents=True, exist_ok=True)
    return [
        _ensure_tauri_driver(cache, pins["tauri-driver"]["version"], console),
        _ensure_msedgedriver(cache, console),
        _ensure_gsudo(cache, pins["gsudo"], console),
    ]


def e2e_env(base: Mapping[str, str], tool_dirs: list[Path]) -> dict[str, str]:
    """`base` with `tool_dirs` ahead of its PATH (keeping the spelling of the key `base` uses)."""
    env = dict(base)
    key = next((k for k in env if k.upper() == "PATH"), "PATH")
    env[key] = os.pathsep.join([*map(str, tool_dirs), env.get(key, "")])
    return env


# tauri-driver ---------------------------------------------------------------------------------------------------------


def _ensure_tauri_driver(cache: Path, version: str, console: Console) -> Path:
    """A prebuilt binary at a pinned version, so the retried part is a download, not a compile.

    Without cargo-binstall (a developer machine) it compiles from source with `cargo install`: slower, nothing else
    differs. `GITHUB_TOKEN` is read from the environment: the unauthenticated GitHub API limit is 60 requests/hour.
    """
    root = cache / f"tauri-driver-v{version}"
    bin_dir = root / "bin"
    if (bin_dir / "tauri-driver.exe").is_file():
        return bin_dir
    if shutil.which("cargo-binstall"):
        command = [
            "cargo", "binstall", "--no-confirm", "--disable-strategies", "compile",
            "--version", version, "--install-path", str(bin_dir), "tauri-driver",
        ]  # fmt: skip
    else:
        command = ["cargo", "install", "--locked", "--version", version, "--root", str(root), "tauri-driver"]
    console.print(f"[bold]Installing tauri-driver {version}[/] into {bin_dir}")
    _run_until_success(command, console)
    if not (bin_dir / "tauri-driver.exe").is_file():
        raise BuildError(f"tauri-driver.exe not found in {bin_dir} after `{' '.join(command)}`")
    return bin_dir


def _run_until_success(command: list[str], console: Console) -> None:
    """Run `command` until it exits 0, like `.github/scripts/retry.sh`: no attempt cap; a missing program ends it."""

    def report(state) -> None:
        console.print(f"[yellow]`{' '.join(command)}` exited {state.outcome.result()}; retrying[/]")

    code = Retrying(
        retry=retry_if_result(lambda code: code != 0 and code not in _CANNOT_RUN),
        wait=_DOWNLOAD_WAIT,
        sleep=lambda seconds: _nap(seconds),
        before_sleep=report,
    )(lambda: subprocess.run(command).returncode)
    if code != 0:
        raise BuildError(f"`{' '.join(command)}` exited {code}")


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
    out.mkdir(parents=True, exist_ok=True)
    archive = out / "edgedriver_win64.zip"
    _download_and_hash(f"https://msedgedriver.microsoft.com/{version}/edgedriver_win64.zip", archive, console)
    with zipfile.ZipFile(archive) as z:
        z.extractall(out)
    archive.unlink()
    if not (out / "msedgedriver.exe").is_file():
        raise BuildError(f"msedgedriver.exe not found in {out} after extracting the {version} driver")
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
    out.mkdir(parents=True, exist_ok=True)
    archive = out / "gsudo.portable.zip"
    _download_and_hash(pin["url"].format(version=version), archive, console)
    with zipfile.ZipFile(archive) as z:
        z.extractall(out)
    archive.unlink()
    if not exe.is_file():
        raise BuildError(f"gsudo.exe not found at {exe} after extract")
    return exe.parent


def main() -> None:
    console = Console(stderr=True)
    try:
        dirs = provision_e2e_tools(_find_repo_root(), console)
    except BuildError as e:
        console.print(f"[bold red]Error:[/] {e}")
        sys.exit(1)
    for d in dirs:
        console.print(f"  {d}")
