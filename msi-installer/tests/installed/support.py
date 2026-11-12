"""Support for the installed-Hole suite: the MSI under test, the Windows state it changes, the `.github/scripts` it drives.

It never uninstalls a Hole it did not install: see `installed_hole` and `INSTALLED_MARKER`.
"""

import ctypes
import json
import os
import platform
import subprocess
import sys
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

import pytest
from rich.console import Console

from conftest import REPO_ROOT
from msi_installer.e2e_tools import e2e_env, provision_e2e_tools
from windows_installer import installed_hole_product_codes, msi_product_code

SCRIPTS = REPO_ROOT / ".github" / "scripts"
INVOKE_MSIEXEC = SCRIPTS / "invoke-msiexec-bounded.ps1"
KILL_HOLE = SCRIPTS / "kill-hole-processes.ps1"
IMAGE_PATH = SCRIPTS / "get-process-image-path.ps1"
RUN_AT_MEDIUM = SCRIPTS / "run-at-medium.ps1"
E2E_MEDIUM = SCRIPTS / "e2e-medium.ps1"
VERIFY_GSUDO = SCRIPTS / "verify-gsudo-deelevation.ps1"
DUMP_UNINSTALL = SCRIPTS / "dump-uninstall-diagnostics.ps1"

# Failure bounds on the child processes the E2E phases start: a wedged phase fails here, naming itself, so the fixture's
# uninstall still runs inside the CI step's own (much larger) timeout.
GSUDO_SELFTEST_TIMEOUT_SECONDS = 5 * 60
DASHBOARD_E2E_TIMEOUT_SECONDS = 5 * 60
DIAGNOSTICS_TIMEOUT_SECONDS = 5 * 60

SERVICE = "HoleBridge"
INSTALL_DIR = Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "hole"
BIN_DIR = INSTALL_DIR / "bin"

MSI_ENV = "MSI_UNDER_TEST"
LOG_DIR_ENV = "MSI_TEST_LOG_DIR"

# `sc query` on an unregistered service.
_ERROR_SERVICE_DOES_NOT_EXIST = 1060

# MSI inputs ===========================================================================================================


def default_msi() -> Path:
    return REPO_ROOT / "target" / "release" / "hole.msi"


def log_dir() -> Path:
    path = Path(os.environ.get(LOG_DIR_ENV) or REPO_ROOT / "target" / "msi-test-logs")
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def msi_path() -> Path:
    """The MSI under test: `MSI_UNDER_TEST`, else the release build. Never built here, never skipped when absent."""
    path = Path(os.environ[MSI_ENV]) if os.environ.get(MSI_ENV) else default_msi()
    if not path.is_file():
        pytest.fail(f"no MSI at {path}: run `cargo xtask build hole-msi`, or set {MSI_ENV} to the MSI to test")
    stat = path.stat()
    # So a stale path or an MSI older than the working tree is visible in the log.
    print(
        f"MSI under test: {path} ({stat.st_size} bytes, modified {datetime.fromtimestamp(stat.st_mtime):%Y-%m-%d %H:%M:%S})"
    )
    return path


@pytest.fixture(scope="session")
def e2e_environment() -> dict[str, str]:
    """The environment for the E2E children: this process's, with the provisioned tools ahead on PATH."""
    if not (REPO_ROOT / "node_modules").is_dir():
        pytest.fail("the E2E needs the repo's node_modules: run `cargo xtask build frontend-build`")
    return e2e_env(os.environ, provision_e2e_tools(REPO_ROOT, Console(stderr=True)))


# PowerShell scripts ===================================================================================================


def _ps_quote(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def run_ps(
    script: Path,
    params: Mapping[str, str | None] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float | None = None,
    phase: str | None = None,
) -> int:
    """Run `script` as a CI `shell: pwsh` step would (`$ErrorActionPreference = 'Stop'`); return its exit code.

    A `None` value emits a bare `-Name` (a switch). With `timeout_seconds`, a child still running then has its
    whole process tree killed and `TimeoutError` names `phase` (default: the script).
    """
    parts = ["$ErrorActionPreference = 'Stop';", f"& {_ps_quote(str(script))}"]
    for name, value in (params or {}).items():
        parts.append(f"-{name}" if value is None else f"-{name} {_ps_quote(value)}")
    parts.append("; exit $LASTEXITCODE")
    child = subprocess.Popen(
        ["pwsh", "-NoProfile", "-Command", " ".join(parts)],
        cwd=REPO_ROOT,
        env=dict(env) if env is not None else None,
    )
    try:
        return child.wait(timeout=timeout_seconds)
    except subprocess.TimeoutExpired:
        outcome = _kill_process_tree(child)
        raise TimeoutError(f"{phase or script.name} did not finish within {timeout_seconds:.0f}s; {outcome}") from None
    except BaseException:
        _kill_process_tree(child)
        raise


def _kill_process_tree(child: subprocess.Popen) -> str:
    """Kill `child` and its descendants (the phase's gsudo, node, tauri-driver and GUI outlive pwsh alone).

    Returns what happened, for an error message. If `taskkill` fails, `child` itself is still killed, so the wait
    below cannot hang on it.
    """
    result = subprocess.run(["taskkill", "/T", "/F", "/PID", str(child.pid)], capture_output=True, text=True)
    if result.returncode == 0:
        child.wait()
        return "its process tree was killed"
    detail = (result.stderr or result.stdout).strip()
    outcome = f"taskkill exited {result.returncode} ({detail}); processes of the phase may still be running"
    print(outcome, file=sys.stderr)
    child.kill()
    child.wait()
    return outcome


def kill_installed_hole_processes() -> None:
    """Kill the GUI the MSI's `LaunchApp` started (and any E2E leftover) under the install dir; the bridge is spared."""
    code = run_ps(KILL_HOLE, {"InstallDir": str(INSTALL_DIR)})
    assert code == 0, f"kill-hole-processes.ps1 exited {code}"


# Machine state ========================================================================================================


def is_elevated() -> bool:
    return bool(ctypes.windll.shell32.IsUserAnAdmin())


def service_registered() -> bool:
    code = subprocess.run(["sc.exe", "query", SERVICE], capture_output=True).returncode
    if code == 0:
        return True
    assert code == _ERROR_SERVICE_DOES_NOT_EXIST, f"`sc query {SERVICE}` exited {code}, neither registered nor absent"
    return False


def machine_path() -> str:
    import winreg  # Windows only

    with winreg.OpenKey(
        winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment"
    ) as key:
        return winreg.QueryValueEx(key, "Path")[0]


def machine_path_has_bin_dir() -> bool:
    return str(BIN_DIR).casefold() in machine_path().casefold()


def leftover_traces() -> list[str]:
    """What an MSI uninstall removes besides the product's registration: the service, the install dir, the PATH entry."""
    traces = []
    if service_registered():
        traces.append(f"the {SERVICE} service is registered")
    if INSTALL_DIR.exists():
        traces.append(f"{INSTALL_DIR} exists")
    if machine_path_has_bin_dir():
        traces.append(f"{BIN_DIR} is in the Machine PATH")
    return traces


def installed_traces() -> list[str]:
    """What shows Hole on this machine: a registered MSI product, or any of `leftover_traces`.

    The one definition of "Hole is installed", shared by the preflight refusal, the verification after an uninstall
    and the cleanup.
    """
    traces = []
    if products := installed_hole_product_codes():
        traces.append(f"MSI product {', '.join(products)} is registered")
    return traces + leftover_traces()


def assert_nothing_installed() -> None:
    traces = installed_traces()
    assert not traces, "Hole is still installed: " + "; ".join(traces)


# Install and uninstall ================================================================================================

INSTALL_LOG_NAME = "msi-install.log"

# Written once a run is about to install, removed once the machine is verified empty. It sits at a fixed place under
# `target\`, not in `MSI_TEST_LOG_DIR`, so the cleanup finds it whatever log dir the run used. The cleanup uninstalls
# only the product it names, so a Hole the harness did not install is never removed.
INSTALLED_MARKER = ".hole-installed-by-the-msi-test-harness"


@dataclass(frozen=True)
class InstallMarker:
    started: datetime
    product_code: str


def install_log_path() -> Path:
    return log_dir() / INSTALL_LOG_NAME


def marker_path() -> Path:
    return REPO_ROOT / "target" / INSTALLED_MARKER


def mark_install_started(product_code: str) -> None:
    """Record the ProductCode about to be installed and when: the diagnostics' event window opens there."""
    path = marker_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"started": datetime.now().astimezone().isoformat(), "product_code": product_code}))


def read_marker() -> InstallMarker | None:
    """The marker, or `None` without one. A marker that cannot be read raises `ValueError`."""
    try:
        raw = json.loads(marker_path().read_text())
        return InstallMarker(datetime.fromisoformat(raw["started"]), raw["product_code"])
    except FileNotFoundError:
        return None
    except (KeyError, TypeError, ValueError) as e:
        raise ValueError(f"{marker_path()} is not a marker this suite wrote ({e!r}): delete it") from e


def install_started() -> datetime | None:
    """The marker's start time, not the install log's creation time: a recreated file keeps the creation time of the
    one it replaces (NTFS tunnelling)."""
    try:
        marker = read_marker()
    except ValueError:
        return None
    return None if marker is None else marker.started


def require_windows_elevated() -> None:
    assert platform.system() == "Windows", "the installed-Hole suite runs on Windows only"
    assert is_elevated(), (
        "this installs Hole system-wide and needs an elevated shell: re-run from an Administrator terminal"
    )


def running_hole_exe_paths() -> list[str]:
    """The image path of every running `hole.exe`, read the way `kill-hole-processes.ps1` reads it."""
    listing = (
        f". {_ps_quote(str(IMAGE_PATH))}; "
        "Get-Process hole -ErrorAction SilentlyContinue | ForEach-Object { "
        "$path = Get-ProcessImagePath $_; if ($path) { $path } else { '(path unreadable)' } }; exit 0"
    )
    out = subprocess.run(
        ["pwsh", "-NoProfile", "-Command", listing],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return out.splitlines()


def refuse_a_machine_with_hole() -> None:
    """Fail before changing anything when Hole is installed or any `hole.exe` runs: none of it is ours to disturb.

    A `hole.exe` from anywhere (a development GUI or `bridge run`) shares the single-instance id and the bridge
    socket with the build under test, so the E2E would route into it and fail misleadingly. It is not killed.
    """
    found = installed_traces()
    if running := running_hole_exe_paths():
        found.append(f"hole.exe is running: {', '.join(running)}")
    assert not found, (
        f"Hole is already on this machine ({'; '.join(found)}). The suite will not install over it, uninstall it or "
        "kill it: quit Hole and uninstall it yourself first"
    )


def dump_failure_diagnostics() -> None:
    """What the uninstall's own processes and the SCM recorded, plus the install log's tail.

    Any error is printed, not raised: this runs while another failure propagates, which it must not replace.
    """
    try:
        params = {} if (since := install_started()) is None else {"Since": since.isoformat()}
        code = run_ps(
            DUMP_UNINSTALL,
            params,
            timeout_seconds=DIAGNOSTICS_TIMEOUT_SECONDS,
            phase="the failure diagnostics dump",
        )
        if code != 0:
            print(f"the failure diagnostics dump exited {code}", file=sys.stderr)
        install_log = install_log_path()
        if install_log.is_file():
            print(f"--- {install_log} (tail) ---")
            print("\n".join(install_log.read_text(errors="replace").splitlines()[-200:]))
    except Exception as e:
        print(f"the failure diagnostics failed: {e!r}", file=sys.stderr)


def ensure_uninstalled(product_code: str, uninstall_log: Path) -> None:
    """Kill the installed GUI, uninstall `product_code`, and verify nothing is left. Fine when nothing is installed.

    Each step runs even when an earlier one failed, and the first failure is the one raised.
    """
    try:
        first_failure = None
        for step in (
            kill_installed_hole_processes,
            # The exit code is ignored: msiexec's output and the verification below report a failed uninstall.
            lambda: run_ps(INVOKE_MSIEXEC, {"Verb": "/x", "Package": product_code, "LogPath": str(uninstall_log)}),
            assert_nothing_installed,
        ):
            try:
                step()
            except Exception as e:
                if first_failure is None:
                    first_failure = e
                else:
                    print(f"also failed: {e!r}", file=sys.stderr)
        if first_failure is not None:
            raise first_failure
    except BaseException:
        dump_failure_diagnostics()
        raise


@pytest.fixture(scope="module")
def installed_hole(msi_path: Path, request: pytest.FixtureRequest) -> Iterator[Path]:
    """Install `msi_path`, yield the install dir, and always uninstall and verify on the way out."""
    require_windows_elevated()
    refuse_a_machine_with_hole()

    failed_before = request.session.testsfailed
    install_completed = False
    product_code = msi_product_code(msi_path)
    mark_install_started(product_code)
    failure = None
    try:
        code = run_ps(
            INVOKE_MSIEXEC,
            {
                "Verb": "/i",
                "Package": str(msi_path),
                "LogPath": str(install_log_path()),
                "FailOnNonZeroExit": None,
            },
        )
        assert code == 0, f"installing {msi_path} failed (exit {code})"
        # The MSI's `LaunchApp` starts the GUI.
        kill_installed_hole_processes()
        install_completed = True
        yield INSTALL_DIR
    except Exception as e:
        failure = e
        raise
    finally:
        try:
            ensure_uninstalled(product_code, log_dir() / "msi-uninstall.log")
        except Exception as e:
            # The marker stays for the cleanup. The first failure is the one reported.
            if failure is None:
                raise
            print(f"the uninstall after it also failed: {e!r}", file=sys.stderr)
        else:
            # A test's failure never reaches this generator; the session's count is the only trace of it.
            if not install_completed or request.session.testsfailed > failed_before:
                dump_failure_diagnostics()
            # Last, so the dump above reads the marker's start time.
            marker_path().unlink(missing_ok=True)
