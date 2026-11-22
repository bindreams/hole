"""Support for the installed-Hole suite: the MSI under test, the Windows state it changes, the `.github/scripts` it drives.

It never uninstalls a Hole it did not install: see `installed_hole` and `INSTALLED_MARKER`.
"""

import codecs
import ctypes
import json
import os
import platform
import re
import subprocess
import sys
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from functools import partial
from pathlib import Path

import pytest
from rich.console import Console

from conftest import REPO_ROOT, canonical_windows_bindir
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

# The pause between two reads of a service that is still starting.
_SERVICE_REREAD_SECONDS = 0.25

# `dwCurrentState` as `sc query` prints it: `STATE : <number> <NAME>`.
_SERVICE_STATES = {
    1: "STOPPED",
    2: "START_PENDING",
    3: "STOP_PENDING",
    4: "RUNNING",
    5: "CONTINUE_PENDING",
    6: "PAUSE_PENDING",
    7: "PAUSED",
}

# MSI inputs ===========================================================================================================


def default_msi() -> Path:
    return REPO_ROOT / "target" / "release" / "hole.msi"


def log_dir() -> Path:
    path = Path(os.environ.get(LOG_DIR_ENV) or REPO_ROOT / "target" / "msi-test-logs")
    path.mkdir(parents=True, exist_ok=True)
    return path


@pytest.fixture(scope="session")
def msi_path() -> Path:
    """The MSI under test: `MSI_UNDER_TEST` (a relative path is from the repo root), else the release build.

    Never built here, never skipped when absent.
    """
    path = REPO_ROOT / os.environ[MSI_ENV] if os.environ.get(MSI_ENV) else default_msi()
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


def _ps_arg(value: str | Sequence[str]) -> str:
    return _ps_quote(value) if isinstance(value, str) else "@(" + ", ".join(_ps_quote(v) for v in value) + ")"


def run_ps(
    script: Path,
    params: Mapping[str, str | Sequence[str] | None] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    timeout_seconds: float | None = None,
    phase: str | None = None,
) -> int:
    """Run `script` as a CI `shell: pwsh` step would (`$ErrorActionPreference = 'Stop'`); return its exit code.

    A `None` value emits a bare `-Name` (a switch); a list emits an array. With `timeout_seconds`, a child still running
    then has its whole process tree killed and `TimeoutError` names `phase` (default: the script).
    """
    parts = ["$ErrorActionPreference = 'Stop';", f"& {_ps_quote(str(script))}"]
    for name, value in (params or {}).items():
        parts.append(f"-{name}" if value is None else f"-{name} {_ps_arg(value)}")
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


def _query_service() -> subprocess.CompletedProcess[str]:
    # Replacement, not strict decoding: a byte outside the code page must not raise inside a teardown.
    return subprocess.run(["sc.exe", "query", SERVICE], capture_output=True, text=True, errors="replace")


def service_registered() -> bool:
    code = _query_service().returncode
    if code == 0:
        return True
    assert code == _ERROR_SERVICE_DOES_NOT_EXIST, f"`sc query {SERVICE}` exited {code}, neither registered nor absent"
    return False


def service_state() -> str | None:
    """The `HoleBridge` service's state (`RUNNING`, `START_PENDING`, ...), `None` when it is not registered.

    Never raises on output it cannot read: it returns `UNREADABLE (...)`, because the teardown reads it before the
    uninstall it must not skip.
    """
    result = _query_service()
    if result.returncode == _ERROR_SERVICE_DOES_NOT_EXIST:
        return None
    match = re.search(r"STATE\s*:\s*(\d+)", result.stdout)
    if result.returncode != 0 or match is None:
        return f"UNREADABLE (`sc query {SERVICE}` exited {result.returncode}: {result.stdout.strip()!r})"
    return _SERVICE_STATES.get(int(match[1]), f"UNKNOWN ({match[1]})")


def wait_until_service_running() -> None:
    """Return once the service is RUNNING; fail naming the state when it settles on anything else.

    `bridge install` starts the service without waiting for it, so a state read right after an install can be
    START_PENDING. That state is re-read, with no cap: a start that never settles is the CI step's bound to end.
    """
    while (state := service_state()) == "START_PENDING":
        time.sleep(_SERVICE_REREAD_SECONDS)
    assert state == "RUNNING", f"the {SERVICE} service is {state}, not RUNNING"


def missing_canonical_files() -> set[str]:
    """The file names the installer must put in `BIN_DIR` and did not."""
    return canonical_windows_bindir() - {p.name for p in BIN_DIR.iterdir() if p.is_file()}


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

# On a `msiexec` command line, so Hole's custom actions meet a RUNNING bridge service: under `/quiet`, Restart Manager
# otherwise stops the service before any custom action runs, which is what the shipped package does by default.
RESTART_MANAGER_PROPERTY = "MSIRESTARTMANAGERCONTROL"
RESTART_MANAGER_DISABLED = "Disable"
_RESTART_MANAGER_OFF_PROPERTY = f"{RESTART_MANAGER_PROPERTY}={RESTART_MANAGER_DISABLED}"


class RestartManager(Enum):
    """Which Restart Manager path an uninstall takes: OFF passes the property, ON is the shipped default."""

    OFF = "off"
    ON = "on"

    @property
    def properties(self) -> tuple[str, ...]:
        match self:
            case RestartManager.OFF:
                return (_RESTART_MANAGER_OFF_PROPERTY,)
            case RestartManager.ON:
                return ()

    def checked_uninstall(self, log: Path, *, tests_passed: bool) -> Callable[[], None] | None:
        """Take the evidence this path's uninstall must be shown to meet, ahead of it; return the check to run after.

        `None` when there is nothing to check: ON's check needs `tests_passed`, because a failed test can leave the old
        product, which carries the property, to be uninstalled. Never raises: the uninstall must run whatever this does.
        """
        match self:
            case RestartManager.OFF:
                bridge_failure = _bridge_failure_before_uninstall()
                baseline = take_log_baseline(CLI_LOG)
                return partial(_assert_uninstall_met_a_running_bridge, bridge_failure, baseline, log)
            case RestartManager.ON:
                return partial(_assert_restart_manager_shut_the_service_down, log) if tests_passed else None


@dataclass(frozen=True)
class InstallMarker:
    started: datetime
    # Every product the run installs, in order: an upgrade case installs two, and whichever is installed when the run
    # is interrupted is the suite's to remove.
    product_codes: tuple[str, ...]


def install_msi(msi: Path, log: Path, restart_manager: RestartManager = RestartManager.ON) -> None:
    """Install `msi`, logging to `log`, on the Restart Manager path `restart_manager`."""
    params = {
        "Verb": "/i",
        "Package": str(msi),
        "LogPath": str(log),
        "Properties": restart_manager.properties,
        "FailOnNonZeroExit": None,
    }
    code = run_ps(INVOKE_MSIEXEC, params)
    assert code == 0, f"installing {msi} failed (exit {code})"


def install_log_path() -> Path:
    return log_dir() / INSTALL_LOG_NAME


def marker_path() -> Path:
    return REPO_ROOT / "target" / INSTALLED_MARKER


def mark_install_started(*product_codes: str) -> None:
    """Record the ProductCodes about to be installed and when: the diagnostics' event window opens there."""
    assert product_codes, "a marker names at least one product"
    path = marker_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps({"started": datetime.now().astimezone().isoformat(), "product_codes": list(product_codes)})
    )


def read_marker() -> InstallMarker | None:
    """The marker, or `None` without one. A marker that cannot be read raises `ValueError`."""
    try:
        raw = json.loads(marker_path().read_text())
        codes = raw["product_codes"]
        if not isinstance(codes, list) or not codes or not all(isinstance(c, str) for c in codes):
            raise TypeError(f"product_codes is {codes!r}")
        return InstallMarker(datetime.fromisoformat(raw["started"]), tuple(codes))
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


def run_msi_logs(since: datetime | None) -> list[Path]:
    """The `msiexec` logs in the log directory written since `since` (all of them without it).

    One per `msiexec` call of the run, and the upgrade case makes several.
    """
    return sorted(log for log in log_dir().glob("*.log") if since is None or log.stat().st_mtime >= since.timestamp())


def dump_failure_diagnostics() -> None:
    """What the uninstall's own processes and the SCM recorded, plus the tail of each `msiexec` log of the run.

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
        for log in run_msi_logs(since):
            print(f"--- {log} (tail) ---")
            print("\n".join(read_msi_log(log).splitlines()[-200:]))
    except Exception as e:
        print(f"the failure diagnostics failed: {e!r}", file=sys.stderr)


# The msiexec log ======================================================================================================

# A line of an `/l*vx` log (the same text whatever the encoding): Restart Manager ended a process holding a file.
RESTART_MANAGER_SHUT_DOWN = "RESTART MANAGER: Successfully shut down"


def read_msi_log(log: Path) -> str:
    """The log's text: msiexec writes UTF-16 LE with a byte-order mark, anything else is read as UTF-8.

    Bytes that do not decode (a log cut short by a killed `msiexec`) are replaced, not raised: the diagnostics read
    every log of the run.
    """
    data = log.read_bytes()
    if data.startswith(codecs.BOM_UTF16_LE):
        return data.decode("utf-16", errors="replace")
    return data.decode("utf-8", errors="replace")


# Hole's own log of the uninstall ======================================================================================

# `hole bridge uninstall` logs here: the `--log-dir` the custom actions in `hole.wxs` pass.
CLI_LOG = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "hole" / "logs" / "gui-cli.log"
# The service's own log, beside it.
BRIDGE_LOG = CLI_LOG.with_name("bridge.log")

# Hole logs this when it sends the Stop; the SCM's observed state follows on indented lines
# (`Look { observed: Running, ... }`).
_STOP_RECORD = "stop wait: sending Stop"
_RUNNING = re.compile(r"\bRunning\b")


@dataclass(frozen=True)
class LogBaseline:
    """A log of Hole's as it stood at one moment: the bytes of the active file `log` and of `<log>.1`.

    `unreadable` is why they could not be read, if so: what the log gained since cannot then be determined, and
    `log_gained` says so.
    """

    log: Path
    active: bytes
    rotated: bytes | None
    unreadable: str | None = None


def _rotated(log: Path) -> Path:
    return log.with_name(log.name + ".1")


def _read_if_present(path: Path) -> bytes | None:
    try:
        return path.read_bytes()
    except FileNotFoundError:
        return None


def take_log_baseline(log: Path) -> LogBaseline:
    """Record `log` (the CLI log before an `msiexec` call, the bridge's before a request). A log that does not exist
    is an empty baseline.

    Never raises, so it can run ahead of an uninstall that must not be skipped; any other failure to read is kept in
    the baseline and fails `log_gained` afterwards.
    """
    try:
        return LogBaseline(log, _read_if_present(log) or b"", _read_if_present(_rotated(log)))
    except OSError as e:
        return LogBaseline(log, b"", None, unreadable=repr(e))


def log_gained(baseline: LogBaseline) -> str:
    """The text the log gained since `baseline`, oldest first. Fails when that cannot be determined exactly.

    The one fact relied on is `DirRotate` (`crates/common/src/logging/dir_rotate.rs`), which writes `gui-cli.log` and
    `bridge.log` alike: the active file is renamed over `<log>.1` at the size limit, and a write that straddles the
    limit is split exactly there. So after one rotation `.1` is the baseline's active file followed by what was gained
    before the split, and the active file holds the rest; a record split between them is rejoined by reading `.1` then
    the active file.
    """
    log, rotated_log = baseline.log, _rotated(baseline.log)

    def cannot(why: str) -> AssertionError:
        return AssertionError(f"what {log.name} gained could not be determined: {why}")

    if baseline.unreadable is not None:
        raise cannot(f"{log} could not be read at the baseline ({baseline.unreadable})")
    try:
        active = _read_if_present(log) or b""
        rotated = _read_if_present(rotated_log)
    except OSError as e:
        raise cannot(f"{log} could not be read afterwards ({e!r})") from e

    if rotated == baseline.rotated and active.startswith(baseline.active):
        gained = active[len(baseline.active) :]
    elif rotated is not None and rotated != baseline.rotated and rotated.startswith(baseline.active):
        gained = rotated[len(baseline.active) :] + active
    else:
        raise cannot(f"neither {log.name} nor {rotated_log.name} continues the log as it was at the baseline")
    return gained.decode("utf-8", errors="replace")


def _log_records(text: str) -> list[list[str]]:
    """The records of `text`: a first line and the indented lines of its fields."""
    records: list[list[str]] = []
    for line in text.splitlines():
        if not line[:1].isspace():
            records.append([])
        if records:
            records[-1].append(line)
    return records


def _is_stop_of_a_running_service(record: list[str]) -> bool:
    return _STOP_RECORD in record[0] and any(_RUNNING.search(line) for line in record[1:])


def stops_sent_to_a_running_service(text: str) -> int:
    """The number of `sending Stop` records in `text` whose look says the service was `Running`."""
    return sum(1 for record in _log_records(text) if _is_stop_of_a_running_service(record))


def assert_msiexec_stopped_a_running_bridge(baseline: LogBaseline, msi_log: Path) -> None:
    """Hole's uninstall stopped a RUNNING service during the `msiexec` call, and Restart Manager did not do it first.

    `baseline` is `take_log_baseline(CLI_LOG)` taken before the call: only what the log gained since counts.
    """
    gained = log_gained(baseline)
    assert stops_sent_to_a_running_service(gained) > 0, (
        f"`hole bridge uninstall` did not stop a running {SERVICE} service: no `{_STOP_RECORD}` record with a "
        f"Running look in what {CLI_LOG} gained during the msiexec call:\n{gained}"
    )
    assert RESTART_MANAGER_SHUT_DOWN not in read_msi_log(msi_log), (
        f"Restart Manager shut an application down during {msi_log.name}, before Hole's custom actions ran"
    )


# Told apart by what each command writes to `gui-cli.log` (every `cli_log!` line is written by `hole::cli` or
# `hole::setup`, then again by `hole::stderr_relay`):
#   `bridge uninstalled`: `uninstall_bridge`, `crates/hole/src/setup.rs`, once the stop and the deregistration are done.
#   `hole bridge install: hole=..., os=..., target=...`: `crates/hole/src/cli.rs`, `BridgeAction::Install`, first.
#   `bridge already installed, reinstalling...`: `install_bridge_with`, `setup.rs`, just before it stops the installed
#       bridge. The install's own stop follows, so a stop after this line is not the uninstall's.
#   `bridge installed and started`: `install_bridge_with`, last. `bridge install failed: ...`: `cli.rs`.
_UNINSTALLED = "bridge uninstalled"
_REINSTALLING = "bridge already installed, reinstalling"
_ONLY_BRIDGE_INSTALL_WRITES = re.compile(
    rf"hole bridge install:|{_REINSTALLING}|bridge installed and started|bridge install failed"
)


def stop_came_from_the_uninstall(text: str) -> bool:
    """Whether `text` has a Running `sending Stop` record that `hole bridge uninstall` wrote, not `hole bridge install`.

    It is followed by the uninstall's completion line before any line only the install writes, and no install in
    `text` found a bridge to reinstall.
    """
    records = _log_records(text)
    if any(_REINSTALLING in record[0] for record in records):
        return False
    for n, record in enumerate(records):
        if not _is_stop_of_a_running_service(record):
            continue
        for later in records[n + 1 :]:
            if _UNINSTALLED in later[0]:
                return True
            if _ONLY_BRIDGE_INSTALL_WRITES.search(later[0]):
                break
    return False


def assert_stop_came_from_the_uninstall(baseline: LogBaseline) -> None:
    """The Running stop that `assert_msiexec_stopped_a_running_bridge` finds is the old product's uninstall's.

    The new product's `hole bridge install` also stops an installed bridge, so during an upgrade the stop alone does
    not say which command sent it.
    """
    gained = log_gained(baseline)
    assert stop_came_from_the_uninstall(gained), (
        f"no Running `{_STOP_RECORD}` record is followed by `{_UNINSTALLED}` before a line only `hole bridge install` "
        f"writes, or the install found a bridge to reinstall, in what {CLI_LOG} gained during the msiexec call:\n"
        f"{gained}"
    )


def _bridge_failure_before_uninstall() -> Exception | None:
    """Why the bridge is not RUNNING, if it is not."""
    try:
        wait_until_service_running()
    except Exception as e:
        return e
    return None


def _assert_uninstall_met_a_running_bridge(
    bridge_failure: Exception | None, baseline: LogBaseline, uninstall_log: Path
) -> None:
    if bridge_failure is not None:
        raise AssertionError(f"the uninstall did not meet a running bridge: {bridge_failure}") from bridge_failure
    assert_msiexec_stopped_a_running_bridge(baseline, uninstall_log)


def _assert_restart_manager_shut_the_service_down(uninstall_log: Path) -> None:
    assert RESTART_MANAGER_SHUT_DOWN in read_msi_log(uninstall_log), (
        f"with Restart Manager on, it did not shut the {SERVICE} service down during {uninstall_log.name}"
    )


def assert_custom_action_ran(log: Path, action: str) -> None:
    """The log has the line `Action start <time>: <action>.`"""
    ran = any("Action start" in line and f": {action}." in line for line in read_msi_log(log).splitlines())
    assert ran, f"{action} did not run in {log}"


def installed_suite_products(product_codes: Sequence[str]) -> list[str]:
    """The members of `product_codes` that are installed."""
    installed = installed_hole_product_codes()
    return [code for code in product_codes if code in installed]


def uninstall_msi(product_code: str, log: Path, properties: Sequence[str] = ()) -> None:
    """Uninstall `product_code`, logging to `log`.

    The exit code is ignored: msiexec's output and the verification after it report a failed uninstall.
    """
    run_ps(INVOKE_MSIEXEC, {"Verb": "/x", "Package": product_code, "LogPath": str(log), "Properties": properties})


def ensure_uninstalled(product_codes: Sequence[str], uninstall_log: Path, properties: Sequence[str] = ()) -> None:
    """Kill the installed GUI, uninstall every one of `product_codes`, and verify nothing is left.

    Fine when nothing is installed. `properties` (`NAME=value`) go on each uninstall's command line; the first
    product's log is `uninstall_log`, the others' are numbered. Each step runs even when an earlier one failed, and
    the first failure is the one raised.
    """
    try:
        first_failure = None
        for step in (
            kill_installed_hole_processes,
            *(
                partial(
                    uninstall_msi,
                    code,
                    uninstall_log if n == 0 else uninstall_log.with_stem(f"{uninstall_log.stem}-{n + 1}"),
                    properties,
                )
                for n, code in enumerate(product_codes)
            ),
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


def finish_run(
    request: pytest.FixtureRequest,
    failed_before: int,
    product_codes: Sequence[str],
    uninstall_log: Path,
    restart_manager: RestartManager,
    *,
    install_completed: bool,
    failure: Exception | None,
    check: Callable[[], None] | None,
) -> None:
    """The teardown of an install run: uninstall the installed `product_codes` and verify nothing is left.

    `restart_manager` is the path the uninstalls take. `failure` is the error the run is already propagating, if any:
    the uninstall's own failure is printed then, not raised over it. The marker stays after a failed uninstall, for the
    cleanup. `check` is the proof the uninstall must carry (`RestartManager.checked_uninstall`): it runs after the
    uninstall and before the diagnostics decision, so a failed one dumps the run's logs, and is raised once the marker
    is gone.
    """
    try:
        ensure_uninstalled(installed_suite_products(product_codes), uninstall_log, restart_manager.properties)
    except Exception as e:
        if failure is None:
            raise
        print(f"the uninstall after it also failed: {e!r}", file=sys.stderr)
    else:
        check_failure = None
        if check is not None:
            try:
                check()
            except Exception as e:
                check_failure = e
        # A test's failure never reaches a fixture's generator; the session's count is the only trace of it.
        if not install_completed or request.session.testsfailed > failed_before or check_failure is not None:
            dump_failure_diagnostics()
        # After the dump, which reads the marker's start time.
        marker_path().unlink(missing_ok=True)
        if check_failure is not None:
            raise check_failure


@contextmanager
def install_run(
    request: pytest.FixtureRequest,
    msi: Path,
    *,
    install_log: Path,
    uninstall_log: Path,
    restart_manager: RestartManager,
    installed_later: Sequence[Path] = (),
) -> Iterator[tuple[str, ...]]:
    """Install `msi` with its bridge RUNNING and the app killed, yield the run's ProductCodes, and always uninstall.

    `installed_later` are MSIs the test installs itself: the marker names them and the teardown removes whichever is
    installed. The teardown is `finish_run` on the `restart_manager` path, which proves the final uninstall met a
    running bridge (OFF) or had Restart Manager stop it (ON).
    """
    require_windows_elevated()
    refuse_a_machine_with_hole()

    failed_before = request.session.testsfailed
    install_completed = False
    failure = None
    product_codes = tuple(msi_product_code(m) for m in (msi, *installed_later))
    assert len(set(product_codes)) == len(product_codes), "two links of the package must be two products"
    mark_install_started(*product_codes)
    try:
        install_msi(msi, install_log)
        # `bridge install` does not wait for the service, and the kill below spares the bridge by the process id the
        # service reports, which is not valid while it is START_PENDING.
        wait_until_service_running()
        # The MSI's `LaunchApp` starts the GUI.
        kill_installed_hole_processes()
        install_completed = True
        yield product_codes
    except Exception as e:
        failure = e
        raise
    finally:
        check = (
            restart_manager.checked_uninstall(uninstall_log, tests_passed=request.session.testsfailed == failed_before)
            if install_completed and failure is None
            else None
        )
        finish_run(
            request,
            failed_before,
            product_codes,
            uninstall_log,
            restart_manager,
            install_completed=install_completed,
            failure=failure,
            check=check,
        )


@pytest.fixture(scope="module")
def installed_hole(msi_path: Path, request: pytest.FixtureRequest) -> Iterator[Path]:
    """Install `msi_path`, yield the install dir, and always uninstall and verify on the way out.

    The uninstall meets the running bridge service: Hole's own uninstall must have stopped it
    (`assert_msiexec_stopped_a_running_bridge`).
    """
    with install_run(
        request,
        msi_path,
        install_log=install_log_path(),
        uninstall_log=log_dir() / "msi-uninstall.log",
        restart_manager=RestartManager.OFF,
    ):
        yield INSTALL_DIR
