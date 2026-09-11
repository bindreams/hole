"""Tests for `.github/scripts/invoke-msiexec-bounded.ps1`.

The wedge branch -- diagnostics + kill + `throw` -- only runs for real during
an actual msiexec wedge, so it is otherwise covered by no CI run at all. The
`-ExePath`/`-ExeArgs` seam substitutes the process the script waits on,
letting these tests drive that branch deterministically without a real MSI
transaction. Windows-only: the script uses Get-Service/Get-CimInstance,
which pwsh only implements on Windows.
"""

import platform
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

from conftest import REPO_ROOT

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows",
    reason="Windows-only (script uses Get-Service/Get-CimInstance, Windows-only PowerShell cmdlets)",
)

SCRIPT_PATH = REPO_ROOT / ".github" / "scripts" / "invoke-msiexec-bounded.ps1"

# The `throw` text itself. Asserting the bare word "wedged" proves nothing:
# it also appears in the "killing wedged process tree" header and in the
# `wedged` stack-capture label, both of which print before the throw.
WEDGE_THROW = "wedged: did not exit within"

DIAGNOSTIC_HEADERS = [
    "--- MSI log tail:",
    "--- HoleBridge service state ---",
    "--- hole.exe processes ---",
    "--- msiexec process tree ---",
    "--- native thread stacks ---",
]


def _ps_quote(value: str) -> str:
    """Single-quote a value for embedding in a PowerShell -Command string."""
    return "'" + value.replace("'", "''") + "'"


def _run_script(*,
                params: dict[str, str | None],
                exe_args: list[str] | None = None,
                timeout: float = 60) -> subprocess.CompletedProcess[str]:
    """Invoke the script via `& <path> -K V ...`, built as a -Command string.

    A -Command call with an explicit `@(...)` array literal is used instead of
    `-File` because pwsh's own `-File` CLI parsing only binds the first token
    after a `[string[]]` parameter, silently dropping the rest. A `None` value
    emits a bare `-Name` (switch parameters take no value).

    `$ErrorActionPreference = 'Stop'` is prepended to match GitHub Actions'
    own `shell: pwsh` wrapper (documented to inject this ahead of every run
    block); pwsh's own interactive/`-Command` default is `Continue`, under
    which an unguarded cmdlet error would NOT abort the script the way it
    does in the real CI steps this script runs in.
    """
    parts = ["$ErrorActionPreference = 'Stop';", f"& {_ps_quote(str(SCRIPT_PATH))}"]
    for name, value in params.items():
        parts.append(f"-{name}" if value is None else f"-{name} {_ps_quote(value)}")
    if exe_args is not None:
        literal = ", ".join(_ps_quote(a) for a in exe_args)
        parts.append(f"-ExeArgs @({literal})")
    command = " ".join(parts)
    return subprocess.run(
        ["pwsh", "-NoProfile", "-Command", command],
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def _python_exe_args(*code: str) -> list[str]:
    return ["-c", *code]


def _real_cdb_path() -> Path:
    """The debugger the script itself would find. Fails rather than skips when
    the SDK's Debugging Tools are absent -- see the `cdb` marker."""
    candidates = [
        Path(r"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"),
        Path(r"C:\Program Files\Windows Kits\10\Debuggers\x64\cdb.exe"),
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise AssertionError(
        f"cdb.exe not found in {[str(c) for c in candidates]}; install the Windows SDK's "
        "OptionId.WindowsDesktopDebuggers feature, or deselect with -m 'not cdb'"
    )


# Wedge branch =========================================================================================================


def test_wedge_throws_within_bound_and_emits_all_diagnostics(tmp_path: Path) -> None:
    """A never-exiting stand-in must fail the step within the bound, with every
    diagnostic section present -- not the job timeout, and not a silent abort
    partway through the diagnostics."""
    log_path = tmp_path / "wedge.log"
    bound_minutes = 0.02  # 1.2s

    start = time.monotonic()
    result = _run_script(
        params={
            "Verb": "/i",
            "MsiPath": "unused.msi",
            "LogPath": str(log_path),
            "BoundMinutes": str(bound_minutes),
            "ExePath": sys.executable,
            # Zero budget: this test is about the other diagnostics and the
            # kill, and a real cdb attach would dominate its runtime. The
            # capture itself is covered below. The debugger is named but never
            # launched -- with no budget left the loop skips before starting
            # it -- which keeps this off the cdb-absent fallback path, whose
            # failure would otherwise be reported here as the wrong thing.
            "StackCaptureSeconds": "0",
            "CdbPath": str(tmp_path / "never-launched-cdb.exe"),
        },
        exe_args=_python_exe_args("import time; time.sleep(3600)"),
    )
    elapsed = time.monotonic() - start
    combined = result.stdout + result.stderr

    assert elapsed < 30, f"wedge branch did not fail within a bounded time (took {elapsed:.1f}s):\n{combined}"
    assert result.returncode != 0, f"expected a nonzero exit on wedge, got 0:\n{combined}"
    for header in DIAGNOSTIC_HEADERS:
        assert header in combined, f"missing diagnostic header {header!r} in output:\n{combined}"
    assert WEDGE_THROW in combined

    # Cluster 2: the stand-in process must actually be killed, not left running.
    match = re.search(r"killed process id\(s\): (\d+)", combined)
    assert match, f"no 'killed process id(s)' confirmation in output:\n{combined}"
    killed_pid = match.group(1)
    check = subprocess.run(
        [
            "pwsh", "-NoProfile", "-Command",
            f"if (Get-Process -Id {killed_pid} -ErrorAction SilentlyContinue) {{ exit 1 }} else {{ exit 0 }}"
        ],
        timeout=30,
    )
    assert check.returncode == 0, f"process {killed_pid} is still running after the script reported it killed"


def test_wedge_still_emits_diagnostics_and_throws_when_log_read_fails(tmp_path: Path) -> None:
    """Cluster 1: a probe that genuinely fails (log held open with no sharing,
    reproducing a live msiexec still writing under `/l*vx`) must not swallow
    the remaining diagnostics or the wedge `throw`."""
    log_path = tmp_path / "wedge.log"
    log_path.write_text("pre-existing content\n")

    holder_command = (
        f"$fs = [System.IO.File]::Open({_ps_quote(str(log_path))}, 'Open', 'ReadWrite', 'None'); "
        "Write-Output 'LOCK-ACQUIRED'; [Console]::Out.Flush(); Start-Sleep -Seconds 30; $fs.Close()"
    )
    holder = subprocess.Popen(
        ["pwsh", "-NoProfile", "-Command", holder_command],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        # Block on the holder's own readiness signal (real event), not a
        # fixed delay: the file is exclusively open once this line arrives.
        signal = holder.stdout.readline()
        assert signal.strip() == "LOCK-ACQUIRED", f"holder did not signal lock acquisition: {signal!r}"

        result = _run_script(
            params={
                "Verb": "/i",
                "MsiPath": "unused.msi",
                "LogPath": str(log_path),
                "BoundMinutes": "0.02",
                "ExePath": sys.executable,
                "StackCaptureSeconds": "0",
                "CdbPath": str(tmp_path / "never-launched-cdb.exe"),
            },
            exe_args=_python_exe_args("import time; time.sleep(3600)"),
        )
        combined = result.stdout + result.stderr

        assert result.returncode != 0
        # Named in full: `Invoke-StackCapture` emits the same literal for a
        # capture file it cannot read, which is a different failure.
        assert f"failed to read {log_path}" in combined, \
            f"expected the log-read failure to be reported, not swallowed:\n{combined}"
        for header in DIAGNOSTIC_HEADERS:
            assert header in combined, f"missing diagnostic header {header!r} after a probe failure:\n{combined}"
        assert WEDGE_THROW in combined, f"wedge throw did not surface after a probe failure:\n{combined}"
    finally:
        holder.terminate()
        holder.wait(timeout=10)


# Native stack capture -------------------------------------------------------------------------------------------------


@pytest.mark.cdb
def test_wedge_captures_symbolised_native_stacks_of_the_wedged_process(tmp_path: Path) -> None:
    """The datum #790 asks for: where the wedged process is actually blocked.

    A thread-state table names no call, and neither does a stack of
    `hole+0x3f21a` frames, so this asserts real symbol resolution. The proof
    is cdb's own `lm` verdict, not a `module!name` frame: dbghelp names
    *exported* functions with no PDB at all, so `ntdll!NtWaitForSingleObject`
    alone would still pass with symbol resolution completely broken.

    The only test here that needs the real toolchain: cdb from the SDK's
    Debugging Tools (present on `windows-latest`) and msdl.microsoft.com for
    the OS PDBs. It fails rather than skips when either is missing, because a
    capture that silently stops symbolising is the failure worth catching.

    Expects exactly one capture, which holds because ci.yaml runs this suite
    in the `Test` step, before `Install` -- so the stand-in is the only target
    in existence. On a host that already has a HoleBridge or hole.exe running,
    those are captured first and can spend the budget before the stand-in's
    turn.
    """
    log_path = tmp_path / "wedge.log"

    result = _run_script(
        params={
            "Verb": "/x",
            "MsiPath": "unused.msi",
            "LogPath": str(log_path),
            "BoundMinutes": "0.02",
            "ExePath": sys.executable,
            "StackCaptureSeconds": "120",
        },
        exe_args=_python_exe_args("import time; time.sleep(3600)"),
        timeout=300,
    )
    combined = result.stdout + result.stderr

    assert result.returncode != 0, f"expected a nonzero exit on wedge:\n{combined}"
    assert WEDGE_THROW in combined, f"the capture swallowed the wedge throw:\n{combined}"

    # Only the stand-in's own capture, by label: a runner that happens to have
    # a live HoleBridge or hole.exe contributes extra files, and concatenating
    # them would let a good capture mask an empty one.
    captures = sorted(tmp_path.glob("wedge-stack-wedged-*.txt"))
    assert len(captures) == 1, f"expected exactly one capture of the wedged stand-in, got {captures}:\n{combined}"
    text = captures[0].read_text(errors="replace")

    assert "Child-SP" in text, f"cdb produced no stack listing:\n{text}"
    assert "ntdll!" in text, f"frames carry no module-qualified names:\n{text}"
    assert "pdb symbols" in text, f"no module loaded a PDB -- symbol resolution is broken:\n{text}"
    # The job log is where a reader actually looks; the artifact is the backup.
    assert "Child-SP" in combined, f"stacks were written to file but never echoed to the job log:\n{combined}"


def test_a_hung_debugger_is_killed_partial_output_survives_and_the_wedge_still_throws(tmp_path: Path) -> None:
    """The capture must not become a second way to hang the step.

    The stand-in writes one line and then never exits, so all three
    consequences are observable at once: the budget kills it, what it managed
    to write is still echoed, and the original bounded failure is what fails
    the step.
    """
    log_path = tmp_path / "wedge.log"
    # A batch stand-in ignores the cdb argv it is handed, and its spin loop
    # keeps the hang inside the one process the script knows to kill -- a
    # sleep helper would leave an orphan behind after Stop-Process.
    standin = tmp_path / "hung-cdb.cmd"
    standin.write_text("@echo off\necho STANDIN-PARTIAL-OUTPUT\n:loop\ngoto loop\n")

    start = time.monotonic()
    result = _run_script(
        params={
            "Verb": "/x",
            "MsiPath": "unused.msi",
            "LogPath": str(log_path),
            "BoundMinutes": "0.02",
            "ExePath": sys.executable,
            "StackCaptureSeconds": "3",
            "CdbPath": str(standin),
        },
        exe_args=_python_exe_args("import time; time.sleep(3600)"),
    )
    elapsed = time.monotonic() - start
    combined = result.stdout + result.stderr

    assert elapsed < 60, f"a hung debugger was not bounded (took {elapsed:.1f}s):\n{combined}"
    assert result.returncode != 0
    assert "did not finish" in combined, f"the hung debugger was not reported:\n{combined}"
    assert "STANDIN-PARTIAL-OUTPUT" in combined, f"partial capture output was discarded:\n{combined}"
    assert WEDGE_THROW in combined, f"the hung debugger swallowed the wedge throw:\n{combined}"
    # This stand-in never attaches to anything, so nothing is left suspended
    # and the tree kill is what reaps the stand-in target, as always.
    assert "killed process id(s)" in combined, f"the tree kill was skipped:\n{combined}"
    assert "failed to kill process id(s)" not in combined, f"the tree kill misfired:\n{combined}"


@pytest.mark.cdb
def test_a_target_the_capture_left_suspended_is_detected_and_terminated(tmp_path: Path) -> None:
    """A non-invasive attach that does not end in `qd` freezes its target.

    The script must notice and free it: a suspended HoleBridge can no more
    answer SERVICE_CONTROL_STOP than a wedged one, so an instrument that
    leaves one behind manufactures the hang it exists to diagnose.

    The stand-in reproduces the real failure with the real tool rather than
    simulating it -- `cdb -pv -p <pid>` with stdin at EOF attaches, falls to
    its prompt, and exits WITHOUT detaching. Then it returns, so the script's
    wait for it is the rendezvous and nothing here races: the suspension is
    already in place when the script measures.
    """
    log_path = tmp_path / "wedge.log"
    standin = tmp_path / "suspending-cdb.cmd"
    # %3 is the target pid: the argv is `-pv -p <pid> -logo "<file>" -c "..."`.
    standin.write_text(f'@echo off\necho STANDIN-SUSPENDED-THE-TARGET\n"{_real_cdb_path()}" -pv -p %3 <nul >nul 2>&1\n')

    result = _run_script(
        params={
            "Verb": "/x",
            "MsiPath": "unused.msi",
            "LogPath": str(log_path),
            "BoundMinutes": "0.02",
            "ExePath": sys.executable,
            "StackCaptureSeconds": "120",
            "CdbPath": str(standin),
        },
        exe_args=_python_exe_args("import time; time.sleep(3600)"),
        timeout=300,
    )
    combined = result.stdout + result.stderr

    assert result.returncode != 0
    assert "thread(s) suspended" in combined, f"the frozen target went unnoticed:\n{combined}"
    assert "terminated suspended pid" in combined, f"the frozen target was left suspended:\n{combined}"
    assert WEDGE_THROW in combined, f"freeing the target swallowed the wedge throw:\n{combined}"
    assert "failed to kill process id(s)" not in combined, f"the freed pid was tree-killed again:\n{combined}"


def test_stack_capture_budget_exhaustion_is_reported_and_does_not_swallow_the_wedge(tmp_path: Path) -> None:
    """A zero budget must skip the capture loudly and still reach the throw --
    the capture is additive instrumentation, never a new way to lose the
    original bounded failure."""
    log_path = tmp_path / "wedge.log"

    result = _run_script(
        params={
            "Verb": "/x",
            "MsiPath": "unused.msi",
            "LogPath": str(log_path),
            "BoundMinutes": "0.02",
            "ExePath": sys.executable,
            "StackCaptureSeconds": "0",
            "CdbPath": str(tmp_path / "never-launched-cdb.exe"),
        },
        exe_args=_python_exe_args("import time; time.sleep(3600)"),
    )
    combined = result.stdout + result.stderr

    assert result.returncode != 0
    assert "--- native thread stacks ---" in combined, f"the section vanished when skipped:\n{combined}"
    assert "stack-capture budget of 0s is spent" in combined, \
        f"budget exhaustion was not reported:\n{combined}"
    assert WEDGE_THROW in combined, f"wedge throw did not survive a skipped capture:\n{combined}"


# Non-wedge paths ======================================================================================================


def test_success_exits_zero_and_does_not_throw(tmp_path: Path) -> None:
    result = _run_script(
        params={
            "Verb": "/i",
            "MsiPath": "unused.msi",
            "LogPath": str(tmp_path / "install.log"),
            "BoundMinutes": "1",
            "ExePath": sys.executable,
        },
        exe_args=_python_exe_args("import sys; sys.exit(0)"),
    )
    assert result.returncode == 0, f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"


def test_nonzero_exit_without_failonnonzeroexit_warns_but_does_not_throw(tmp_path: Path) -> None:
    result = _run_script(
        params={
            "Verb": "/x",
            "MsiPath": "unused.msi",
            "LogPath": str(tmp_path / "uninstall.log"),
            "BoundMinutes": "1",
            "ExePath": sys.executable,
        },
        exe_args=_python_exe_args("import sys; sys.exit(3)"),
    )
    combined = result.stdout + result.stderr
    assert result.returncode == 0, f"a non-fatal nonzero exit must not fail the step:\n{combined}"
    assert "failed with exit code 3" in combined


def test_nonzero_exit_with_failonnonzeroexit_throws(tmp_path: Path) -> None:
    result = _run_script(
        params={
            "Verb": "/i",
            "MsiPath": "unused.msi",
            "LogPath": str(tmp_path / "install.log"),
            "BoundMinutes": "1",
            "ExePath": sys.executable,
            "FailOnNonZeroExit": None,
        },
        exe_args=_python_exe_args("import sys; sys.exit(3)"),
    )
    combined = result.stdout + result.stderr
    assert result.returncode != 0, f"expected -FailOnNonZeroExit to fail the step:\n{combined}"
    assert "failed with exit code 3" in combined
