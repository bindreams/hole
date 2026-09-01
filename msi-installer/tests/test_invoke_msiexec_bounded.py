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

DIAGNOSTIC_HEADERS = [
    "--- MSI log tail:",
    "--- HoleBridge service state ---",
    "--- hole.exe processes ---",
    "--- msiexec process tree ---",
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
        },
        exe_args=_python_exe_args("import time; time.sleep(3600)"),
    )
    elapsed = time.monotonic() - start
    combined = result.stdout + result.stderr

    assert elapsed < 30, f"wedge branch did not fail within a bounded time (took {elapsed:.1f}s):\n{combined}"
    assert result.returncode != 0, f"expected a nonzero exit on wedge, got 0:\n{combined}"
    for header in DIAGNOSTIC_HEADERS:
        assert header in combined, f"missing diagnostic header {header!r} in output:\n{combined}"
    assert "wedged" in combined

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
            },
            exe_args=_python_exe_args("import time; time.sleep(3600)"),
        )
        combined = result.stdout + result.stderr

        assert result.returncode != 0
        assert "failed to read" in combined.lower(
        ), f"expected the log-read failure to be reported, not swallowed:\n{combined}"
        for header in DIAGNOSTIC_HEADERS:
            assert header in combined, f"missing diagnostic header {header!r} after a probe failure:\n{combined}"
        assert "wedged" in combined, f"wedge throw did not surface after a probe failure:\n{combined}"
    finally:
        holder.terminate()
        holder.wait(timeout=10)


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
