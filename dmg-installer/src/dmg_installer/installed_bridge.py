"""The installed macOS bridge's footprint and its teardown.

One teardown serves the install e2e's fixture and the CI cleanup step that follows it, which must still run when a
step timeout killed pytest before the fixture's own teardown: `uv run --directory dmg-installer cleanup-installed-bridge`.
"""

import re
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Mirrors `crates/bridge/src/platform/macos.rs`, `hole_common::protocol::default_bridge_socket_path` and
# `hole_bridge::group::GROUP_NAME`.
LAUNCHD_LABEL = "com.hole.bridge"
HELPER_PATH = Path("/Library/PrivilegedHelperTools/com.hole.bridge")
PLIST_PATH = Path("/Library/LaunchDaemons/com.hole.bridge.plist")
SOCKET_PATH = Path("/var/run/hole-bridge.sock")
GROUP = "hole"
# What `hole bridge uninstall` is expected to remove.
INSTALL_PATHS = [HELPER_PATH, PLIST_PATH, SOCKET_PATH, Path("/Library/Application Support/Hole"), Path("/var/run/hole")]
# What the install and the running bridge write that `uninstall` leaves.
SERVICE_DIRS = [Path("/var/log/hole"), Path("/var/db/hole")]


def sudo(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(["sudo", "-n", *args], capture_output=True, text=True)


def describe(r: subprocess.CompletedProcess[str]) -> str:
    return f"exit {r.returncode}\n--- stdout ---\n{r.stdout}\n--- stderr ---\n{r.stderr}"


def bridge_log() -> str:
    """Everything the installed bridge wrote under /var/log/hole."""
    r = sudo("sh", "-c", 'for f in /var/log/hole/*; do echo "=== $f"; cat "$f"; done')
    return r.stdout + r.stderr


def job_state(job: str) -> str:
    """The `state` line of a `launchctl print` dump."""
    state = re.search(r"^\s*state = (.*)$", job, re.MULTILINE)
    return state.group(1).strip() if state is not None else "unknown"


def read_job_loaded() -> str | None:
    """The bridge's launchd job as `launchctl print` shows it, `None` once it is not loaded."""
    r = sudo("launchctl", "print", f"system/{LAUNCHD_LABEL}")
    return r.stdout if r.returncode == 0 else None


def group_exists() -> bool:
    import grp  # POSIX only: the install e2e's test module must still be collected on Windows

    try:
        grp.getgrnam(GROUP)
    except KeyError:
        return False
    return True


@dataclass(frozen=True)
class Preexisting:
    """What a teardown leaves alone because it was there before the install."""

    dirs: frozenset[Path]
    group: bool

    @classmethod
    def snapshot(cls) -> "Preexisting":
        return cls(frozenset(d for d in [*INSTALL_PATHS, *SERVICE_DIRS] if d.exists()), group_exists())

    @classmethod
    def nothing(cls) -> "Preexisting":
        return cls(frozenset(), False)


def tear_down(hole: Path | None, preexisting: Preexisting) -> list[str]:
    """Uninstall the bridge with `hole` (when there is one), then remove whatever remains of it.

    Returns what went wrong; a removal that failed or left something behind is reported, never ignored.
    """
    problems = []
    if hole is not None:
        r = sudo(str(hole), "bridge", "uninstall")
        if r.returncode != 0:
            problems.append(f"hole bridge uninstall failed: {describe(r)}")

    if read_job_loaded() is not None:
        r = sudo("launchctl", "bootout", f"system/{LAUNCHD_LABEL}")
        if r.returncode != 0 and read_job_loaded() is not None:
            problems.append(f"launchctl bootout failed: {describe(r)}")
    # launchd unloads the job asynchronously and announces nothing, and the bridge removes its socket as it exits:
    # re-read the job until it is gone. The CI step timeout bounds a job that never goes.
    last_state = None
    while (job := read_job_loaded()) is not None:
        if (state := job_state(job)) != last_state:
            print(f"waiting for {LAUNCHD_LABEL} to unload; launchd state: {state}", file=sys.stderr, flush=True)
            last_state = state

        time.sleep(1)

    if hole is not None:
        status = sudo(str(hole), "bridge", "status")
        if status.returncode != 2:
            problems.append(f"bridge still installed after uninstall: {describe(status)}")
        left = [p for p in INSTALL_PATHS if p.exists()]
        if left:
            problems.append(f"uninstall left files behind: {left}")

    # Fallback for an uninstall that failed or never ran.
    removable = [p for p in [*INSTALL_PATHS, *SERVICE_DIRS] if p not in preexisting.dirs]
    r = sudo("rm", "-rf", *map(str, removable))
    if r.returncode != 0:
        problems.append(f"rm -rf {removable} failed: {describe(r)}")
    if not preexisting.group and group_exists():
        r = sudo("dseditgroup", "-o", "delete", GROUP)
        if r.returncode != 0 and group_exists():
            problems.append(f"deleting group {GROUP} failed: {describe(r)}")

    remaining = [p for p in removable if p.exists()]
    if remaining:
        problems.append(f"still there after removal: {remaining}")
    if not preexisting.group and group_exists():
        problems.append(f"group {GROUP} still exists after removal")
    return problems


def main() -> int:
    """CI cleanup after the install e2e: print the bridge's log, then tear down. Exit 1 if anything went wrong."""
    print(bridge_log())
    problems = tear_down(HELPER_PATH if HELPER_PATH.exists() else None, Preexisting.nothing())
    for problem in problems:
        print(f"::error::{problem}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
