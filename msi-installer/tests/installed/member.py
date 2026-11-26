"""The person the installer granted: a member of `hole` whose token predates the membership, and who is not elevated.

Windows adds a new group membership to a token only at the next sign-in, so the child's token has no `hole` group in
it: it is admitted only by what the bridge wrote into the socket's access list for the user. The child is de-elevated
with `gsudo`, as the dashboard E2E is.
"""

import json
import re
import shutil
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from support import (
    BIN_DIR,
    BRIDGE_LOG,
    BRIDGE_SOCKET,
    HOLE_CLI_TIMEOUT_SECONDS,
    RECORD_RUN,
    RUN_AT_MEDIUM,
    LogBaseline,
    hole_command_report,
    log_dir,
    run_ps,
    take_log_baseline,
)

# Where `record-run.ps1` reads its spec from.
SPEC_ENV = "HOLE_RECORD_RUN_SPEC"

ADMINISTRATORS_SID = "S-1-5-32-544"


@dataclass
class UnelevatedMember:
    """Runs commands in a child of this process that `gsudo` de-elevated."""

    # The service's log as the test found it: a failure shows what the log gained since.
    bridge_log: LogBaseline
    environment: Mapping[str, str]
    # A folder the child can read and write.
    scratch: Path
    # Where the test is, for a failure's text.
    phase: str = "before any restart"
    runs: int = 0
    # How the child's own connect to the bridge's socket went after its last command: `None` is accepted.
    socket_refusal: str | None = None

    def recorded_command(self, exe: Path, *args: str) -> dict:
        """Run `exe args` in the de-elevated child; return what `record-run.ps1` recorded of the run and of the child's
        token. A child still running at `HOLE_CLI_TIMEOUT_SECONDS` is killed and raises `TimeoutError`."""
        self.runs += 1
        spec = self.scratch / f"run-{self.runs}.json"
        result = self.scratch / f"run-{self.runs}-result.json"
        spec.write_text(
            json.dumps({
                "exe": str(exe),
                "arguments": subprocess.list2cmdline(args),
                "socket": str(BRIDGE_SOCKET),
                "result": str(result),
            }),
            encoding="utf-8",
        )
        code = run_ps(
            RUN_AT_MEDIUM,
            {"Script": str(RECORD_RUN)},
            env={**self.environment, SPEC_ENV: str(spec)},
            timeout_seconds=HOLE_CLI_TIMEOUT_SECONDS,
            phase=f"`{exe.name} {' '.join(args)}` in the de-elevated child",
        )
        assert result.is_file(), (
            f"the de-elevated child recorded nothing for `{exe.name} {' '.join(args)}` (the launcher exited {code}): "
            "see its output above"
        )
        record = json.loads(result.read_text(encoding="utf-8"))
        self.socket_refusal = record["socket_refusal"]
        return record

    def recorded(self, *args: str) -> dict:
        """`recorded_command` of the installed `hole.exe`."""
        return self.recorded_command(BIN_DIR / "hole.exe", *args)

    def run(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [str(BIN_DIR / "hole.exe"), *args]
        try:
            record = self.recorded(*args)
        except TimeoutError as e:
            # Returned as a failed command, not raised, as `InstalledCli.run` does: the journey reports those.
            return subprocess.CompletedProcess(command, returncode=-1, stdout="", stderr=f"(killed: {e})")
        return subprocess.CompletedProcess(command, record["exit_code"], record["stdout"], record["stderr"])

    def report(self, what: str, result: subprocess.CompletedProcess[str]) -> str:
        # The child's own connect names the socket error, which `hole`'s "permission denied" does not.
        connect = "accepted" if self.socket_refusal is None else f"refused: {self.socket_refusal}"
        return hole_command_report(
            f"{self.phase}, as the user, not elevated: {what}\n"
            f"the same user's own connect to {BRIDGE_SOCKET} after its last command was {connect}",
            result,
            self.bridge_log,
        )


@pytest.fixture
def member(request: pytest.FixtureRequest, installed_hole: Path, gsudo_environment: dict[str, str]) -> UnelevatedMember:
    # Not `tmp_path`: pytest makes it with mode 0o700, which on Windows admits only its owner, and a folder this
    # elevated process makes is owned by Administrators. A folder made without a mode inherits its parent's access.
    # One per test, so no test removes what another left for a reader of its failure.
    scratch = log_dir() / "member" / re.sub(r"[^\w.-]+", "_", request.node.name)
    # Emptied, so a result read below is one this run wrote.
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir(parents=True)
    return UnelevatedMember(take_log_baseline(BRIDGE_LOG), gsudo_environment, scratch)


def assert_only_the_bridges_grant_admits(record: dict) -> None:
    """The child is who the test is about: a member of `hole` that neither Administrators nor the group in its own
    token would admit. Otherwise the run passes whatever the bridge did, so it fails here and says which way."""
    assert record["exit_code"] == 0, f"the de-elevated child could not run the installed `hole version`: {record}"
    enabled = set(record["enabled_group_sids"])
    assert ADMINISTRATORS_SID not in enabled, (
        "the child still holds Administrators as an enabled group, so the de-elevation did not take: the socket's "
        "Administrators entry admits it whatever the bridge granted the user"
    )
    group = record["hole_group_sid"]
    assert group is not None, "there is no `hole` group after the install"
    assert group not in enabled, (
        "the child's token already carries the `hole` group, so its sign-in is newer than the membership: the group's "
        "entry admits it, and the run cannot show what a restart does to a user who has not signed in again"
    )
    assert isinstance(record["hole_member_sids"], list) and record["user_sid"] in record["hole_member_sids"], (
        f"the user this test runs as ({record['user_sid']}) is not a member of `hole` ({record['hole_member_sids']}): "
        "the installer adds the user of the console session, and this run is someone else"
    )
