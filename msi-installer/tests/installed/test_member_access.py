"""The user the installer granted reaches the installed bridge as themselves, before and after the bridge restarts.

Every other installed case talks to the bridge from this elevated process, which the socket's Administrators entry
admits whatever the bridge granted anyone else. Here the requests come from a child that is not elevated and whose
token was made before the install. Windows adds a new group membership to a token only at the next sign-in, so that
token has no `hole` group in it, and the child is admitted only by what the bridge wrote into the socket's access list
for the user. The bridge writes that list at every start, so the test restarts the service twice: an in-app update, a
crash restart and a manual restart all start the bridge again inside the same sign-in session.

The second test takes the user out of the group and restarts the bridge, then runs the elevated
`hole bridge grant-access` the app offers a refused user, and connects with no further restart.

The third puts a member into `hole` whose account does not exist (what a deleted domain account leaves behind), restarts
the bridge, and checks that the bridge lists it among the members and still admits the user.

A request is the whole connection of `connect_journey`, to a server with no plugin: it needs the `ss_plugin_server`
example built (`cargo build -p plugin-e2e --example ss_plugin_server`). The child is de-elevated with `gsudo`, as the
dashboard E2E is.
"""

import ctypes
import itertools
import json
import shutil
import subprocess
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path

import pytest
from connect_journey import connect_and_fetch
from connect_journey import ss_server, target  # noqa: F401 (fixtures)
from support import (
    BIN_DIR,
    BRIDGE_LOG,
    BRIDGE_SOCKET,
    HOLE_CLI_TIMEOUT_SECONDS,
    RECORD_RUN,
    RUN_AT_MEDIUM,
    SERVICE,
    LogBaseline,
    hole_command_report,
    log_dir,
    log_gained,
    restart_service,
    run_ps,
    take_log_baseline,
)
from support import gsudo_environment, installed_hole, msi_path  # noqa: F401 (fixtures)

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-member-access"

# Where `record-run.ps1` reads its spec from.
SPEC_ENV = "HOLE_RECORD_RUN_SPEC"

ADMINISTRATORS_SID = "S-1-5-32-544"

# A SID of a domain no machine here can resolve. Deleting a local user takes it out of its groups (measured on the
# guest), so a member with no account is made the way a domain account's deletion leaves one: a SID the group holds
# and nothing resolves.
NO_ACCOUNT_SID = "S-1-5-21-111111111-222222222-333333333-1234"


@dataclass
class UnelevatedMember:
    """The installed `hole.exe`, run by a child of this process that `gsudo` de-elevated."""

    # The service's log as the test found it: a failure shows what the log gained since.
    bridge_log: LogBaseline
    environment: Mapping[str, str]
    # A folder the child can read and write: the specs and results of the runs, and the journey's server entry.
    scratch: Path
    # Where the test is, for a failure's text.
    phase: str = "before any restart"
    runs: int = 0
    # How the child's own connect to the bridge's socket went after its last command: `None` is accepted.
    socket_refusal: str | None = None

    def recorded(self, *args: str) -> dict:
        """Run `hole.exe args` in the de-elevated child; return what `record-run.ps1` recorded of the run and of the
        child's token. A child still running at `HOLE_CLI_TIMEOUT_SECONDS` is killed and raises `TimeoutError`."""
        self.runs += 1
        spec = self.scratch / f"run-{self.runs}.json"
        result = self.scratch / f"run-{self.runs}-result.json"
        spec.write_text(
            json.dumps({
                "exe": str(BIN_DIR / "hole.exe"),
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
            phase=f"`hole {' '.join(args)}` in the de-elevated child",
        )
        assert result.is_file(), (
            f"the de-elevated child recorded nothing for `hole {' '.join(args)}` (the launcher exited {code}): "
            "see its output above"
        )
        record = json.loads(result.read_text(encoding="utf-8"))
        self.socket_refusal = record["socket_refusal"]
        return record

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
            f"the same user's own connect to {BRIDGE_SOCKET} after its last `hole` command was {connect}",
            result,
            self.bridge_log,
        )


@pytest.fixture
def member(installed_hole: Path, gsudo_environment: dict[str, str]) -> UnelevatedMember:
    # Not `tmp_path`: pytest makes it with mode 0o700, which on Windows admits only its owner, and a folder this
    # elevated process makes is owned by Administrators. A folder made without a mode inherits its parent's access.
    scratch = log_dir() / "member-access"
    # Emptied, so a result read below is one this run wrote.
    shutil.rmtree(scratch, ignore_errors=True)
    scratch.mkdir()
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


@pytest.mark.parametrize("ss_server", ["none"], indirect=True)
def test_the_installing_user_reaches_the_bridge_before_and_after_restarts(
    member: UnelevatedMember, ss_server: dict, target: tuple[int, str]
):
    assert_only_the_bridges_grant_admits(member.recorded("version"))

    connect_and_fetch(member, ss_server, None, target, member.scratch)
    for restart in (1, 2):
        restart_service()
        member.phase = f"after restart {restart} of the {SERVICE} service"
        connect_and_fetch(member, ss_server, None, target, member.scratch)


def remove_from_hole_group(user_sid: str) -> None:
    """Take `user_sid` out of the `hole` group, from this elevated process."""
    removed = subprocess.run(
        ["powershell", "-NoProfile", "-Command", f"Remove-LocalGroupMember -Group hole -Member '{user_sid}'"],
        capture_output=True,
        text=True,
        errors="replace",
    )
    assert removed.returncode == 0, f"could not take {user_sid} out of `hole`: {removed.stderr}"


@pytest.mark.parametrize("ss_server", ["none"], indirect=True)
def test_grant_access_admits_a_user_while_the_bridge_runs(
    member: UnelevatedMember, ss_server: dict, target: tuple[int, str]
):
    """An elevated `hole bridge grant-access`, which the app runs for a user the bridge refused, admits that user to a
    bridge that is already running.

    The user starts outside the group, with a bridge that started without them: then nothing but `grant-access` can
    be what lets them in.
    """
    before = member.recorded("version")
    assert_only_the_bridges_grant_admits(before)
    remove_from_hole_group(before["user_sid"])
    restart_service()
    outside = member.recorded("proxy", "stop")
    assert outside["exit_code"] != 0 and "permission denied" in outside["stderr"], (
        f"`hole proxy stop` by the user after leaving `hole` and a bridge restart was not refused, so this run cannot "
        f"show that `grant-access` is what admits them: {outside}"
    )
    # The same fact from the socket itself, which also names the error.
    assert outside["socket_refusal"] is not None, (
        f"the user still connects to {BRIDGE_SOCKET} after leaving `hole` and a bridge restart, so this run cannot "
        "show that `grant-access` is what admits them"
    )

    granted = subprocess.run(
        [str(BIN_DIR / "hole.exe"), "bridge", "grant-access"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=HOLE_CLI_TIMEOUT_SECONDS,
    )
    assert granted.returncode == 0, hole_command_report(
        "the elevated `hole bridge grant-access` failed", granted, member.bridge_log
    )

    member.phase = "after an elevated `hole bridge grant-access`, with no bridge restart"
    connect_and_fetch(member, ss_server, None, target, member.scratch)


def change_group_member(function: str, group: str, sid: str) -> None:
    """`NetLocalGroupAddMembers` or `NetLocalGroupDelMembers` (`function`) at level 0, a member by SID alone, for the one
    SID `sid`. Not `Add-LocalGroupMember`: it refuses a SID it cannot find an account for."""
    psid = ctypes.c_void_p()
    if not ctypes.windll.advapi32.ConvertStringSidToSidW(sid, ctypes.byref(psid)):
        raise ctypes.WinError()
    # A `LOCALGROUP_MEMBERS_INFO_0` is one pointer to a SID.
    entry = ctypes.c_void_p(psid.value)
    try:
        status = getattr(ctypes.windll.netapi32, function)(None, group, 0, ctypes.byref(entry), 1)
    finally:
        ctypes.windll.kernel32.LocalFree(psid)
    assert status == 0, f"{function}({group!r}, {sid}) failed: error {status}"


@pytest.fixture
def member_with_no_account(member: UnelevatedMember) -> Iterator[str]:
    change_group_member("NetLocalGroupAddMembers", "hole", NO_ACCOUNT_SID)
    try:
        yield NO_ACCOUNT_SID
    finally:
        change_group_member("NetLocalGroupDelMembers", "hole", NO_ACCOUNT_SID)


def members_the_bridge_logged(bridge_log: str) -> str:
    """The `members` field of the last record in `bridge_log` that says which access list the bridge set."""
    lines = bridge_log.splitlines()
    starts = [i for i, line in enumerate(lines) if "IPC restricted to SYSTEM + Administrators + the hole group" in line]
    assert starts, f"the bridge logged no access list with the `hole` group in it:\n{bridge_log}"
    fields = itertools.takewhile(lambda line: line[:1].isspace(), lines[starts[-1] + 1 :])
    members = next((line for line in fields if line.strip().startswith("members:")), None)
    assert members is not None, f"the bridge's access-list record has no `members` field:\n{bridge_log}"
    return members


@pytest.mark.parametrize("ss_server", ["none"], indirect=True)
def test_a_member_with_no_account_is_listed_and_does_not_lock_the_user_out(
    member: UnelevatedMember, member_with_no_account: str, ss_server: dict, target: tuple[int, str]
):
    """A member of `hole` whose account no longer exists does not stop the bridge from admitting the others.

    The bridge restarts with such a member in the group: its log lists that SID among the members, and the user, who
    has not signed in since joining, still connects.
    """
    before = member.recorded("version")
    assert_only_the_bridges_grant_admits(before)
    assert member_with_no_account in before["hole_member_sids"], (
        f"the group does not list {member_with_no_account} for the child that reads it: {before['hole_member_sids']}"
    )

    baseline = take_log_baseline(BRIDGE_LOG)
    restart_service()
    member.phase = f"after a restart of the {SERVICE} service with a member of `hole` that has no account"
    connect_and_fetch(member, ss_server, None, target, member.scratch)

    logged = members_the_bridge_logged(log_gained(baseline))
    for sid in (member_with_no_account, before["user_sid"]):
        assert sid in logged, f"the bridge's access list for its socket does not name {sid}: {logged}"
