"""The user the installer granted reaches the installed bridge as themselves, before and after the bridge restarts.

The connect case talks to the bridge from this elevated process, which the socket's Administrators entry admits
whatever the bridge granted anyone else. Here the requests come from a child that is not elevated and whose
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
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest
from connect_journey import connect_and_fetch
from connect_journey import ss_server, target  # noqa: F401 (fixtures)
from member import UnelevatedMember, assert_only_the_bridges_grant_admits
from member import member  # noqa: F401 (fixture)
from support import (
    BIN_DIR,
    BRIDGE_LOG,
    BRIDGE_SOCKET,
    HOLE_CLI_TIMEOUT_SECONDS,
    SERVICE,
    hole_command_report,
    log_gained,
    restart_service,
    take_log_baseline,
)
from support import gsudo_environment, installed_hole, msi_path  # noqa: F401 (fixtures)

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-member-access"

# A SID of a domain no machine here can resolve. Deleting a local user takes it out of its groups (measured on the
# guest), so a member with no account is made the way a domain account's deletion leaves one: a SID the group holds
# and nothing resolves.
NO_ACCOUNT_SID = "S-1-5-21-111111111-222222222-333333333-1234"


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
