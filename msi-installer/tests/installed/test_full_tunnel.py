"""The installed product carries a person's traffic through a full tunnel: the default of `hole proxy start`.

The case a person meets when they press Connect: every route of the machine goes into the tunnel, its DNS is pointed at
Hole, and a page from outside the machine arrives by address and by name. The person is not elevated and is a member of
`hole` whose token predates the membership (`member.py`); the `HoleBridge` service the MSI registered does the work that
needs rights.

The far side is the `ss_plugin_server` example, behind each bundled plugin and with none. It runs on this machine, so
its own dials leave through the machine's default interface, not the routing table, which the tunnel now owns. It
listens on loopback: Windows refuses the host route for the machine's own address (`WindowsMachine.far_side_address`).
It needs the example built (`cargo build -p plugin-e2e --example ss_plugin_server`), the working tree's `galoshes` and
`ex-ray` builds, and the internet: `1.1.1.1` is the address asked for, the name asked for is `one.one.one.one`, and the
product's own default DNS is DoH to `1.1.1.1`.

A separate file with its own install and its own `msiexec` logs, as `test_connect.py` is: a failed full tunnel then
cannot change what the other cases meet.
"""

from collections.abc import Iterator
from pathlib import Path

import pytest
from connect_journey import SERVER_IDS, SERVERS, full_tunnel_journey, report_teardown_failure, run_far_side
from member import UnelevatedMember, assert_only_the_bridges_grant_admits
from member import member  # noqa: F401 (fixture)
from support import SERVICE, log_gained, restart_service
from support import gsudo_environment, installed_hole, msi_path  # noqa: F401 (fixtures)
from windows_machine import WindowsMachine

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-full-tunnel"

# What the service starts with: galoshes, which the bridge starts and which inherits it, logs yamux at `debug`, so that
# a case that stalls shows whether the transport refused new streams while 256 were unacknowledged
# (bindreams/hole#1377). The bridge's log carries the plugin's lines.
SERVICE_ENVIRONMENT = ["RUST_LOG=info,yamux=debug"]
SERVICE_KEY = rf"SYSTEM\CurrentControlSet\Services\{SERVICE}"
ACK_WAIT = "streams waiting for ACK"


@pytest.fixture(scope="module", autouse=True)
def yamux_debug_environment(installed_hole: Path, request: pytest.FixtureRequest) -> Iterator[None]:
    """The `HoleBridge` service's `Environment` value holds `SERVICE_ENVIRONMENT` while this module runs, in place of
    any entry of the same names (compared as Windows does, ignoring case)."""
    import winreg  # Windows only

    failed_before = request.session.testsfailed
    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        try:
            previous = winreg.QueryValueEx(key, "Environment")[0]
        except FileNotFoundError:
            previous = None
        names = {entry.partition("=")[0].casefold() for entry in SERVICE_ENVIRONMENT}
        kept = [entry for entry in previous or [] if entry.partition("=")[0].casefold() not in names]
        winreg.SetValueEx(key, "Environment", 0, winreg.REG_MULTI_SZ, [*kept, *SERVICE_ENVIRONMENT])
        try:
            restart_service()
            yield
        finally:
            if previous is None:
                winreg.DeleteValue(key, "Environment")
            else:
                winreg.SetValueEx(key, "Environment", 0, winreg.REG_MULTI_SZ, previous)
            try:
                restart_service()
            except AssertionError as e:
                # A bridge that died during a case cannot be stopped; that case's failure is the one to report.
                report_teardown_failure(str(e), primary_ok=request.session.testsfailed == failed_before)


def show_ack_waits(member: UnelevatedMember) -> None:
    """Print how many yamux lines about streams waiting for ACK the bridge's log gained since the test began, with the
    first and the last, whether the case passes or fails."""
    try:
        waiting = [line for line in log_gained(member.bridge_log).splitlines() if ACK_WAIT in line]
    except AssertionError as e:
        print(f"=== yamux: {ACK_WAIT} ===\n(not counted: {e})", flush=True)
        return
    ends = [f"  first: {waiting[0]}", f"  last: {waiting[-1]}"] if waiting else []
    print("\n".join([f"=== yamux: {ACK_WAIT} ===", f"{len(waiting)} line(s)", *ends]), flush=True)


@pytest.mark.parametrize(("plugin", "kind"), SERVERS, ids=SERVER_IDS)
def test_installed_full_tunnel_carries_a_page(member: UnelevatedMember, plugin: str | None, kind: str):
    assert_only_the_bridges_grant_admits(member.recorded("version"))
    machine = WindowsMachine(member)
    member.phase = "in the full tunnel"
    scratch: Path = member.scratch
    try:
        with run_far_side(kind, scratch, machine) as server:
            full_tunnel_journey(member, server, plugin, machine, scratch)
    finally:
        show_ack_waits(member)
