"""The installed product carries a person's traffic through a full tunnel: the default of `hole proxy start`.

The case a person meets when they press Connect: every route of the machine goes into the tunnel, its DNS is pointed at
Hole, and a page from outside the machine arrives by address and by name. The person is not elevated and is a member of
`hole` whose token predates the membership (`member.py`); the `HoleBridge` service the MSI registered does the work that
needs rights.

The far side is the `ss_plugin_server` example, behind each bundled plugin and with none. It runs on this machine, so
its own dials leave through the machine's default interface, not the routing table, which the tunnel now owns. It needs
the example built (`cargo build -p plugin-e2e --example ss_plugin_server`), the working tree's `galoshes` and `ex-ray`
builds, and the internet: `1.1.1.1` is the address asked for, the name asked for is `one.one.one.one`, and the
product's own default DNS is DoH to `1.1.1.1`.

A separate file with its own install and its own `msiexec` logs, as `test_connect.py` is: a failed full tunnel then
cannot change what the other cases meet.
"""

from pathlib import Path

import pytest
from connect_journey import SERVER_IDS, SERVERS, full_tunnel_journey, run_ss_server
from member import UnelevatedMember, assert_only_the_bridges_grant_admits
from member import member  # noqa: F401 (fixture)
from support import gsudo_environment, installed_hole, msi_path  # noqa: F401 (fixtures)
from windows_machine import WindowsMachine

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-full-tunnel"


@pytest.mark.parametrize(("plugin", "kind"), SERVERS, ids=SERVER_IDS)
def test_installed_full_tunnel_carries_a_page(member: UnelevatedMember, plugin: str | None, kind: str):
    assert_only_the_bridges_grant_admits(member.recorded("version"))
    machine = WindowsMachine(member)
    member.phase = "in the full tunnel"
    scratch: Path = member.scratch
    with run_ss_server(kind, scratch, machine.default_interface()) as server:
        full_tunnel_journey(member, server, plugin, machine, scratch)
