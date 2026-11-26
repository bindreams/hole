"""The installed product carries a person's traffic through a full tunnel: the default of `hole proxy start`.

The case a person meets when they press Connect: every route of the machine goes into the tunnel, its DNS is pointed at
Hole, and a page from outside the machine arrives by address and by name. The person is not elevated and is a member of
`hole` whose token predates the membership (`member.py`); the `HoleBridge` service the MSI registered does the work that
needs rights.

The far side is the `ss_plugin_server` example, behind each bundled plugin and with none. It runs on this machine, so
its own dials leave through the machine's default interface, not the routing table, which the tunnel now owns. It
listens on loopback: Windows refuses the host route for the machine's own address (`WindowsMachine.far_side_address`).
It needs
the example built (`cargo build -p plugin-e2e --example ss_plugin_server`), the working tree's `galoshes` and `ex-ray`
builds, and the internet: `1.1.1.1` is the address asked for, the name asked for is `one.one.one.one`, and the
product's own default DNS is DoH to `1.1.1.1`.

A separate file with its own install and its own `msiexec` logs, as `test_connect.py` is: a failed full tunnel then
cannot change what the other cases meet.
"""

from collections import Counter
from collections.abc import Iterator
from pathlib import Path

import pytest
from connect_journey import SERVER_IDS, SERVERS, full_tunnel_journey, run_far_side
from member import UnelevatedMember, assert_only_the_bridges_grant_admits
from member import member  # noqa: F401 (fixture)
from support import SERVICE, _log_records, log_gained, restart_service
from support import gsudo_environment, installed_hole, msi_path  # noqa: F401 (fixtures)
from windows_machine import WindowsMachine

pytestmark = pytest.mark.system_wide

# This module's install and uninstall logs (`installed_hole`).
MSIEXEC_LOG_STEM = "msi-full-tunnel"

# Measurement of why the galoshes case stalls (bindreams/hole#1377); to be reverted ====================================

# What the service starts with: galoshes (which the bridge starts and which inherits it) at debug for yamux, and the
# bridge's file log at debug for the lines that name each UDP flow and each reply the engine writes to the tunnel.
SERVICE_ENVIRONMENT = [
    "RUST_LOG=info,yamux=debug",
    "HOLE_BRIDGE_LOG=hole_bridge=info,hole_bridge::hole_router=debug,tun_engine::engine::driver=debug",
]
SERVICE_KEY = rf"SYSTEM\CurrentControlSet\Services\{SERVICE}"


@pytest.fixture(scope="module", autouse=True)
def bridge_debug_environment(installed_hole: Path) -> Iterator[None]:
    """The `HoleBridge` service's `Environment` value holds `SERVICE_ENVIRONMENT` while this module runs."""
    import winreg  # Windows only

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, SERVICE_KEY, 0, winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        try:
            previous = winreg.QueryValueEx(key, "Environment")[0]
        except FileNotFoundError:
            previous = None
        winreg.SetValueEx(key, "Environment", 0, winreg.REG_MULTI_SZ, [*(previous or []), *SERVICE_ENVIRONMENT])
        try:
            restart_service()
            yield
        finally:
            if previous is None:
                winreg.DeleteValue(key, "Environment")
            else:
                winreg.SetValueEx(key, "Environment", 0, winreg.REG_MULTI_SZ, previous)
            restart_service()


def _fields(record: list[str]) -> dict[str, str]:
    """The `key: value` lines of a log record, quotes removed."""
    fields = {}
    for line in record[1:]:
        key, _, value = line.strip().partition(": ")
        fields[key] = value.strip("'\"")
    return fields


def udp_flow_summary(log: str) -> str:
    """What the bridge's debug lines say of the UDP flows of the tunnel, and the yamux lines about streams waiting for ACK.

    A flow is a (source, destination) pair; a reply written to the tunnel names the same pair, swapped. The yamux lines
    are grouped by their text after the timestamps, each group with its count and its first and last line.
    """
    flows: Counter[tuple[str, str, str]] = Counter()
    replied: set[tuple[str, str]] = set()
    for record in _log_records(log):
        fields = _fields(record)
        if "UDP flow dispatched" in record[0]:
            flows[(fields["src"], fields["dst"], fields["endpoint"])] += 1
        elif "UDP flow dropped" in record[0]:
            flows[(fields["src"], fields["dst"], "(dropped)")] += 1
        elif record[0].rstrip(":").endswith("UDP reply"):
            replied.add((fields["dst"], fields["src"]))
    per_destination: Counter[tuple[str, str]] = Counter()
    answered: Counter[tuple[str, str]] = Counter()
    for (src, dst, endpoint), count in flows.items():
        per_destination[(dst, endpoint)] += count
        answered[(dst, endpoint)] += (src, dst) in replied
    total = sum(flows.values())
    lines = [
        f"UDP flows the engine created: {total}, to {len({dst for dst, _ in per_destination})} distinct "
        f"destinations; {sum(answered.values())} got a reply, {total - sum(answered.values())} did not",
        *(
            f"  {dst} via {endpoint}: {count} flow(s), {answered[(dst, endpoint)]} with a reply"
            for (dst, endpoint), count in sorted(per_destination.items())
        ),
    ]
    waiting: dict[str, list[str]] = {}
    for line in log.splitlines():
        if "streams waiting for ACK" in line:
            waiting.setdefault(line.partition("yamux::connection:")[2], []).append(line)
    lines.append(f"yamux lines about streams waiting for ACK: {sum(map(len, waiting.values()))}")
    for text, group in waiting.items():
        lines += [f"  {len(group)} line(s) of{text}", f"    first: {group[0]}", f"    last: {group[-1]}"]
    return "\n".join(lines)


def show_udp_flows(member: UnelevatedMember) -> None:
    """Print `udp_flow_summary` of what the bridge logged since the test began, whether the case passes or fails."""
    try:
        summary = udp_flow_summary(log_gained(member.bridge_log))
    except AssertionError as e:
        summary = f"(no summary: {e})"
    print(f"=== the tunnel's UDP flows (T8i measurement) ===\n{summary}", flush=True)


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
        show_udp_flows(member)
