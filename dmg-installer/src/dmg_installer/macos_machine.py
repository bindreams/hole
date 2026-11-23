"""A macOS machine as the full-tunnel journey (`connect_journey.full_tunnel_journey`) sees it.

Written without a macOS host to run it on; the first run is the CI install-e2e step. What it reads is the output of
`route`, `netstat`, `ifconfig` and `scutil`, which Hole's tunnel changes; the `curl` is this process's own, run as the
user of the test, while `hole` runs as root.
"""

import re
import subprocess

# `scutil --dns` prints the resolvers of two sections; the second, for scoped queries, is the per-interface view of the
# same configuration and is left out.
_SCOPED_SECTION = "DNS configuration (for scoped queries)"


def _output(*command: str) -> str:
    result = subprocess.run(command, capture_output=True, text=True, errors="replace")
    assert result.returncode == 0, (
        f"`{' '.join(command)}` exited {result.returncode}:\n{result.stdout}\n{result.stderr}"
    )
    return result.stdout


def _is_network_route(columns: list[str]) -> bool:
    """A row of `netstat -rn` that routes a network or is the default: not a heading, not a host route (flag `H`) and not
    a neighbour or cloned entry (flag `W`), which the caches add and expire."""
    return len(columns) >= 4 and columns[0] != "Destination" and not {"H", "W"} & set(columns[2])


def _resolvers() -> dict[str, frozenset[str]]:
    """The resolvers of `scutil --dns` by their own text (flags, order, reachability) without the `resolver #N` heading:
    the numbers follow the order, which changes when a resolver is added, and the rest of a resolver does not."""
    section = _output("scutil", "--dns").split(_SCOPED_SECTION)[0]
    resolvers = {}
    for block in re.split(r"^resolver #\d+\s*$", section, flags=re.MULTILINE)[1:]:
        text = "\n".join(line.strip() for line in block.strip().splitlines())
        resolvers[text] = frozenset(re.findall(r"nameserver\[\d+\]\s*:\s*(\S+)", block))
    return resolvers


class MacMachine:
    def default_interface(self) -> str:
        """`interface: en0` in `route -n get default`."""
        match = re.search(r"^\s*interface:\s*(\S+)", _output("route", "-n", "get", "default"), re.MULTILINE)
        assert match is not None, "`route -n get default` names no interface: the machine has no default route"
        return match.group(1)

    def snapshot(self) -> str:
        """The network routes, the interface names and the resolver configuration."""
        routes = [
            " ".join(columns[:4])
            for family in ("inet", "inet6")
            for line in _output("netstat", "-rn", "-f", family).splitlines()
            if _is_network_route(columns := line.split())
        ]
        return "\n".join([
            "== routes",
            *routes,
            "== interfaces",
            _output("ifconfig", "-l").strip(),
            "== resolvers",
            *_resolvers(),
        ])

    def dns_servers(self) -> dict[str, frozenset[str]]:
        return _resolvers()

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["curl", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
