"""A macOS machine as the full-tunnel journey (`connect_journey.full_tunnel_journey`) sees it.

Written without a macOS host to run it on; the first run is the CI install-e2e step. What it reads is the output of
`route`, `netstat`, `ifconfig` and `scutil`, which Hole's tunnel changes; the `curl` is this process's own.
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


class MacMachine:
    def default_interface(self) -> str:
        """`interface: en0` in `route -n get default`."""
        match = re.search(r"^\s*interface:\s*(\S+)", _output("route", "-n", "get", "default"), re.MULTILINE)
        assert match is not None, "`route -n get default` names no interface: the machine has no default route"
        return match.group(1)

    def snapshot(self) -> str:
        """The network routes (not the host entries the ARP and neighbour caches add and expire), the interface names
        and the resolver configuration."""
        routes = [
            line
            for family in ("inet", "inet6")
            for line in _output("netstat", "-rn", "-f", family).splitlines()
            if line.startswith("default") or "/" in line.split(" ", 1)[0]
        ]
        return "\n".join([
            "== routes",
            *routes,
            "== interfaces",
            _output("ifconfig", "-l").strip(),
            "== resolvers",
            _output("scutil", "--dns").split(_SCOPED_SECTION)[0],
        ])

    def dns_servers(self) -> dict[str, frozenset[str]]:
        """The nameservers of each `resolver #N` of `scutil --dns`, by that heading."""
        servers: dict[str, set[str]] = {}
        scope = None
        for line in _output("scutil", "--dns").split(_SCOPED_SECTION)[0].splitlines():
            if heading := re.match(r"^resolver #\d+", line.strip()):
                scope = heading.group(0)
                servers[scope] = set()
            elif scope is not None and (nameserver := re.match(r"^\s*nameserver\[\d+\]\s*:\s*(\S+)", line)):
                servers[scope].add(nameserver.group(1))
        return {scope: frozenset(addresses) for scope, addresses in servers.items()}

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(["curl", *args], capture_output=True, text=True, encoding="utf-8", errors="replace")
