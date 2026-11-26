"""A Windows machine as the full-tunnel journey (`connect_journey.full_tunnel_journey`) sees it.

What the operating system says is read by `.github/scripts/network-state.ps1`, from this elevated process: the
answers do not depend on who asks. The `curl` is the person's, run by the de-elevated child of `member.py`.
"""

import json
import os
import subprocess
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TypeVar

from connect_journey import DnsWatch, MachineReadError, Resolver, Route, Snapshot
from member import UnelevatedMember
from support import SCRIPTS

NETWORK_STATE = SCRIPTS / "network-state.ps1"

# The `curl` Windows ships, not whichever one a `PATH` names first.
CURL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"

# What Windows lists as the IPv6 DNS servers of an interface that was given none.
_NO_IPV6_SERVER = ("fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3")

T = TypeVar("T")


class _AlreadySettled:
    """Windows has taken a DNS server in by the time the call that set it returns."""

    def settle(self, read: Callable[[], T], settled: Callable[[T], bool]) -> T:
        return read()


@dataclass(frozen=True)
class WindowsMachine:
    person: UnelevatedMember

    def _state(self, what: str) -> str:
        result = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
                str(NETWORK_STATE),
                "-What",
                what,
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode != 0:
            raise MachineReadError(f"network-state.ps1 -What {what} exited {result.returncode}:\n{result.stderr}")
        return result.stdout

    def default_interface(self) -> str:
        return self._state("default-interface").strip()

    def snapshot(self) -> Snapshot:
        text = self._state("snapshot")
        try:
            state = json.loads(text)
        except json.JSONDecodeError as e:
            raise MachineReadError(f"network-state.ps1 -What snapshot printed no JSON ({e}):\n{text}") from e
        return Snapshot(
            interfaces=tuple(sorted(state["interfaces"])),
            routes=tuple(
                sorted(
                    Route(route["destination"], route["gateway"], route["interface"], f"metric {route['metric']}")
                    for route in state["routes"]
                )
            ),
            addresses=tuple(sorted(state["addresses"])),
            resolvers=tuple(
                sorted(
                    Resolver(
                        scope=f"{dns['interface']} {dns['family']}",
                        servers=() if tuple(dns["servers"]) == _NO_IPV6_SERVER else tuple(dns["servers"]),
                        interface=dns["interface"],
                    )
                    for dns in state["dns"]
                )
            ),
        )

    @contextmanager
    def watch_dns(self) -> Iterator[DnsWatch]:
        yield _AlreadySettled()

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [str(CURL), *args]
        try:
            record = self.person.recorded_command(CURL, *args)
        except TimeoutError as e:
            # Returned as a failed command, not raised: the journey reports it, with the bridge's log.
            return subprocess.CompletedProcess(command, returncode=-1, stdout="", stderr=f"(killed: {e})")
        return subprocess.CompletedProcess(command, record["exit_code"], record["stdout"], record["stderr"])
