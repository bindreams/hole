"""A Windows machine as the full-tunnel journey (`connect_journey.full_tunnel_journey`) sees it.

What the operating system says is read by `.github/scripts/network-state.ps1`, from this elevated process: the
answers do not depend on who asks. The `curl` is the person's, run by the de-elevated child of `member.py`.
"""

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from member import UnelevatedMember
from support import SCRIPTS

NETWORK_STATE = SCRIPTS / "network-state.ps1"

# The `curl` Windows ships, not whichever one a `PATH` names first.
CURL = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / "curl.exe"


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
        assert result.returncode == 0, f"network-state.ps1 -What {what} exited {result.returncode}:\n{result.stderr}"
        return result.stdout

    def default_interface(self) -> str:
        return self._state("default-interface").strip()

    def snapshot(self) -> str:
        return self._state("snapshot")

    def dns_servers(self) -> dict[str, frozenset[str]]:
        servers = {}
        for line in self._state("dns-servers").splitlines():
            scope, _, addresses = line.partition("|")
            servers[scope] = frozenset(address for address in addresses.split(",") if address)
        return servers

    def run_curl(self, *args: str) -> subprocess.CompletedProcess[str]:
        command = [str(CURL), *args]
        try:
            record = self.person.recorded_command(CURL, *args)
        except TimeoutError as e:
            # Returned as a failed command, not raised: the journey reports it, with the bridge's log.
            return subprocess.CompletedProcess(command, returncode=-1, stdout="", stderr=f"(killed: {e})")
        return subprocess.CompletedProcess(command, record["exit_code"], record["stdout"], record["stderr"])
