#!/usr/bin/env python3
"""Emergency network reset script for Hole.

Removes routes, adapters, and stale processes left behind by a crashed
bridge. State-file-aware: reads `bridge-routes.json` (if present) from
candidate state directories to target the exact leaked bypass route
rather than blindly removing every /32 or /128 on the machine.

Run with admin/root privileges:
  macOS:   sudo python3 scripts/network-reset.py
  Windows: run from an elevated PowerShell
"""
# /// script
# requires-python = ">=3.9"
# ///
from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

import _lib

# Keep in sync with `crates/tun-engine/src/routing/state.rs::STATE_FILE_NAME`.
STATE_FILE_NAME = "bridge-routes.json"


def run(cmd: list[str], *, check: bool = False) -> subprocess.CompletedProcess[str]:
    print(f"  $ {' '.join(cmd)}")
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def candidate_state_dirs() -> list[Path]:
    """Candidate state directories, in the order the bridge and dev.py
    might have written to them. First valid JSON wins."""
    dirs: list[Path] = []
    if platform.system() == "Windows":
        program_data = os.environ.get("ProgramData", r"C:\ProgramData")
        dirs.append(Path(program_data) / "hole" / "state")  # service
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            dirs.append(Path(local_app_data) / "hole" / "state")  # default user
    elif platform.system() == "Darwin":
        dirs.append(Path("/var/db/hole/state"))  # service
        dirs.append(Path.home() / "Library" / "Application Support" / "hole" / "state")
    dirs.append(Path(tempfile.gettempdir()) / "hole-dev" / "state")  # dev.py
    return dirs


def load_state_file() -> dict | None:
    """Return the first valid parsed state file found across candidate
    directories, or None if none exists / all are corrupted."""
    for d in candidate_state_dirs():
        path = d / STATE_FILE_NAME
        if not path.exists():
            continue
        try:
            with path.open() as f:
                data = json.load(f)
            print(f"  Found state file at {path}")
            return data
        except (json.JSONDecodeError, OSError) as e:
            print(f"  Skipping {path} (parse error: {e})")
    return None


def reset_macos(state: dict | None) -> None:
    print("Removing split routes (IPv4 + IPv6)...")
    run(["route", "-n", "delete", "-net", "0.0.0.0/1"])
    run(["route", "-n", "delete", "-net", "128.0.0.0/1"])
    run(["route", "-n", "delete", "-inet6", "::/1"])
    run(["route", "-n", "delete", "-inet6", "8000::/1"])

    if state is not None:
        server_ip = state.get("server_ip", "")
        if ":" in server_ip:
            print(f"Removing IPv6 bypass route for {server_ip}...")
            run(["route", "-n", "delete", "-inet6", "-host", server_ip])
        elif server_ip:
            print(f"Removing IPv4 bypass route for {server_ip}...")
            run(["route", "-n", "delete", "-host", server_ip])
    else:
        print(
            "  No state file found — cannot identify per-server bypass route. "
            "If you still have connectivity issues, run 'netstat -rn' and "
            "remove any host routes pointing at a stale hole-tun interface."
        )

    print("Killing bridge and v2ray-plugin processes...")
    # Match both the installed binary (`/usr/local/bin/hole bridge run ...`)
    # and the dev-copied binary (`$TMPDIR/hole-dev-<pid>/hole bridge run ...`).
    # ERE: `hole` followed by zero-or-more non-space chars, then ` bridge run`.
    run(["pkill", "-fE", r"hole[^ ]* bridge run"])
    run(["pkill", "-f", "v2ray-plugin"])

    print("Flushing route cache and DNS cache...")
    run(["route", "-n", "flush"])
    run(["dscacheutil", "-flushcache"])
    run(["killall", "-HUP", "mDNSResponder"])


def reset_windows(state: dict | None) -> None:
    print("Removing split routes (IPv4 + IPv6, scoped to hole-tun*)...")
    for prefix in ("0.0.0.0/1", "128.0.0.0/1", "::/1", "8000::/1"):
        run([
            "powershell",
            "-Command",
            f'Remove-NetRoute -DestinationPrefix "{prefix}" '
            f'-InterfaceAlias "hole-tun*" -Confirm:$false -ErrorAction SilentlyContinue',
        ])

    if state is not None:
        server_ip = state.get("server_ip", "")
        if ":" in server_ip:
            print(f"Removing IPv6 bypass route for {server_ip}...")
            run([
                "powershell",
                "-Command",
                f'Remove-NetRoute -DestinationPrefix "{server_ip}/128" '
                f'-Confirm:$false -ErrorAction SilentlyContinue',
            ])
        elif server_ip:
            print(f"Removing IPv4 bypass route for {server_ip}...")
            run([
                "powershell",
                "-Command",
                f'Remove-NetRoute -DestinationPrefix "{server_ip}/32" '
                f'-Confirm:$false -ErrorAction SilentlyContinue',
            ])
    else:
        print(
            "  No state file found — cannot identify per-server bypass route. "
            "If you still have connectivity issues, run 'Get-NetRoute' and "
            "remove any host routes pointing at a stale hole-tun interface."
        )

    print("Stopping HoleBridge service and killing bridge + v2ray-plugin processes...")
    run([
        "powershell",
        "-Command",
        'Stop-Service -Name "HoleBridge" -Force -ErrorAction SilentlyContinue',
    ])
    # The dev bridge is now staged at `%TEMP%\hole-dev-<pid>\hole.exe`, so
    # `Name = 'hole.exe'` matches both installed and dev. The `LIKE 'hole%.exe'`
    # wildcard is kept to also catch any older `hole-dev-bridge-<pid>.exe`
    # left behind by an earlier dev.py version. Command-line filter ensures we
    # only hit the bridge subcommand and not the GUI.
    run([
        "powershell",
        "-Command",
        """
        Get-CimInstance Win32_Process -Filter "Name LIKE 'hole%.exe'" |
            Where-Object { $_.CommandLine -like '*bridge run*' } |
            ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
        """,
    ])
    run([
        "powershell",
        "-Command",
        'Get-Process -Name "v2ray-plugin" -ErrorAction SilentlyContinue | Stop-Process -Force',
    ])

    print("Removing wintun adapters...")
    run([
        "powershell",
        "-Command",
        """
        Get-NetAdapter -Name "hole-tun*" -ErrorAction SilentlyContinue |
            ForEach-Object {
                Write-Host "  Removing: $($_.Name)"
                Remove-NetAdapter -Name $_.Name -Confirm:$false -ErrorAction SilentlyContinue
            }
        """,
    ])

    print("Flushing DNS cache...")
    run(["ipconfig", "/flushdns"])

    print()
    print("If still broken, run these as Administrator and reboot:")
    print("  netsh winsock reset")
    print("  netsh int ip reset")


def main() -> None:
    print("=== Hole Emergency Network Reset ===")
    print()

    _lib.require_elevation()

    print("Looking for route-state file...")
    state = load_state_file()
    print()

    system = platform.system()
    if system == "Darwin":
        reset_macos(state)
    elif system == "Windows":
        reset_windows(state)
    else:
        print(f"Unsupported platform: {system}", file=sys.stderr)
        sys.exit(1)

    print()
    print("Done. Test connectivity: curl -I https://example.com")


if __name__ == "__main__":
    main()
