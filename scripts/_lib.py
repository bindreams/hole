"""Shared helpers for dev.py and network-reset.py — elevation detection
and sudo user drop for POSIX split-privilege workflows.

Imported by both scripts as a plain sibling module. Python adds each
script's own directory to sys.path at startup, so `import _lib` works
with both `python scripts/<script>.py` and `uv run scripts/<script>.py`.
"""
# PEP 604 union syntax (`X | None`) in runtime annotations is Python 3.10+.
# `from __future__ import annotations` stringifies all annotations so the
# scripts parse cleanly on the declared `requires-python = ">=3.9"`.
from __future__ import annotations

import os
import platform
import sys


def require_elevation() -> None:
    """Exit with code 1 and a clear message if not running elevated."""
    if platform.system() == "Windows":
        import ctypes

        if not ctypes.windll.shell32.IsUserAnAdmin():
            print(
                "ERROR: this script must run from an elevated PowerShell/terminal.",
                file=sys.stderr,
            )
            sys.exit(1)
    else:
        if os.geteuid() != 0:
            print("ERROR: this script must run as root (use sudo).", file=sys.stderr)
            sys.exit(1)


def sudo_target_user() -> tuple[int, int, str, str] | None:
    """Return (uid, gid, username, home) of the invoking user if running
    under `sudo` on POSIX, else None.

    Returns None if:
      - running on Windows (no equivalent concept — UAC preserves identity),
      - SUDO_USER is unset (not running under sudo),
      - SUDO_USER equals "root" (sudo -u root; no drop is meaningful),
      - pwd.getpwnam cannot resolve SUDO_USER (NIS/LDAP lookup failure;
        prints a warning and returns None so the caller falls back to
        keeping the child at root rather than crashing).
    """
    if platform.system() == "Windows":
        return None

    user = os.environ.get("SUDO_USER")
    if not user or user == "root":
        return None

    try:
        import pwd

        pw = pwd.getpwnam(user)
    except KeyError:
        print(
            f"WARNING: SUDO_USER='{user}' could not be resolved via pwd.getpwnam. "
            f"GUI will run as root; your real config will not be used.",
            file=sys.stderr,
        )
        return None

    return (pw.pw_uid, pw.pw_gid, user, pw.pw_dir)
