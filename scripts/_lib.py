"""Shared helpers for dev.py and network-reset.py — elevation detection.

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
