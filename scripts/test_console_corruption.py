#!/usr/bin/env python3
"""Test that dev.py child processes don't corrupt the Windows console.

Reproduces the bug: launching a subprocess that inherits stdin allows it to
modify console input modes (e.g., node.js sets raw mode for keyboard shortcuts).
When the subprocess is terminated (not cleanly exited), the console mode is not
restored — breaking arrow keys and echo in the parent terminal.

Fix: redirect stdin to DEVNULL for all child processes. None of them need
interactive input, and DEVNULL prevents them from accessing the console input.

Usage (Windows only, must be run in a real console — not piped):
  uv run scripts/test_console_corruption.py
"""
# /// script
# requires-python = ">=3.9"
# ///

import ctypes
import ctypes.wintypes
import shutil
import subprocess
import sys
import time

if sys.platform != "win32":
    print("SKIP: this test only runs on Windows")
    sys.exit(0)

kernel32 = ctypes.windll.kernel32
STD_INPUT_HANDLE = ctypes.wintypes.DWORD(-10 & 0xFFFFFFFF)


def get_console_input_mode() -> int | None:
    """Get the current console input mode, or None if stdin is not a console."""
    handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
    mode = ctypes.wintypes.DWORD()
    if kernel32.GetConsoleMode(handle, ctypes.byref(mode)) == 0:
        return None
    return mode.value


def mode_flags(mode: int) -> str:
    """Format console mode as human-readable flags."""
    flags = {
        0x0001: "ENABLE_PROCESSED_INPUT",
        0x0002: "ENABLE_LINE_INPUT",
        0x0004: "ENABLE_ECHO_INPUT",
        0x0008: "ENABLE_WINDOW_INPUT",
        0x0010: "ENABLE_MOUSE_INPUT",
        0x0020: "ENABLE_INSERT_MODE",
        0x0040: "ENABLE_QUICK_EDIT_MODE",
        0x0200: "ENABLE_VIRTUAL_TERMINAL_INPUT",
    }
    active = [name for bit, name in flags.items() if mode & bit]
    return f"0x{mode:04x} ({', '.join(active)})"


def run_and_terminate(cmd: list[str], *, stdin_devnull: bool) -> None:
    """Launch a subprocess, wait briefly, then terminate it."""
    stdin_arg = subprocess.DEVNULL if stdin_devnull else None
    proc = subprocess.Popen(
        cmd,
        stdin=stdin_arg,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    time.sleep(2)
    proc.terminate()
    proc.wait(timeout=10)


def test_subprocess(label: str, cmd: list[str], *, stdin_devnull: bool) -> bool:
    """Run a subprocess test and return True if console mode was preserved."""
    before = get_console_input_mode()
    if before is None:
        print(f"  SKIP: stdin is not a console (are you piping?)")
        return True

    print(f"  Before: {mode_flags(before)}")
    run_and_terminate(cmd, stdin_devnull=stdin_devnull)
    after = get_console_input_mode()
    if after is None:
        print(f"  FAIL: {label} — stdin is no longer a console")
        return False
    print(f"  After:  {mode_flags(after)}")

    if before == after:
        print(f"  PASS: {label}")
        return True

    print(f"  FAIL: {label} — console mode changed!")
    # Restore for subsequent tests
    handle = kernel32.GetStdHandle(STD_INPUT_HANDLE)
    kernel32.SetConsoleMode(handle, before)
    return False


def main() -> None:
    npm = shutil.which("npm")
    if not npm:
        print("npm not found on PATH")
        sys.exit(1)

    vite_cmd = [npm, "run", "dev"]

    print("=" * 60)
    print("Test 1: inherited stdin (EXPECT FAIL — reproduces the bug)")
    print("=" * 60)
    bug_reproduced = not test_subprocess("inherited stdin", vite_cmd, stdin_devnull=False)

    print()
    print("=" * 60)
    print("Test 2: stdin=DEVNULL (EXPECT PASS — the fix)")
    print("=" * 60)
    fix_works = test_subprocess("stdin=DEVNULL", vite_cmd, stdin_devnull=True)

    print()
    if bug_reproduced and fix_works:
        print("RESULT: Bug reproduced and fix confirmed.")
        sys.exit(0)
    elif not bug_reproduced:
        print("RESULT: Bug did NOT reproduce (console mode was not modified).")
        print("  This may happen if Vite's version doesn't use raw stdin,")
        print("  or if the test is run in a non-interactive console.")
        sys.exit(1)
    else:
        print("RESULT: Fix did NOT work — console mode still changed with DEVNULL.")
        sys.exit(1)


if __name__ == "__main__":
    main()
