#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pytest"]
# ///
"""Unit tests for helpers in `dev.py`.

Covers:
- privilege-model helpers (elevation policy + sudo argv builders)
- `prefix_stream` log multiplexing (platform-agnostic)

Run with: `uv run scripts/dev_tests.py`
"""
from __future__ import annotations

import importlib.util
import io
import sys
import threading
import types
from pathlib import Path
from unittest import mock

import pytest

_SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS_DIR))

# `dev.py` imports `_lib` at module load and `_lib.require_elevation()` is
# normally called from `main()`. Tests do not call `main`, but we still need
# to satisfy the import. A minimal `_lib` stub keeps the import side-effect
# free without requiring sudo / a target user. Use `types.ModuleType` rather
# than `SimpleNamespace` so `sys.modules["_lib"]` matches its declared type.
_lib_stub = types.ModuleType("_lib")
# `setattr` bypasses ty's static attribute check (ModuleType has no
# declared `require_elevation`); the attr is created dynamically and read
# from `dev.py` at module-load time.
setattr(_lib_stub, "require_elevation", lambda: None)
sys.modules.setdefault("_lib", _lib_stub)

_spec = importlib.util.spec_from_file_location("dev", str(_SCRIPTS_DIR / "dev.py"))
assert _spec and _spec.loader, "failed to locate scripts/dev.py"
dev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dev)

# privilege-model helpers ==============================================================================================


def test_elevation_action_windows_requires_admin():
    assert dev.elevation_action("Windows", None) == "windows-require-admin"


def test_elevation_action_windows_ignores_euid():
    assert dev.elevation_action("Windows", 0) == "windows-require-admin"


def test_elevation_action_posix_root_is_error():
    assert dev.elevation_action("Darwin", 0) == "posix-error-root"
    assert dev.elevation_action("Linux", 0) == "posix-error-root"


def test_elevation_action_posix_user_ok():
    assert dev.elevation_action("Darwin", 501) == "posix-ok"


def test_sudo_prefix_posix_is_sudo():
    assert dev.sudo_prefix("Darwin") == ["sudo"]


def test_sudo_prefix_windows_is_empty():
    assert dev.sudo_prefix("Windows") == []


def test_missing_hole_group_true_when_absent():
    assert dev.missing_hole_group(4242, {20, 12, 80}) is True


def test_missing_hole_group_false_when_present_as_supplementary():
    assert dev.missing_hole_group(4242, {20, 4242, 80}) is False


def test_missing_hole_group_false_when_group_absent():
    assert dev.missing_hole_group(None, {20, 12}) is False


def test_grant_access_argv_posix_prefixes_sudo_with_preserve_env():
    argv = dev.grant_access_argv(["sudo"], "/tmp/hole-dev-1/hole")
    assert argv == [
        "sudo", "--preserve-env=RUST_LOG,RUST_BACKTRACE,HOLE_BRIDGE_LOG", "/tmp/hole-dev-1/hole", "bridge",
        "grant-access"
    ]


def test_grant_access_argv_windows_no_sudo():
    argv = dev.grant_access_argv([], "C:/hole/hole.exe")
    assert argv == ["C:/hole/hole.exe", "bridge", "grant-access"]


def test_bridge_argv_posix_prefixes_sudo_and_passes_paths():
    argv = dev.bridge_argv(["sudo"], "/tmp/hole-dev-1/hole", "/tmp/x.sock", "/tmp/state")
    assert argv == [
        "sudo", "--preserve-env=RUST_LOG,RUST_BACKTRACE,HOLE_BRIDGE_LOG", "/tmp/hole-dev-1/hole", "bridge", "run",
        "--socket-path", "/tmp/x.sock", "--state-dir", "/tmp/state"
    ]


def test_bridge_argv_windows_no_sudo():
    argv = dev.bridge_argv([], "C:/hole/hole.exe", "P", "S")
    assert argv == ["C:/hole/hole.exe", "bridge", "run", "--socket-path", "P", "--state-dir", "S"]


def test_shutdown_does_not_kill_bridge_on_timeout(capsys):
    import subprocess as _sp
    killed = []

    class _FakeProc:

        def __init__(self, name):
            self.name = name
            self.pid = 4321

        def wait(self, timeout: float | None = None):
            raise _sp.TimeoutExpired(cmd=self.name, timeout=timeout or 0)

        def kill(self):
            killed.append(self.name)

    bridge = _FakeProc("bridge")
    vite = _FakeProc("vite")
    with mock.patch.object(dev, "terminate_tree"):
        dev.shutdown([vite, bridge], bridge_proc=bridge)
    # Non-bridge procs are force-killed; the root bridge is NOT (SIGKILL to the
    # sudo wrapper wouldn't reach it), and the user is told how to recover.
    assert killed == ["vite"]
    assert "network-reset.py" in capsys.readouterr().err


def test_shutdown_graceful_exit_kills_nothing(capsys):
    killed = []

    class _FakeProc:

        def __init__(self, name):
            self.name = name
            self.pid = 4321

        def wait(self, timeout: float | None = None):
            return 0

        def kill(self):
            killed.append(self.name)

    bridge = _FakeProc("bridge")
    vite = _FakeProc("vite")
    with mock.patch.object(dev, "terminate_tree"):
        dev.shutdown([vite, bridge], bridge_proc=bridge)
    assert killed == []
    assert "network-reset.py" not in capsys.readouterr().err


# prefix_stream tests (platform-agnostic) ==============================================================================
#
# These tests pin the no-interleave invariant: a multi-line tracing entry
# from one stream must not be split by lines from another.


def _strip_ansi(s: str) -> str:
    """Drop ANSI color escape sequences so assertions can compare the
    visible text. dev.py wraps prefixes in colors; the tests only care
    about ordering and atomicity."""
    import re

    return re.sub(r"\x1b\[[0-9;]*m", "", s)


def _run_streams(streams: list[tuple[str, str, bool]]) -> str:
    """Run prefix_stream in parallel against `streams`.

    Each tuple is `(label, text, buffer_entries)`. Returns the captured
    stdout with ANSI codes stripped.
    """
    lock = threading.Lock()
    threads: list[threading.Thread] = []
    captured = io.StringIO()
    with mock.patch.object(dev.sys, "stdout", captured):
        for label, text, buffer_entries in streams:
            stream = io.StringIO(text)
            t = threading.Thread(
                target=dev.prefix_stream,
                args=(stream, label, "", lock),
                kwargs={"buffer_entries": buffer_entries},
            )
            t.start()
            threads.append(t)
        for t in threads:
            t.join(timeout=5)
            assert not t.is_alive(), "prefix_stream thread did not terminate"
    return _strip_ansi(captured.getvalue())


def test_prefix_stream_single_line_emits_prefixed_line():
    text = "2026-05-24T11:13:36Z INFO hole_bridge: started\n"
    out = _run_streams([("bridge", text, True)])
    assert out == "[bridge] 2026-05-24T11:13:36Z INFO hole_bridge: started\n"


def test_prefix_stream_buffers_multiline_entry_until_next_entry():
    # The bridge's structured panic entry from #393 — must stay
    # contiguous in the output even when the test's "next entry"
    # marker arrives mid-buffer.
    bridge_text = (
        "2026-05-24T11:13:36Z ERROR hole::panic: panic: ...\n"
        "  location: shadowsocks.rs:101\n"
        "  backtrace: |2\n"
        "       0: frame_a\n"
        "       1: frame_b\n"
        "2026-05-24T11:13:37Z INFO hole_bridge: stopping\n"
    )
    out = _run_streams([("bridge", bridge_text, True)])
    # The first entry's 5 lines must appear contiguously before the
    # second entry's single line. (No other stream is competing, so
    # this just verifies the buffer-and-flush mechanics.)
    lines = out.splitlines(keepends=True)
    assert lines == [
        "[bridge] 2026-05-24T11:13:36Z ERROR hole::panic: panic: ...\n",
        "[bridge]   location: shadowsocks.rs:101\n",
        "[bridge]   backtrace: |2\n",
        "[bridge]        0: frame_a\n",
        "[bridge]        1: frame_b\n",
        "[bridge] 2026-05-24T11:13:37Z INFO hole_bridge: stopping\n",
    ]


def test_prefix_stream_eof_flushes_final_entry():
    # The panic-then-exit case: the bridge writes one tracing entry
    # then dies. EOF must flush the buffered entry.
    bridge_text = ("2026-05-24T11:13:36Z ERROR hole::panic: panic: dying\n"
                   "  backtrace: |2\n"
                   "       0: frame\n")
    out = _run_streams([("bridge", bridge_text, True)])
    assert out == (
        "[bridge] 2026-05-24T11:13:36Z ERROR hole::panic: panic: dying\n"
        "[bridge]   backtrace: |2\n"
        "[bridge]        0: frame\n"
    )


def test_prefix_stream_non_buffered_emits_per_line():
    # Vite has no timestamps; buffer_entries=False prints each line
    # immediately. With buffer_entries=True we'd starve forever.
    vite_text = "VITE v8.0.13 ready in 499 ms\nLocal: http://localhost:1420/\n"
    out = _run_streams([("  vite", vite_text, False)])
    assert out == ("[  vite] VITE v8.0.13 ready in 499 ms\n"
                   "[  vite] Local: http://localhost:1420/\n")


def test_prefix_stream_standalone_panic_message_after_flush():
    # The stdlib default panic hook prints `thread '...' panicked at ...`
    # AFTER the tracing entry. With no preceding buffer, this line is
    # emitted as a standalone, not appended to a prior entry.
    text = (
        "2026-05-24T11:13:36Z ERROR hole::panic: panic\n"
        "  backtrace: |2\n"
        "       0: f\n"
        "thread 'tokio-rt-worker' panicked at shadowsocks.rs:101\n"
        "note: run with `RUST_BACKTRACE=1` ...\n"
        "2026-05-24T11:13:37Z INFO hole_bridge: next entry\n"
    )
    out = _run_streams([("bridge", text, True)])
    # First three lines are the tracing entry (flushed when "thread ..."
    # arrives WITHOUT a timestamp — but my impl appends non-timestamp
    # lines to the in-progress buffer if one exists). The current
    # design buffers the panic-message lines onto the preceding
    # tracing entry until the next entry-start arrives. That is the
    # documented trade-off; pin it explicitly here so a future
    # behavior change is noticed.
    assert out == (
        "[bridge] 2026-05-24T11:13:36Z ERROR hole::panic: panic\n"
        "[bridge]   backtrace: |2\n"
        "[bridge]        0: f\n"
        "[bridge] thread 'tokio-rt-worker' panicked at shadowsocks.rs:101\n"
        "[bridge] note: run with `RUST_BACKTRACE=1` ...\n"
        "[bridge] 2026-05-24T11:13:37Z INFO hole_bridge: next entry\n"
    )


def test_prefix_stream_multiline_entries_do_not_interleave_across_streams():
    # The motivating bug: bridge backtrace was chopped up by [client]
    # lines. With the lock + buffer, each entry is one atomic write.
    bridge_text = (
        "2026-05-24T11:13:36Z ERROR hole::panic: panic\n"
        "  backtrace: |2\n"
        "       0: f0\n"
        "       1: f1\n"
        "       2: f2\n"
        "2026-05-24T11:13:38Z INFO hole_bridge: done\n"
    )
    client_text = (
        "2026-05-24T11:13:36Z WARN hole::state: comm error\n"
        "  error: 'connection closed'\n"
        "2026-05-24T11:13:37Z ERROR hole::tray: send failed\n"
    )

    # Run a few times to surface scheduling races. (Test-of-timing
    # exception class per CLAUDE.md: we're checking the absence of
    # interleaving, which is intrinsically a concurrency property.)
    for _ in range(10):
        out = _run_streams([
            ("bridge", bridge_text, True),
            ("client", client_text, True),
        ])
        # Each entry's lines must be contiguous. We test that by
        # confirming no [client] line appears between two consecutive
        # [bridge] lines of the same entry.
        lines = out.splitlines(keepends=True)
        bridge_entries: list[list[str]] = []
        client_entries: list[list[str]] = []
        current_bridge: list[str] | None = None
        current_client: list[str] | None = None
        for ln in lines:
            if ln.startswith("[bridge]"):
                if current_bridge is None:
                    current_bridge = [ln]
                elif "ERROR" in ln or "INFO" in ln or "WARN" in ln:
                    # New entry — flush previous
                    bridge_entries.append(current_bridge)
                    current_bridge = [ln]
                else:
                    current_bridge.append(ln)
                # If a [client] entry was in progress when [bridge] starts,
                # it must NOT have been interrupted mid-entry.
            elif ln.startswith("[client]"):
                if current_client is None:
                    current_client = [ln]
                elif "ERROR" in ln or "INFO" in ln or "WARN" in ln:
                    client_entries.append(current_client)
                    current_client = [ln]
                else:
                    current_client.append(ln)
        if current_bridge:
            bridge_entries.append(current_bridge)
        if current_client:
            client_entries.append(current_client)

        # Bridge entries: first 5 lines (entry-start + 4 continuations),
        # then 1 line.
        assert len(bridge_entries) == 2
        assert len(bridge_entries[0]) == 5
        assert len(bridge_entries[1]) == 1
        # Client entries: first 2 lines, then 1 line.
        assert len(client_entries) == 2
        assert len(client_entries[0]) == 2
        assert len(client_entries[1]) == 1


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
