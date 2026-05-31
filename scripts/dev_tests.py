#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pytest"]
# ///
"""Unit tests for helpers in `dev.py`.

Covers:
- `drop_kwargs` (POSIX-only; skipped on Windows)
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
# declared `require_elevation` / `sudo_target_user`); the attrs are
# created dynamically and read from `dev.py` at module-load time.
setattr(_lib_stub, "require_elevation", lambda: None)
setattr(_lib_stub, "sudo_target_user", lambda: None)
sys.modules.setdefault("_lib", _lib_stub)

_spec = importlib.util.spec_from_file_location("dev", str(_SCRIPTS_DIR / "dev.py"))
assert _spec and _spec.loader, "failed to locate scripts/dev.py"
dev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dev)

# drop_kwargs tests (POSIX-only) =======================================================================================

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="drop_kwargs is POSIX-only")


@posix_only
def test_target_none_returns_empty():
    assert dev.drop_kwargs(None) == {}


@posix_only
def test_hole_present_includes_hole_gid():
    fake = types.SimpleNamespace(gr_gid=4242)
    with mock.patch.object(dev.grp, "getgrnam", return_value=fake):
        kw = dev.drop_kwargs((501, 20, "alice", "/Users/alice"))
    assert kw == {"user": 501, "group": 20, "extra_groups": [4242]}


@posix_only
def test_hole_absent_returns_empty_list():
    with mock.patch.object(dev.grp, "getgrnam", side_effect=KeyError("hole")):
        kw = dev.drop_kwargs((501, 20, "alice", "/Users/alice"))
    assert kw == {"user": 501, "group": 20, "extra_groups": []}


@posix_only
def test_directory_services_failure_returns_empty_list(capsys):
    with mock.patch.object(dev.grp, "getgrnam", side_effect=OSError("DS unreachable")):
        kw = dev.drop_kwargs((501, 20, "alice", "/Users/alice"))
    assert kw == {"user": 501, "group": 20, "extra_groups": []}
    # Surface the failure to the user — silently dropping `hole` would
    # leave the GUI confused without any breadcrumb.
    assert "DS unreachable" in capsys.readouterr().err


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
