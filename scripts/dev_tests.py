#!/usr/bin/env python3
# /// script
# requires-python = ">=3.9"
# dependencies = ["pytest"]
# ///
"""Unit tests for `drop_kwargs` in `dev.py`.

Run with: `uv run scripts/dev_tests.py`
"""
from __future__ import annotations

import importlib.util
import sys
import types
from pathlib import Path
from unittest import mock

import pytest

# `drop_kwargs` is a no-op on Windows (always returns `{}`). Skip the whole
# module to avoid loading `dev.py` which references `grp` (POSIX-only) when
# `target_user` is non-None — and to avoid pretending we have coverage we
# don't.
if sys.platform == "win32":
    pytest.skip("drop_kwargs is POSIX-only", allow_module_level=True)

_SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(_SCRIPTS_DIR))

# `dev.py` imports `_lib` at module load and `_lib.require_elevation()` is
# normally called from `main()`. Tests do not call `main`, but we still need
# to satisfy the import. A minimal `_lib` stub keeps the import side-effect
# free without requiring sudo / a target user.
sys.modules.setdefault(
    "_lib",
    types.SimpleNamespace(
        require_elevation=lambda: None,
        sudo_target_user=lambda: None,
    ),
)

_spec = importlib.util.spec_from_file_location("dev", str(_SCRIPTS_DIR / "dev.py"))
assert _spec and _spec.loader, "failed to locate scripts/dev.py"
dev = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dev)


def test_target_none_returns_empty():
    assert dev.drop_kwargs(None) == {}


def test_hole_present_includes_hole_gid():
    fake = types.SimpleNamespace(gr_gid=4242)
    with mock.patch.object(dev.grp, "getgrnam", return_value=fake):
        kw = dev.drop_kwargs((501, 20, "alice", "/Users/alice"))
    assert kw == {"user": 501, "group": 20, "extra_groups": [4242]}


def test_hole_absent_returns_empty_list():
    with mock.patch.object(dev.grp, "getgrnam", side_effect=KeyError("hole")):
        kw = dev.drop_kwargs((501, 20, "alice", "/Users/alice"))
    assert kw == {"user": 501, "group": 20, "extra_groups": []}


def test_directory_services_failure_returns_empty_list(capsys):
    with mock.patch.object(
        dev.grp, "getgrnam", side_effect=OSError("DS unreachable")
    ):
        kw = dev.drop_kwargs((501, 20, "alice", "/Users/alice"))
    assert kw == {"user": 501, "group": 20, "extra_groups": []}
    # Surface the failure to the user — silently dropping `hole` would
    # leave the GUI confused without any breadcrumb.
    assert "DS unreachable" in capsys.readouterr().err


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
