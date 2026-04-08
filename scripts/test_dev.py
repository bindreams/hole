#!/usr/bin/env python3
"""Unit tests for scripts/dev.py freshness logic.

Covers `node_modules_is_stale` (the pure predicate) and
`_write_install_stamp` (the post-install housekeeping that writes the
stamp and self-heals a missing `node_modules/` dir). The subprocess
bridge to `npm install` in `ensure_node_modules` itself is not unit
tested — mocking privilege drop and subprocess run would dwarf the
function under test — but everything around it is.
"""
from __future__ import annotations

import hashlib
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import dev  # noqa: E402


def _hash(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


class NodeModulesIsStaleTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hole-dev-test-"))
        (self.tmp / "package-lock.json").write_bytes(b'{"v": 1}')

    def tearDown(self) -> None:
        # Loud on cleanup failure — CLAUDE.md: "Tests must never silently
        # skip [...] Fail loudly by default."
        shutil.rmtree(self.tmp)

    def _stamp(self, value: str) -> None:
        (self.tmp / "node_modules").mkdir(exist_ok=True)
        (self.tmp / "node_modules" / dev.INSTALL_STAMP_NAME).write_text(value)

    def test_missing_node_modules(self) -> None:
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_missing_node_modules_and_lockfile(self) -> None:
        # Short-circuits on node_modules check, lockfile hash never attempted.
        (self.tmp / "package-lock.json").unlink()
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_node_modules_without_stamp(self) -> None:
        (self.tmp / "node_modules").mkdir()
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_stamp_does_not_match(self) -> None:
        self._stamp("deadbeef")
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_stamp_matches(self) -> None:
        self._stamp(_hash(b'{"v": 1}'))
        self.assertFalse(dev.node_modules_is_stale(self.tmp))

    def test_stamp_matches_then_lockfile_changes(self) -> None:
        self._stamp(_hash(b'{"v": 1}'))
        self.assertFalse(dev.node_modules_is_stale(self.tmp))
        (self.tmp / "package-lock.json").write_bytes(b'{"v": 2}')
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_missing_lockfile(self) -> None:
        self._stamp(_hash(b'{"v": 1}'))
        (self.tmp / "package-lock.json").unlink()
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_stamp_path_is_unreadable(self) -> None:
        # Stamp path exists but is a directory. read_text raises OSError:
        # IsADirectoryError on POSIX, PermissionError on Windows. Both
        # are OSError subclasses and caught by the same branch.
        nm = self.tmp / "node_modules"
        nm.mkdir()
        (nm / dev.INSTALL_STAMP_NAME).mkdir()
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_lockfile_is_unreadable(self) -> None:
        # Lockfile path exists but is a directory. read_bytes raises
        # OSError (IsADirectoryError on POSIX, PermissionError on Windows).
        (self.tmp / "package-lock.json").unlink()
        (self.tmp / "package-lock.json").mkdir()
        self._stamp("anything")
        self.assertTrue(dev.node_modules_is_stale(self.tmp))


class WriteInstallStampTests(unittest.TestCase):

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp(prefix="hole-dev-test-"))
        (self.tmp / "package-lock.json").write_bytes(b'{"v": 1}')

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp)

    def test_writes_stamp_when_node_modules_exists(self) -> None:
        (self.tmp / "node_modules").mkdir()
        dev._write_install_stamp(self.tmp, None)
        stamp = self.tmp / "node_modules" / dev.INSTALL_STAMP_NAME
        self.assertTrue(stamp.exists())
        self.assertEqual(stamp.read_text(), _hash(b'{"v": 1}'))

    def test_self_heals_missing_node_modules(self) -> None:
        # Zero-dep project regression: `npm install` on a project with no
        # dependencies logs "up to date, audited 1 package" without
        # creating `node_modules/`. The stamp write must still succeed.
        self.assertFalse((self.tmp / "node_modules").exists())
        dev._write_install_stamp(self.tmp, None)
        self.assertTrue((self.tmp / "node_modules").exists())
        stamp = self.tmp / "node_modules" / dev.INSTALL_STAMP_NAME
        self.assertTrue(stamp.exists())
        self.assertEqual(stamp.read_text(), _hash(b'{"v": 1}'))

    def test_predicate_agrees_after_write(self) -> None:
        # The predicate and the writer must be in sync: writing the stamp
        # must make `node_modules_is_stale` return False on the next call.
        dev._write_install_stamp(self.tmp, None)
        self.assertFalse(dev.node_modules_is_stale(self.tmp))

    def test_missing_lockfile_does_not_write_stamp(self) -> None:
        # If the lockfile vanished between `npm install` and the stamp
        # write, we warn and return — we don't write an empty/wrong stamp.
        (self.tmp / "package-lock.json").unlink()
        dev._write_install_stamp(self.tmp, None)
        stamp = self.tmp / "node_modules" / dev.INSTALL_STAMP_NAME
        self.assertFalse(stamp.exists())

    def test_write_failure_exits_loudly(self) -> None:
        # Block the stamp write by making `node_modules` a plain file.
        # `Path.mkdir(exist_ok=True)` only suppresses FileExistsError if
        # the existing path is a directory — when it's a regular file the
        # error is re-raised (see pathlib source). The test asserts that
        # any OSError in the try-block triggers sys.exit(1), regardless
        # of whether it comes from mkdir or write_text.
        (self.tmp / "node_modules").write_bytes(b"not a directory")
        with self.assertRaises(SystemExit) as ctx:
            dev._write_install_stamp(self.tmp, None)
        self.assertEqual(ctx.exception.code, 1)


if __name__ == "__main__":
    unittest.main()
