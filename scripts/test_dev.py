"""Unit tests for scripts/dev.py freshness logic.

Covers `node_modules_is_stale`, the pure predicate used by
`ensure_node_modules` to decide whether to invoke `npm install`. The
install path itself (subprocess, chown, stamp write) is covered by the
end-to-end verification in the plan, not here — mocking privilege drop
and subprocess would dwarf the function under test.
"""
# /// script
# requires-python = ">=3.9"
# ///
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
        # Stamp path exists but is a directory; read_text raises IsADirectoryError.
        nm = self.tmp / "node_modules"
        nm.mkdir()
        (nm / dev.INSTALL_STAMP_NAME).mkdir()
        self.assertTrue(dev.node_modules_is_stale(self.tmp))

    def test_lockfile_is_unreadable(self) -> None:
        # Lockfile path exists but is a directory; read_bytes raises IsADirectoryError.
        (self.tmp / "package-lock.json").unlink()
        (self.tmp / "package-lock.json").mkdir()
        self._stamp("anything")
        self.assertTrue(dev.node_modules_is_stale(self.tmp))


if __name__ == "__main__":
    unittest.main()
