"""DMG payload conformance + debug-symbol parity checks for the built Hole.app.

These guard issue #512 (a canonical BINDIR file silently dropped from the DMG)
and #512 defer-1 (hole.dSYM must ship next to the binary so production panic
backtraces resolve at runtime — parity with the Windows hole.pdb).
"""

import re
import subprocess
from pathlib import Path

from conftest import canonical_darwin_bindir

# Canonical Mach-O UUID shape (8-4-4-4-12 hex), matching
# msi-installer/tests/test_hole_wxs.py. Unanchored for use with finditer.
_UUID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")


def test_dmg_ships_full_canonical_bindir(installed_app: Path) -> None:
    """Every canonical macOS BINDIR file must ship in the .app payload (#512).

    Derives the expected set from the single source of truth so a future bindir
    addition nobody wired into the Tauri config fails here. We scan only the two
    payload roots — Contents/MacOS (the binary, sidecars, and the dSYM bundle)
    and Contents/Resources (NOTICES.md) — and do NOT recurse, so the DWARF
    Mach-O named `hole` inside hole.dSYM cannot falsely satisfy the `hole`
    entry. The dSYM's internal structure + UUID are covered by the two tests
    below.
    """
    expected = canonical_darwin_bindir()
    contents = installed_app / "Contents"
    present = {p.name for p in (contents / "MacOS").iterdir()}
    present |= {p.name for p in (contents / "Resources").iterdir()}
    missing = expected - present
    assert not missing, (
        f"Hole.app payload is missing canonical BINDIR file(s) {sorted(missing)} "
        f"(searched Contents/MacOS + Contents/Resources). Expected (from "
        f"`cargo xtask bindir-names --os darwin`): {sorted(expected)}."
    )


def test_dsym_is_sibling_of_binary(installed_app: Path) -> None:
    """hole.dSYM must sit next to the hole binary in Contents/MacOS (#512 defer-1).

    std's backtrace symbolizer (library/backtrace `Mapping::new`) reads the
    running binary's Mach-O UUID, scans the binary's parent directory for any
    `*.dSYM`, and matches by UUID inside `<dSYM>/Contents/Resources/DWARF/`. So
    the dSYM must be a sibling of the binary, with its DWARF Mach-O inside.
    """
    macos = installed_app / "Contents" / "MacOS"
    binary = macos / "hole"
    dwarf = macos / "hole.dSYM" / "Contents" / "Resources" / "DWARF" / "hole"
    assert binary.is_file(), f"main binary missing at {binary}"
    assert dwarf.is_file(), (
        f"dSYM DWARF missing at {dwarf} — std's backtrace scans the binary's "
        f"parent dir ({macos}) for *.dSYM, so the dSYM must be a sibling of the binary"
    )


def _macho_uuids(path: Path) -> set[str]:
    """All Mach-O LC_UUIDs in `path` (one per arch slice), via `dwarfdump --uuid`."""
    out = subprocess.run(
        ["dwarfdump", "--uuid", str(path)],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    # Lines look like: "UUID: 1234ABCD-... (x86_64) /path/to/hole"
    return {m.group(0).upper() for m in _UUID_RE.finditer(out)}


def test_dsym_uuid_matches_binary(installed_app: Path) -> None:
    """The dSYM's DWARF must carry the binary's UUID, or backtrace ignores it.

    This is the deterministic proof that std's symbolizer will resolve: the
    sibling-directory scan (test_dsym_is_sibling_of_binary) plus a UUID match
    are exactly the two conditions `Mapping::new` requires.
    """
    macos = installed_app / "Contents" / "MacOS"
    binary_uuids = _macho_uuids(macos / "hole")
    dwarf_uuids = _macho_uuids(macos / "hole.dSYM" / "Contents" / "Resources" / "DWARF" / "hole")
    assert binary_uuids, "no Mach-O UUID found in the hole binary"
    assert dwarf_uuids, "no Mach-O UUID found in the dSYM DWARF Mach-O"
    assert binary_uuids == dwarf_uuids, (
        f"binary UUID(s) {binary_uuids} != dSYM UUID(s) {dwarf_uuids}; std's backtrace "
        f"symbolizer would skip the dSYM and panic frames would render <unknown> (#393)"
    )
