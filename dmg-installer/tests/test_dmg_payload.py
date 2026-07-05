"""DMG payload conformance + debug-symbol parity checks for the built Hole.app.

These guard issue #512 (a canonical BINDIR file silently dropped from the DMG)
and #512 defer-1 (hole.dSYM must ship next to the binary so production panic
backtraces resolve at runtime — parity with the Windows hole.pdb).
"""

import plistlib
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


def test_bundle_is_menu_bar_app(installed_app: Path) -> None:
    """The shipped bundle must carry LSUIElement=true (Tauri merges
    crates/hole/Info.plist), or macOS treats Hole as a regular Dock app."""
    info = plistlib.loads((installed_app / "Contents" / "Info.plist").read_bytes())
    assert info.get("LSUIElement") is True, "bundle Info.plist missing LSUIElement=true"


def test_dsym_is_sibling_of_binary(installed_app: Path) -> None:
    """hole.dSYM must sit next to the hole binary in Contents/MacOS (#512 defer-1).

    std's backtrace symbolizer (library/backtrace `Mapping::new`) reads the
    running binary's Mach-O UUID, scans the binary's parent directory for any
    `*.dSYM`, and matches by UUID inside `<dSYM>/Contents/Resources/DWARF/`. So
    the dSYM must be a sibling of the binary with its DWARF Mach-O inside.
    """
    macos = installed_app / "Contents" / "MacOS"
    assert (macos / "hole").is_file(), f"main binary missing at {macos / 'hole'}"
    dwarfs = _dsym_dwarf_machos(installed_app)
    assert dwarfs, (
        f"no DWARF Mach-O inside {macos / 'hole.dSYM' / 'Contents' / 'Resources' / 'DWARF'} — "
        f"std's backtrace scans {macos} for a *.dSYM, so the dSYM must be a real directory "
        f"sibling of the binary with its DWARF Mach-O inside"
    )


def _dsym_dwarf_machos(installed_app: Path) -> list[Path]:
    """Mach-O files inside hole.dSYM/Contents/Resources/DWARF/.

    dsymutil names the DWARF after its *input* binary — cargo compiles
    `deps/hole-<hash>`, so the file is `hole-<hash>`, not `hole`. std matches by
    UUID, not filename (`Mapping::try_dsym_candidate` scans the dir), so we scan
    rather than assume a name.
    """
    dwarf_dir = installed_app / "Contents" / "MacOS" / "hole.dSYM" / "Contents" / "Resources" / "DWARF"
    return [p for p in dwarf_dir.iterdir() if p.is_file()] if dwarf_dir.is_dir() else []


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

    Deterministic proof std's symbolizer will resolve: the sibling-directory
    scan (test_dsym_is_sibling_of_binary) plus a UUID match are exactly the two
    conditions `Mapping::new` requires. The match is by UUID across whatever
    Mach-O(s) the DWARF dir holds — `Mapping::try_dsym_candidate` does the same.
    """
    binary_uuids = _macho_uuids(installed_app / "Contents" / "MacOS" / "hole")
    dwarf_uuids: set[str] = set()
    for dwarf in _dsym_dwarf_machos(installed_app):
        dwarf_uuids |= _macho_uuids(dwarf)
    assert binary_uuids, "no Mach-O UUID found in the hole binary"
    assert binary_uuids <= dwarf_uuids, (
        f"binary UUID(s) {binary_uuids} not all present in dSYM DWARF UUID(s) {dwarf_uuids}; "
        f"std's backtrace symbolizer would skip the dSYM and panic frames would render "
        f"<unknown> (#393)"
    )
