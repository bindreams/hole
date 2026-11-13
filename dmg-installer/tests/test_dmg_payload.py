"""DMG payload conformance + debug-symbol parity checks for the built Hole.app.

These guard issue #512 (a canonical BINDIR file silently dropped from the DMG)
and #512 defer-1 (hole.dSYM must ship next to the binary so production panic
backtraces resolve at runtime — parity with the Windows hole.pdb).
"""

import plistlib
import re
import shutil
import subprocess
from pathlib import Path


from conftest import REPO_ROOT, canonical_darwin_bindir, embedded_plugin_names

# Canonical Mach-O UUID shape (8-4-4-4-12 hex), matching
# msi-installer/tests/test_hole_wxs.py. Unanchored for use with finditer.
_UUID_RE = re.compile(r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}")

# Failure bound for a child that prints one line and exits: a hang means a broken
# binary, surfaced to the human instead of stalling the job.
_HOLE_VERSION_TIMEOUT_SECS = 60


def test_dmg_ships_full_canonical_bindir(installed_app: Path) -> None:
    """Every file the macOS bundle must hold ships in the .app payload (#512).

    Derives the expected set from the single source of truth so a future bindir
    addition nobody wired into the Tauri config fails here. We scan
    Contents/MacOS without recursing, so the DWARF Mach-O named `hole` inside
    hole.dSYM cannot falsely satisfy the `hole` entry. The dSYM's internal structure + UUID are covered
    by the two tests below.
    """
    expected = canonical_darwin_bindir()
    contents = installed_app / "Contents"
    present = {p.name for p in (contents / "MacOS").iterdir()}
    missing = expected - present
    assert not missing, (
        f"Hole.app payload is missing canonical BINDIR file(s) {sorted(missing)} "
        f"(searched Contents/MacOS). Expected (from "
        f"`cargo xtask bindir-names --os darwin --bundle`): {sorted(expected)}."
    )


def test_plugins_are_not_in_the_app(installed_app: Path) -> None:
    """The app carries no plugin binary: `hole` embeds them and the service writes them to a root-owned folder.

    A plugin left in Contents/MacOS would be one the service never runs, and
    `test_dmg_ships_full_canonical_bindir` only reports missing names, so it cannot say this.
    """
    plugins = embedded_plugin_names()
    assert plugins, "`cargo xtask bindir-names` lists no embedded plugin: the macOS tables changed"
    contents = installed_app / "Contents"
    present = {p.name for p in (contents / "MacOS").iterdir()}
    present |= {p.name for p in (contents / "Resources").iterdir()}
    assert not (plugins & present), f"Hole.app still ships plugin(s) {sorted(plugins & present)}"


def test_hole_carries_the_plugin_bytes(installed_app: Path) -> None:
    """Each plugin's build output occurs inside `hole`, byte for byte, and is not an empty stub.

    The inputs are what `cargo xtask deps` left in `.cache/<name>/<name>-<triple>`, found by the single-match glob
    the staging code uses. An empty input means `hole` embeds nothing and the service would have no plugin to write.
    """
    hole = (installed_app / "Contents" / "MacOS" / "hole").read_bytes()
    for name in sorted(embedded_plugin_names()):
        matches = sorted((REPO_ROOT / ".cache" / name).glob(f"{name}-*"))
        assert len(matches) == 1, f"expected one .cache/{name}/{name}-<triple>, found {matches}"
        payload = matches[0].read_bytes()
        assert payload, f"{matches[0]} is empty: `cargo xtask deps` did not run before the build"
        assert payload in hole, f"hole does not contain the bytes of {matches[0].name}"


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


def test_shipped_version_is_exact(installed_app: Path, tmp_path: Path) -> None:
    """The shipped binary reports exactly the version `cargo xtask version` gives this tree, without `.dirty` (#1066).

    Both sides come from the same version logic, so this checks the stamp, not
    which version a tree should carry. The binary is run (`hole version`, the
    lib constant, printed before any GUI or logging) rather than scanned: the
    version is a bare string a dependency's own version can match byte for
    byte. It runs from a copy outside the quarantined Hole.app. Requires a
    clean checkout.
    """
    result = subprocess.run(
        ["cargo", "xtask", "version", "--group", "hole"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"`cargo xtask version` failed:\n{result.stderr}"
    clean = result.stdout.strip().removesuffix(".dirty")
    assert not clean.startswith("0.0.0"), (
        f"`cargo xtask version` printed {clean!r}, its fallback when git or the workspace cannot be read; "
        f"the binary would report the same and this check would prove nothing."
    )

    binary = Path(shutil.copy(installed_app / "Contents" / "MacOS" / "hole", tmp_path / "hole"))
    command = [str(binary), "version"]
    run = subprocess.run(command, capture_output=True, text=True, check=False, timeout=_HOLE_VERSION_TIMEOUT_SECS)
    killed = f" (killed by signal {-run.returncode})" if run.returncode < 0 else ""
    assert run.returncode == 0, f"`hole version` exited {run.returncode}{killed}:\n{run.stderr}"
    assert run.stdout.strip() == f"hole {clean}", (
        f"`hole version` printed {run.stdout.strip()!r}, expected 'hole {clean}'. A `.dirty` suffix means "
        f"the build script stamped a dirty tree."
    )


def test_build_leaves_tracked_files_unmodified() -> None:
    """The Tauri CLI rewrites tracked files (e.g. `crates/hole/Cargo.toml`) before
    compiling, which dirties the tree and the shipped version (#1066).
    Requires a clean checkout.
    """
    result = subprocess.run(
        ["git", "status", "--porcelain", "--untracked-files=no"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"`git status` failed:\n{result.stderr}"
    assert not result.stdout, (
        f"tracked files differ from HEAD after the build:\n{result.stdout}"
        f"Commit the form the Tauri CLI writes so it leaves them alone."
    )
