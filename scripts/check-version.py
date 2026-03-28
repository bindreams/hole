#!/usr/bin/env python3
"""Verify Cargo.toml versions are consistent with git tags.

Usage:
  python scripts/check-version.py          # default: allow equal or one bump ahead
  python scripts/check-version.py --exact  # require exact match (for release workflows)
"""

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path


def get_nearest_tag_version() -> tuple[int, int, int]:
    """Get the semver tuple from the nearest ancestor version tag."""
    result = subprocess.run(
        ["git", "describe", "--tags", "--match", "v[0-9]*.[0-9]*.[0-9]*", "--abbrev=0"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"error: git describe failed: {result.stderr.strip()}", file=sys.stderr)
        print("  hint: is there a version tag (e.g. v0.1.0) reachable from HEAD?", file=sys.stderr)
        sys.exit(1)

    tag = result.stdout.strip()
    match = re.fullmatch(r"v(\d+)\.(\d+)\.(\d+)", tag)
    if not match:
        print(f"error: nearest tag '{tag}' is not strict vMAJOR.MINOR.PATCH", file=sys.stderr)
        sys.exit(1)

    return (int(match[1]), int(match[2]), int(match[3]))


def get_cargo_versions() -> dict[str, tuple[int, int, int]]:
    """Read version from all workspace member Cargo.toml files."""
    root_toml = Path("Cargo.toml")
    with open(root_toml, "rb") as f:
        root = tomllib.load(f)

    members = root.get("workspace", {}).get("members", [])
    if not members:
        print("error: no workspace members found in Cargo.toml", file=sys.stderr)
        sys.exit(1)

    # Only literal paths are supported (no glob patterns).
    for member in members:
        if any(c in member for c in "*?["):
            print(f"error: glob patterns in workspace members are not supported: {member}", file=sys.stderr)
            sys.exit(1)

    versions: dict[str, tuple[int, int, int]] = {}

    for member in members:
        cargo_path = Path(member) / "Cargo.toml"
        with open(cargo_path, "rb") as f:
            data = tomllib.load(f)
        version_str = data["package"]["version"]
        match = re.fullmatch(r"(\d+)\.(\d+)\.(\d+)", version_str)
        if not match:
            print(f"error: {cargo_path} has non-semver version: {version_str}", file=sys.stderr)
            sys.exit(1)
        versions[str(cargo_path)] = (int(match[1]), int(match[2]), int(match[3]))

    return versions


def is_valid_next(tag_ver: tuple[int, int, int], cargo_ver: tuple[int, int, int]) -> bool:
    """Check if cargo_ver is equal to tag_ver or exactly one bump ahead."""
    if cargo_ver == tag_ver:
        return True

    major_t, minor_t, patch_t = tag_ver
    # Patch bump
    if cargo_ver == (major_t, minor_t, patch_t + 1):
        return True
    # Minor bump
    if cargo_ver == (major_t, minor_t + 1, 0):
        return True
    # Major bump
    if cargo_ver == (major_t + 1, 0, 0):
        return True

    return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--exact",
        action="store_true",
        help="require exact match between Cargo.toml and tag (for release workflows)",
    )
    parser.add_argument("filenames", nargs="*", help=argparse.SUPPRESS)  # pre-commit compat
    args = parser.parse_args()

    tag_ver = get_nearest_tag_version()
    cargo_versions = get_cargo_versions()

    # All workspace members must have the same version.
    unique = set(cargo_versions.values())
    if len(unique) > 1:
        print("error: workspace members have inconsistent versions:", file=sys.stderr)
        for path, ver in sorted(cargo_versions.items()):
            print(f"  {path}: {'.'.join(map(str, ver))}", file=sys.stderr)
        sys.exit(1)

    cargo_ver = unique.pop()
    tag_str = ".".join(map(str, tag_ver))
    cargo_str = ".".join(map(str, cargo_ver))

    if args.exact:
        if cargo_ver != tag_ver:
            print(f"error: Cargo.toml version ({cargo_str}) != tag version ({tag_str})", file=sys.stderr)
            sys.exit(1)
    else:
        if not is_valid_next(tag_ver, cargo_ver):
            print(
                f"error: Cargo.toml version ({cargo_str}) is not a valid successor of tag version ({tag_str})",
                file=sys.stderr,
            )
            print(f"  allowed: {tag_str}, or one patch/minor/major bump", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()

# Tests (run with pytest) ==============================================================================================


def test_equal_versions():
    assert is_valid_next((0, 1, 0), (0, 1, 0))


def test_equal_nonzero():
    assert is_valid_next((2, 3, 4), (2, 3, 4))


def test_patch_bump():
    assert is_valid_next((0, 1, 0), (0, 1, 1))


def test_minor_bump():
    assert is_valid_next((0, 1, 0), (0, 2, 0))


def test_major_bump():
    assert is_valid_next((0, 1, 0), (1, 0, 0))


def test_patch_bump_from_nonzero():
    assert is_valid_next((1, 2, 3), (1, 2, 4))


def test_minor_bump_from_nonzero():
    assert is_valid_next((1, 2, 3), (1, 3, 0))


def test_major_bump_from_nonzero():
    assert is_valid_next((1, 2, 3), (2, 0, 0))


def test_double_patch_bump():
    assert not is_valid_next((0, 1, 0), (0, 1, 2))


def test_minor_bump_without_patch_reset():
    assert not is_valid_next((0, 1, 3), (0, 2, 3))


def test_major_bump_without_minor_reset():
    assert not is_valid_next((1, 2, 0), (2, 2, 0))


def test_major_bump_without_patch_reset():
    assert not is_valid_next((1, 0, 3), (2, 0, 3))


def test_downgrade():
    assert not is_valid_next((1, 0, 0), (0, 9, 0))


def test_skip_minor():
    assert not is_valid_next((1, 0, 0), (1, 2, 0))


def test_multi_component_bump():
    assert not is_valid_next((1, 0, 0), (1, 1, 1))
