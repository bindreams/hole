#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Sign a draft GitHub release's SHA256SUMS and upload the signature.

Only `hole` releases are signed (minisign supply-chain integrity for the
auto-updated binary distribution); `galoshes`, `garter`, and `ex-ray`
ship unsigned — they are either embedded into hole and covered by its
signature, or built-from-source by their consumers who pin SHA256 directly.

Usage:
    uv run scripts/sign-release.py 1.0.0
    uv run scripts/sign-release.py 1.0.0 --secret-key ~/path/to/minisign.key

The script accepts the bare semver and prepends the `releases/hole/v` tag
prefix internally.
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = "bindreams/hole"
TAG_PREFIX = "releases/hole/v"
# Assets that carry signing metadata rather than being covered by it.
SIGNATURE_ASSETS = frozenset({"SHA256SUMS", "SHA256SUMS.minisig"})


def normalize_tag(tag: str) -> str:
    """Strip optional 'v'/'releases/hole/v' prefix and validate semver. Returns full tag."""
    version = tag.removeprefix(TAG_PREFIX).removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"error: invalid version: {tag!r} (expected MAJOR.MINOR.PATCH)", file=sys.stderr)
        sys.exit(1)
    return f"{TAG_PREFIX}{version}"


def signable_asset_names(asset_names) -> set:
    """Release assets that SHA256SUMS must cover: everything but the signing metadata."""
    return {name for name in asset_names if name not in SIGNATURE_ASSETS}


def validate_sha256sums(path: Path, expected: set) -> None:
    """Assert SHA256SUMS covers exactly `expected`, one well-formed line each.

    Derived from the release's own asset list rather than a count, so adding a
    platform or artifact needs no change here (#682).
    """
    lines = [line for line in path.read_text().splitlines() if line.strip()]

    listed = []
    for i, line in enumerate(lines, 1):
        match = re.fullmatch(r"([0-9a-fA-F]{64})  (.+)", line)
        if not match:
            print(f"error: SHA256SUMS line {i} is malformed: {line!r}", file=sys.stderr)
            sys.exit(1)
        listed.append(match.group(2))

    duplicates = sorted({name for name in listed if listed.count(name) > 1})
    if duplicates:
        print(f"error: SHA256SUMS lists {', '.join(duplicates)} more than once", file=sys.stderr)
        sys.exit(1)

    if set(listed) != expected:
        missing = sorted(expected - set(listed))
        unknown = sorted(set(listed) - expected)
        detail = []
        if missing:
            detail.append(f"release assets absent from SHA256SUMS: {', '.join(missing)}")
        if unknown:
            detail.append(f"SHA256SUMS entries not on the release: {', '.join(unknown)}")
        print(f"error: {'; '.join(detail)}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("tag", help="release tag (e.g. v1.0.0)")
    parser.add_argument("--secret-key", "-s", help="path to minisign secret key file")
    args = parser.parse_args()

    tag = normalize_tag(args.tag)

    # Verify draft release exists with expected assets.
    result = subprocess.run(
        ["gh", "release", "view", tag, "--repo", REPO, "--json", "isDraft,assets"],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"error: failed to fetch release {tag}: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)

    release = json.loads(result.stdout)
    if not release["isDraft"]:
        print(f"error: release {tag} is not a draft", file=sys.stderr)
        sys.exit(1)

    asset_names = {a["name"] for a in release["assets"]}

    if "SHA256SUMS" not in asset_names:
        print("error: SHA256SUMS not found on release", file=sys.stderr)
        sys.exit(1)

    if "SHA256SUMS.minisig" in asset_names:
        print("error: SHA256SUMS.minisig already exists on release (already signed?)", file=sys.stderr)
        sys.exit(1)

    # Download, validate, sign, upload.
    with tempfile.TemporaryDirectory(prefix="hole-sign-") as tmpdir:
        tmpdir = Path(tmpdir)

        subprocess.run(
            ["gh", "release", "download", tag, "--repo", REPO, "--pattern", "SHA256SUMS", "--dir",
             str(tmpdir)],
            check=True,
        )

        sha256sums_path = tmpdir / "SHA256SUMS"
        validate_sha256sums(sha256sums_path, signable_asset_names(asset_names))

        sign_cmd = ["minisign", "-Sm", str(sha256sums_path)]
        if args.secret_key:
            sign_cmd.extend(["-s", args.secret_key])
        subprocess.run(sign_cmd, check=True)

        minisig_path = tmpdir / "SHA256SUMS.minisig"
        if not minisig_path.exists():
            print("error: minisign did not produce SHA256SUMS.minisig", file=sys.stderr)
            sys.exit(1)

        subprocess.run(
            ["gh", "release", "upload", tag, "--repo", REPO,
             str(minisig_path)],
            check=True,
        )

    print(f"\nSignature uploaded to {tag}.")
    print("Run the 'Publish Release' workflow to finalize.")


if __name__ == "__main__":
    main()

# Tests (run with pytest) ==============================================================================================


def test_normalize_tag_with_v_prefix():
    assert normalize_tag("v1.0.0") == "releases/hole/v1.0.0"


def test_normalize_tag_without_prefix():
    assert normalize_tag("1.0.0") == "releases/hole/v1.0.0"


def test_normalize_tag_with_full_prefix():
    assert normalize_tag("releases/hole/v1.0.0") == "releases/hole/v1.0.0"


def test_normalize_tag_large_numbers():
    assert normalize_tag("v10.20.30") == "releases/hole/v10.20.30"


def test_normalize_tag_invalid():
    import pytest

    with pytest.raises(SystemExit):
        normalize_tag("v1.0")
    with pytest.raises(SystemExit):
        normalize_tag("v1.0.0-rc1")
    with pytest.raises(SystemExit):
        normalize_tag("abc")


# The 0.5.0 asset set: three installers plus the three update archives added in
# #659. A hardcoded count went stale on exactly this change (#682).
SIGNABLE_ASSETS = [
    "hole-0.5.0-darwin-amd64.dmg",
    "hole-0.5.0-darwin-amd64.tar.gz",
    "hole-0.5.0-darwin-arm64.dmg",
    "hole-0.5.0-darwin-arm64.tar.gz",
    "hole-0.5.0-windows-amd64.msi",
    "hole-0.5.0-windows-amd64.zip",
]


def _sums(names):
    return "".join(f"{i:064x}  {name}\n" for i, name in enumerate(names, 1))


def test_accepts_sums_covering_every_release_asset(tmp_path):
    path = tmp_path / "SHA256SUMS"
    path.write_text(_sums(SIGNABLE_ASSETS))

    validate_sha256sums(path, set(SIGNABLE_ASSETS))


def test_asset_count_is_not_fixed(tmp_path):
    """Adding an asset to the release must not require touching this script."""
    extended = [*SIGNABLE_ASSETS, "hole-0.5.0-linux-amd64.tar.gz"]
    path = tmp_path / "SHA256SUMS"
    path.write_text(_sums(extended))

    validate_sha256sums(path, set(extended))


def test_rejects_asset_missing_from_sums(tmp_path):
    import pytest

    path = tmp_path / "SHA256SUMS"
    path.write_text(_sums(SIGNABLE_ASSETS[:-1]))

    with pytest.raises(SystemExit):
        validate_sha256sums(path, set(SIGNABLE_ASSETS))


def test_rejects_sums_line_for_unknown_asset(tmp_path):
    import pytest

    path = tmp_path / "SHA256SUMS"
    path.write_text(_sums([*SIGNABLE_ASSETS, "hole-0.5.0-windows-arm64.msi"]))

    with pytest.raises(SystemExit):
        validate_sha256sums(path, set(SIGNABLE_ASSETS))


def test_rejects_duplicate_entry(tmp_path):
    import pytest

    path = tmp_path / "SHA256SUMS"
    path.write_text(_sums(SIGNABLE_ASSETS) + f"{7:064x}  {SIGNABLE_ASSETS[0]}\n")

    with pytest.raises(SystemExit):
        validate_sha256sums(path, set(SIGNABLE_ASSETS))


def test_rejects_malformed_line(tmp_path):
    import pytest

    path = tmp_path / "SHA256SUMS"
    path.write_text("not-a-hash  hole-0.5.0-windows-amd64.msi\n")

    with pytest.raises(SystemExit):
        validate_sha256sums(path, {"hole-0.5.0-windows-amd64.msi"})


def test_signature_assets_are_not_themselves_hashed(tmp_path):
    """`SHA256SUMS`/`.minisig` are release assets but never entries."""
    path = tmp_path / "SHA256SUMS"
    path.write_text(_sums(SIGNABLE_ASSETS))

    validate_sha256sums(path, signable_asset_names(SIGNABLE_ASSETS + ["SHA256SUMS"]))


def test_validate_sha256sums_valid(tmp_path: Path):
    p = tmp_path / "SHA256SUMS"
    p.write_text(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  hole-1.0.0-windows-amd64.msi\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  hole-1.0.0-darwin-arm64.dmg\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  hole-1.0.0-darwin-amd64.dmg\n"
    )
    validate_sha256sums(
        p,
        {
            "hole-1.0.0-windows-amd64.msi",
            "hole-1.0.0-darwin-arm64.dmg",
            "hole-1.0.0-darwin-amd64.dmg",
        },
    )  # should not raise


def test_validate_sha256sums_short_of_the_release_assets(tmp_path: Path):
    import pytest

    p = tmp_path / "SHA256SUMS"
    p.write_text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  hole-1.0.0-windows-amd64.msi\n")
    with pytest.raises(SystemExit):
        validate_sha256sums(p, {"hole-1.0.0-windows-amd64.msi", "hole-1.0.0-darwin-arm64.dmg"})


def test_validate_sha256sums_malformed_hash(tmp_path: Path):
    import pytest

    p = tmp_path / "SHA256SUMS"
    p.write_text(
        "shorthash  hole-1.0.0-windows-amd64.msi\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  hole-1.0.0-darwin-arm64.dmg\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  hole-1.0.0-darwin-amd64.dmg\n"
    )
    with pytest.raises(SystemExit):
        validate_sha256sums(
            p,
            {
                "hole-1.0.0-windows-amd64.msi",
                "hole-1.0.0-darwin-arm64.dmg",
                "hole-1.0.0-darwin-amd64.dmg",
            },
        )
