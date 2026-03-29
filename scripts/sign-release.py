#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Sign a draft GitHub release's SHA256SUMS and upload the signature.

Usage:
    uv run scripts/sign-release.py v1.0.0
    uv run scripts/sign-release.py v1.0.0 --secret-key ~/path/to/minisign.key
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = "bindreams/hole"
EXPECTED_INSTALLER_COUNT = 3


def normalize_tag(tag: str) -> str:
    """Strip optional 'v' prefix and validate semver format. Returns 'v'-prefixed tag."""
    version = tag.removeprefix("v")
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"error: invalid version: {tag!r} (expected MAJOR.MINOR.PATCH)", file=sys.stderr)
        sys.exit(1)
    return f"v{version}"


def validate_sha256sums(path: Path) -> None:
    """Validate that the SHA256SUMS file has the expected format."""
    content = path.read_text()
    lines = [line for line in content.splitlines() if line.strip()]

    if len(lines) != EXPECTED_INSTALLER_COUNT:
        print(
            f"error: SHA256SUMS has {len(lines)} entries, expected {EXPECTED_INSTALLER_COUNT}",
            file=sys.stderr,
        )
        sys.exit(1)

    for i, line in enumerate(lines, 1):
        if not re.fullmatch(r"[0-9a-fA-F]{64}  .+", line):
            print(f"error: SHA256SUMS line {i} is malformed: {line!r}", file=sys.stderr)
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
        validate_sha256sums(sha256sums_path)

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


def test_normalize_tag_with_prefix():
    assert normalize_tag("v1.0.0") == "v1.0.0"


def test_normalize_tag_without_prefix():
    assert normalize_tag("1.0.0") == "v1.0.0"


def test_normalize_tag_large_numbers():
    assert normalize_tag("v10.20.30") == "v10.20.30"


def test_normalize_tag_invalid():
    import pytest

    with pytest.raises(SystemExit):
        normalize_tag("v1.0")
    with pytest.raises(SystemExit):
        normalize_tag("v1.0.0-rc1")
    with pytest.raises(SystemExit):
        normalize_tag("abc")


def test_validate_sha256sums_valid(tmp_path: Path):
    p = tmp_path / "SHA256SUMS"
    p.write_text(
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  hole-1.0.0-windows-amd64.msi\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  hole-1.0.0-darwin-arm64.dmg\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  hole-1.0.0-darwin-amd64.dmg\n"
    )
    validate_sha256sums(p)  # should not raise


def test_validate_sha256sums_wrong_line_count(tmp_path: Path):
    import pytest

    p = tmp_path / "SHA256SUMS"
    p.write_text("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  hole-1.0.0-windows-amd64.msi\n")
    with pytest.raises(SystemExit):
        validate_sha256sums(p)


def test_validate_sha256sums_malformed_hash(tmp_path: Path):
    import pytest

    p = tmp_path / "SHA256SUMS"
    p.write_text(
        "shorthash  hole-1.0.0-windows-amd64.msi\n"
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb  hole-1.0.0-darwin-arm64.dmg\n"
        "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc  hole-1.0.0-darwin-amd64.dmg\n"
    )
    with pytest.raises(SystemExit):
        validate_sha256sums(p)
