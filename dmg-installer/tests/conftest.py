"""Shared fixtures for DMG installer tests."""

import shutil
import subprocess
from collections.abc import Iterator
from pathlib import Path

import pytest

import dmg_installer

REPO_ROOT = dmg_installer._find_repo_root()

# The xattr value Brave writes when downloading a .dmg. Recorded verbatim
# from a real installed bundle on 2026-05-18: the third semicolon-separated
# field is the source app, the fourth is a per-download UUID; the leading
# `0381` is the quarantine flags field (uncleared + user-approved bit).
# Mirroring the exact shape ensures Gatekeeper treats the test bundle the
# same way it treats a real user install.
QUARANTINE_VALUE = "0381;6a0b6446;Brave;FAKE0000-0000-0000-0000-000000000000"


@pytest.fixture(scope="module")
def installed_app(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Mount the built DMG, copy Hole.app to a tmp dir, mark it quarantined.

    The copy is what we test — copying out of the read-only mount mirrors
    what Finder does on `cp -R` and what the OS does when the user drags
    Hole.app into /Applications. Quarantine is applied so Gatekeeper's
    assessment runs in the same code path it would for a real download.

    Flags align with `crates/hole/src/update/install.rs::hdiutil_attach_args`
    (-nobrowse, -quiet, -mountpoint) and add -readonly + -noverify which
    only make sense for read-only test mounts.
    """
    dmg = dmg_installer.find_built_dmg(REPO_ROOT)

    mount_dir = tmp_path_factory.mktemp("mount")
    install_dir = tmp_path_factory.mktemp("install")

    subprocess.run(
        [
            "hdiutil",
            "attach",
            "-nobrowse",
            "-readonly",
            "-noverify",
            "-quiet",
            "-mountpoint",
            str(mount_dir),
            str(dmg),
        ],
        check=True,
    )
    try:
        src_app = mount_dir / "Hole.app"
        if not src_app.is_dir():
            raise dmg_installer.DmgTestError(f"Hole.app not found in DMG (looked in {mount_dir})")

        dst_app = install_dir / "Hole.app"
        shutil.copytree(src_app, dst_app, symlinks=True)

        subprocess.run(
            ["xattr", "-w", "com.apple.quarantine", QUARANTINE_VALUE,
             str(dst_app)],
            check=True,
        )

        yield dst_app
    finally:
        subprocess.run(
            ["hdiutil", "detach", "-quiet", str(mount_dir)],
            check=False,
        )
