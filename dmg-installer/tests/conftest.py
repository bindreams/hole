"""Shared fixtures for DMG installer tests."""

import json
import shutil
import subprocess
import warnings
from collections.abc import Iterator
from pathlib import Path

import pytest

import dmg_installer

REPO_ROOT = dmg_installer._find_repo_root()

# A com.apple.quarantine xattr value matching the shape Brave writes for a
# downloaded .dmg, so Gatekeeper assesses the test bundle on the same code
# path as a real user install.
QUARANTINE_VALUE = "0381;6a0b6446;Brave;FAKE0000-0000-0000-0000-000000000000"


def canonical_darwin_bindir() -> set[str]:
    """Canonical macOS BINDIR filenames, from the single source of truth.

    Runs `cargo xtask bindir-names --os darwin` so the DMG payload is checked
    against `bindir::bindir_dest_names`, not a hand-restated copy (mirrors
    `msi-installer/tests/conftest.py::canonical_windows_bindir`). The dmg lane
    builds via cargo, so the toolchain is present; `check=True` surfaces a
    missing toolchain loudly rather than silently skipping.
    """
    out = subprocess.run(
        ["cargo", "xtask", "bindir-names", "--os", "darwin"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return set(json.loads(out.stdout))


@pytest.fixture(scope="module")
def installed_app(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Mount the built DMG, copy Hole.app to a tmp dir, mark it quarantined.

    The copy is what we test — copying out of the read-only mount mirrors
    what Finder does on `cp -R` and what the OS does when the user drags
    Hole.app into /Applications. Quarantine is applied so Gatekeeper's
    assessment runs in the same code path it would for a real download.

    Flags align with the bridge cutover's DMG attach in
    `crates/bridge/src/cutover/extract.rs` (-nobrowse, -quiet, -mountpoint) and
    add -readonly + -noverify which only make sense for read-only test mounts.
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


@pytest.fixture(scope="module")
def mounted_dmg(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Path]:
    """Attach the built DMG read-only and yield the mounted volume root.

    Layout assertions read the volume's `.DS_Store` and `.background.tiff`, which
    the app-only `installed_app` fixture does not expose.
    """
    dmg = dmg_installer.find_built_dmg(REPO_ROOT)
    mount_dir = tmp_path_factory.mktemp("layout-mount")
    subprocess.run(
        ["hdiutil", "attach", "-nobrowse", "-readonly", "-noverify", "-quiet", "-mountpoint",
         str(mount_dir),
         str(dmg)],
        check=True,
    )
    try:
        yield mount_dir
    finally:
        # Best-effort, but visible: a busy detach leaves a stale mount that can
        # break the next run's attach — surface it instead of swallowing it.
        r = subprocess.run(["hdiutil", "detach", str(mount_dir)], capture_output=True, text=True)
        if r.returncode != 0:
            warnings.warn(f"hdiutil detach {mount_dir} failed (rc={r.returncode}): {r.stderr.strip()}")
