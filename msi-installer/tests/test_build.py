"""Unit tests for msi_installer build helpers."""

from pathlib import Path

import pytest

from msi_installer import BuildError, find_wix_exe, get_version

# Note: hardlink/copy logic moved to `xtask::stage` (Rust). See xtask/src/stage.rs
# and xtask/src/stage_tests.rs. The msi-installer Python project no longer
# owns BINDIR composition — `stage_files()` delegates to `cargo xtask stage`.

# get_version tests ====================================================================================================


def test_get_version(tmp_path: Path) -> None:
    gui_dir = tmp_path / "crates" / "hole"
    gui_dir.mkdir(parents=True)
    (gui_dir / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "1.2.3"\n')

    assert get_version(tmp_path) == "1.2.3"


def test_get_version_rejects_invalid(tmp_path: Path) -> None:
    gui_dir = tmp_path / "crates" / "hole"
    gui_dir.mkdir(parents=True)
    (gui_dir / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "1.2.3-beta"\n')

    with pytest.raises(BuildError):
        get_version(tmp_path)


# find_wix_exe tests ===================================================================================================


def test_find_wix_exe_found(tmp_path: Path) -> None:
    wix = tmp_path / "sub" / "dir" / "wix.exe"
    wix.parent.mkdir(parents=True)
    wix.write_text("")

    assert find_wix_exe(tmp_path) == wix


def test_find_wix_exe_not_found(tmp_path: Path) -> None:
    assert find_wix_exe(tmp_path) is None
