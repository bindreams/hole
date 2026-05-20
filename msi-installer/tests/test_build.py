"""Unit tests for msi_installer build helpers."""

from pathlib import Path

import pytest

from msi_installer import BuildError, find_wix_exe, get_version, ui_extension_path

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


# ui_extension_path tests ==============================================================================================


def _make_wix_layout(cache_dir: Path, version: str, minor: str, wixext: str) -> tuple[Path, Path]:
    """Lay out a fake wix-v<ver> cache tree mirroring the admin-extracted MSI.

    Returns (wix_exe_path, ui_ext_dll_path). The two paths are *not* linked —
    `ui_extension_path` derives the DLL location from `wix_exe`'s grandparents
    plus the wixext folder name; this fixture creates both so the existence
    check inside the function passes.
    """
    cache_root = cache_dir / f"wix-v{version}"
    wix_exe = cache_root / "PFiles64" / f"WiX Toolset v{minor}" / "bin" / "wix.exe"
    wix_exe.parent.mkdir(parents=True)
    wix_exe.write_text("")

    dll = (
        cache_root / "CFiles64" / "WixToolset" / "extensions" / "WixToolset.UI.wixext" / version / wixext /
        "WixToolset.UI.wixext.dll"
    )
    dll.parent.mkdir(parents=True)
    dll.write_text("")
    return wix_exe, dll


def test_ui_extension_path_v7(tmp_path: Path) -> None:
    wix_exe, expected_dll = _make_wix_layout(tmp_path, version="7.0.0", minor="7.0", wixext="wixext7")
    assert ui_extension_path(wix_exe) == expected_dll


def test_ui_extension_path_derives_from_major(tmp_path: Path) -> None:
    """Forward-looking: derivation is `wixext{major}`, not a literal 7."""
    wix_exe, expected_dll = _make_wix_layout(tmp_path, version="8.1.2", minor="8.1", wixext="wixext8")
    assert ui_extension_path(wix_exe) == expected_dll


def test_ui_extension_path_missing_dll_raises(tmp_path: Path) -> None:
    cache_root = tmp_path / "wix-v7.0.0"
    wix_exe = cache_root / "PFiles64" / "WiX Toolset v7.0" / "bin" / "wix.exe"
    wix_exe.parent.mkdir(parents=True)
    wix_exe.write_text("")
    # No DLL written under CFiles64/...

    with pytest.raises(BuildError):
        ui_extension_path(wix_exe)
