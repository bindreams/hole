"""Unit tests for msi_installer build helpers."""

import os
from pathlib import Path

import pytest

from msi_installer import BuildError, find_wix_exe, get_version, link_or_copy


# link_or_copy tests ===================================================================================================


def test_link_or_copy_hardlink(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("hello")
    dst = tmp_path / "dst.txt"

    method = link_or_copy(src, dst)
    assert method == "hardlinked"
    assert dst.read_text() == "hello"
    assert os.path.samefile(src, dst)


def test_link_or_copy_overwrites_existing(tmp_path: Path) -> None:
    src = tmp_path / "src.txt"
    src.write_text("new")
    dst = tmp_path / "dst.txt"
    dst.write_text("old")

    link_or_copy(src, dst)
    assert dst.read_text() == "new"


def test_link_or_copy_fallback_to_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    src = tmp_path / "src.txt"
    src.write_text("hello")
    dst = tmp_path / "dst.txt"

    monkeypatch.setattr(os, "link", lambda s, d: (_ for _ in ()).throw(OSError("forced")))
    method = link_or_copy(src, dst)
    assert method == "copied"
    assert dst.read_text() == "hello"


# get_version tests ====================================================================================================


def test_get_version(tmp_path: Path) -> None:
    gui_dir = tmp_path / "crates" / "gui"
    gui_dir.mkdir(parents=True)
    (gui_dir / "Cargo.toml").write_text('[package]\nname = "test"\nversion = "1.2.3"\n')

    assert get_version(tmp_path) == "1.2.3"


def test_get_version_rejects_invalid(tmp_path: Path) -> None:
    gui_dir = tmp_path / "crates" / "gui"
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
