"""`find_built_dmg` picks the DMG under test: `DMG_UNDER_TEST`, else the one release-build `.dmg`."""

from pathlib import Path

import pytest

import dmg_installer


def make_dmg(directory: Path, name: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / name
    path.write_bytes(b"dmg")
    return path


def test_the_environment_variable_names_the_dmg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    elsewhere = make_dmg(tmp_path / "elsewhere", "other.dmg")
    make_dmg(tmp_path / "target" / "release" / "bundle" / "dmg", "built.dmg")
    monkeypatch.setenv(dmg_installer.DMG_ENV, str(elsewhere))

    assert dmg_installer.find_built_dmg(tmp_path) == elsewhere


def test_without_the_variable_the_single_built_dmg_is_used(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(dmg_installer.DMG_ENV, raising=False)
    built = make_dmg(tmp_path / "target" / "release" / "bundle" / "dmg", "built.dmg")

    assert dmg_installer.find_built_dmg(tmp_path) == built


def test_a_missing_override_fails_instead_of_falling_back(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    make_dmg(tmp_path / "target" / "release" / "bundle" / "dmg", "built.dmg")
    monkeypatch.setenv(dmg_installer.DMG_ENV, str(tmp_path / "nope.dmg"))

    with pytest.raises(dmg_installer.DmgTestError):
        dmg_installer.find_built_dmg(tmp_path)
