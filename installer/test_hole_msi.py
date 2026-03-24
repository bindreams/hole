"""Build + validation tests for installer/hole.wxs.

Builds an MSI with dummy binaries, then validates it via ICE checks and
table inspection. Windows-only (requires WiX toolchain and msiexec).

Run with: uv run pytest installer/test_hole_msi.py -v
"""
# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest"]
# ///

import platform
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from conftest import NS, WXS_PATH

pytestmark = pytest.mark.skipif(
    platform.system() != "Windows", reason="Windows-only (needs WiX + msiexec)"
)


# Fixtures =====


@pytest.fixture(scope="session")
def staged_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a staging directory with dummy (empty) binaries."""
    d = tmp_path_factory.mktemp("stage")
    for name in ("hole.exe", "v2ray-plugin.exe", "wintun.dll"):
        (d / name).write_bytes(b"")
    return d


@pytest.fixture(scope="session")
def built_msi(
    wix_exe: Path, staged_dir: Path, tmp_path_factory: pytest.TempPathFactory
) -> Path:
    """Build an MSI from hole.wxs with dummy binaries."""
    out_dir = tmp_path_factory.mktemp("msi")
    msi_path = out_dir / "hole.msi"
    result = subprocess.run(
        [
            str(wix_exe), "build", str(WXS_PATH),
            "-arch", "x64",
            "-bindpath", f"BinDir={staged_dir}",
            "-d", "ProductVersion=1.0.0",
            "-o", str(msi_path),
        ],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"wix build failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    return msi_path


@pytest.fixture(scope="session")
def decompiled_tree(
    wix_exe: Path, built_msi: Path, tmp_path_factory: pytest.TempPathFactory
) -> ET.ElementTree:
    """Decompile the built MSI back to XML for table inspection."""
    out_dir = tmp_path_factory.mktemp("decompiled")
    wxs_out = out_dir / "decompiled.wxs"
    result = subprocess.run(
        [str(wix_exe), "msi", "decompile", str(built_msi), "-o", str(wxs_out)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"wix msi decompile failed (exit {result.returncode}):\n{result.stderr}"
    )
    return ET.parse(wxs_out)


# Build tests =====


def test_wix_build_succeeds(built_msi: Path) -> None:
    """wix build should exit 0 and produce an MSI file."""
    assert built_msi.exists()
    assert built_msi.stat().st_size > 0


def test_ice_validation_passes(wix_exe: Path, built_msi: Path) -> None:
    """wix msi validate should pass all ICE checks."""
    result = subprocess.run(
        [str(wix_exe), "msi", "validate", str(built_msi)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"ICE validation failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


# Sequence number tests =====


def _get_decompiled_sequence_map(tree: ET.ElementTree) -> dict[str, dict]:
    """Extract InstallExecuteSequence entries from decompiled XML.

    Returns {action_name: {"before": ..., "after": ..., "condition": ...}}.
    """
    pkg = tree.getroot().find("wix:Package", NS)
    assert pkg is not None
    seq = pkg.find("wix:InstallExecuteSequence", NS)
    assert seq is not None, "InstallExecuteSequence not found in decompiled MSI"

    entries = {}
    for custom in seq.findall("wix:Custom", NS):
        action = custom.get("Action", "")
        entries[action] = {
            "before": custom.get("Before"),
            "after": custom.get("After"),
            "condition": custom.get("Condition", ""),
        }
    return entries


def test_sequence_install_order(decompiled_tree: ET.ElementTree) -> None:
    """Install CAs must be ordered: InstallFiles < DaemonInstall < PathAdd."""
    entries = _get_decompiled_sequence_map(decompiled_tree)

    assert "DaemonInstall" in entries, "DaemonInstall not found in InstallExecuteSequence"
    assert "PathAdd" in entries, "PathAdd not found in InstallExecuteSequence"

    assert entries["DaemonInstall"]["after"] == "InstallFiles", (
        f"DaemonInstall should be After='InstallFiles', "
        f"got After='{entries['DaemonInstall']['after']}'"
    )
    assert entries["PathAdd"]["after"] == "DaemonInstall", (
        f"PathAdd should be After='DaemonInstall', "
        f"got After='{entries['PathAdd']['after']}'"
    )


def test_sequence_uninstall_order(decompiled_tree: ET.ElementTree) -> None:
    """Uninstall CAs must be ordered: PathRemove < DaemonUninstall < RemoveFiles."""
    entries = _get_decompiled_sequence_map(decompiled_tree)

    assert "DaemonUninstall" in entries, "DaemonUninstall not found in InstallExecuteSequence"
    assert "PathRemove" in entries, "PathRemove not found in InstallExecuteSequence"

    assert entries["DaemonUninstall"]["before"] == "RemoveFiles", (
        f"DaemonUninstall should be Before='RemoveFiles', "
        f"got Before='{entries['DaemonUninstall']['before']}'"
    )
    assert entries["PathRemove"]["before"] == "DaemonUninstall", (
        f"PathRemove should be Before='DaemonUninstall', "
        f"got Before='{entries['PathRemove']['before']}'"
    )


# Component bitness tests =====


def test_components_are_64bit(decompiled_tree: ET.ElementTree) -> None:
    """All components must target 64-bit (not 'always32').

    A 32-bit MSI installs to Program Files (x86) instead of Program Files,
    which is incorrect for x64 binaries.
    """
    pkg = decompiled_tree.getroot().find("wix:Package", NS)
    assert pkg is not None

    for comp in pkg.iter(f"{{{NS['wix']}}}Component"):
        comp_id = comp.get("Id", "<anonymous>")
        bitness = comp.get("Bitness", "")
        assert bitness != "always32", (
            f"Component '{comp_id}' has Bitness='always32' (32-bit). "
            "Pass '-arch x64' to 'wix build' to build a 64-bit MSI."
        )
