"""Build + validation tests for hole.wxs.

Builds an MSI with dummy binaries, then validates it via ICE checks and
table inspection. Windows-only, requires WiX toolchain.
"""

import platform
import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from conftest import NS, WXS_PATH

pytestmark = [
    pytest.mark.skipif(platform.system() != "Windows", reason="Windows-only (needs WiX + msiexec)"),
    pytest.mark.wix,
]

# Fixtures =============================================================================================================


@pytest.fixture(scope="session")
def staged_dir(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Create a staging directory with non-zero dummy binaries.

    Non-zero so the embedded cabinet actually contains data and the
    relocated-extract test (#357) has files to find post-extraction.
    """
    d = tmp_path_factory.mktemp("stage")
    for name in ("hole.exe", "v2ray-plugin.exe", "wintun.dll"):
        (d / name).write_bytes(b"x" * 1024)
    return d


@pytest.fixture(scope="session")
def built_msi(wix_exe: Path, staged_dir: Path, tmp_path_factory: pytest.TempPathFactory) -> Path:
    """Build an MSI from hole.wxs with dummy binaries."""
    out_dir = tmp_path_factory.mktemp("msi")
    msi_path = out_dir / "hole.msi"
    result = subprocess.run(
        [
            str(wix_exe),
            "build",
            str(WXS_PATH),
            "-arch",
            "x64",
            "-bindpath",
            f"BinDir={staged_dir}",
            "-d",
            "ProductVersion=1.0.0",
            "-o",
            str(msi_path),
        ],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"wix build failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    return msi_path


@pytest.fixture(scope="session")
def decompiled_tree(wix_exe: Path, built_msi: Path, tmp_path_factory: pytest.TempPathFactory) -> ET.ElementTree:
    """Decompile the built MSI back to XML for table inspection."""
    out_dir = tmp_path_factory.mktemp("decompiled")
    wxs_out = out_dir / "decompiled.wxs"
    result = subprocess.run(
        [str(wix_exe), "msi", "decompile", str(built_msi), "-o",
         str(wxs_out)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (f"wix msi decompile failed (exit {result.returncode}):\n{result.stderr}")
    return ET.parse(wxs_out)


# Build tests ==========================================================================================================


def test_wix_build_succeeds(built_msi: Path) -> None:
    """wix build should exit 0 and produce an MSI file."""
    assert built_msi.exists()
    assert built_msi.stat().st_size > 0


def test_ice_validation_passes(wix_exe: Path, built_msi: Path) -> None:
    """wix msi validate should pass all ICE checks."""
    result = subprocess.run(
        [str(wix_exe), "msi", "validate", str(built_msi)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"ICE validation failed (exit {result.returncode}):\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )


# Sequence number tests ================================================================================================


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
    """Install CAs must be ordered: InstallFiles < BridgeInstall < PathAdd."""
    entries = _get_decompiled_sequence_map(decompiled_tree)

    assert "BridgeInstall" in entries, "BridgeInstall not found in InstallExecuteSequence"
    assert "PathAdd" in entries, "PathAdd not found in InstallExecuteSequence"

    assert entries["BridgeInstall"]["after"] == "InstallFiles", (
        f"BridgeInstall should be After='InstallFiles', "
        f"got After='{entries['BridgeInstall']['after']}'"
    )
    assert entries["PathAdd"]["after"] == "BridgeInstall", (
        f"PathAdd should be After='BridgeInstall', "
        f"got After='{entries['PathAdd']['after']}'"
    )


def test_sequence_uninstall_order(decompiled_tree: ET.ElementTree) -> None:
    """Uninstall CAs must be ordered: PathRemove < BridgeUninstall < RemoveFiles."""
    entries = _get_decompiled_sequence_map(decompiled_tree)

    assert "BridgeUninstall" in entries, "BridgeUninstall not found in InstallExecuteSequence"
    assert "PathRemove" in entries, "PathRemove not found in InstallExecuteSequence"

    assert entries["BridgeUninstall"]["before"] == "RemoveFiles", (
        f"BridgeUninstall should be Before='RemoveFiles', "
        f"got Before='{entries['BridgeUninstall']['before']}'"
    )
    assert entries["PathRemove"]["before"] == "BridgeUninstall", (
        f"PathRemove should be Before='BridgeUninstall', "
        f"got Before='{entries['PathRemove']['before']}'"
    )


# Component bitness tests ==============================================================================================


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


# Cabinet embedding tests ==============================================================================================


def test_decompiled_msi_cab_is_embedded(decompiled_tree: ET.ElementTree) -> None:
    """The built MSI's Media table must declare embedded cabinets.

    `wix msi decompile` translates the on-disk Cabinet='#name.cab' embedded
    marker back to source form: it strips the '#' and emits EmbedCab='yes'
    on each <Media>. Absence of EmbedCab='yes' on the decompiled XML means
    the MSI ships external cabs and breaks for end users (#357 — v0.1.0).
    """
    pkg = decompiled_tree.getroot().find("wix:Package", NS)
    assert pkg is not None
    media_elements = list(pkg.iter(f"{{{NS['wix']}}}Media"))
    assert media_elements, "Decompiled MSI has no <Media> element"
    for media in media_elements:
        embed = media.get("EmbedCab", "")
        assert embed == "yes", (
            f"<Media Id='{media.get('Id')}' Cabinet='{media.get('Cabinet')}' "
            f"EmbedCab='{embed}'> declares an EXTERNAL cabinet. "
            "Set <MediaTemplate EmbedCab='yes'> in hole.wxs."
        )


def test_built_msi_has_no_external_cab(built_msi: Path) -> None:
    """No .cab file should sit next to the built .msi.

    External cabs land in the same directory as the .msi with a name like
    'cab1.cab'. End users who download only the .msi then get 'Source file
    not found: cab1.cab' at install time (#357 — v0.1.0).
    """
    siblings = list(built_msi.parent.glob("*.cab"))
    assert not siblings, (
        f"Found external cabinet(s) next to the built MSI: {siblings}. "
        "The MSI must be self-contained (<MediaTemplate EmbedCab='yes'>)."
    )


def test_msi_admin_extract_works_when_separated_from_build_dir(
    built_msi: Path,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Simulate the end-user 'download MSI alone and run it' flow.

    Copy the .msi alone to a fresh directory (no cab siblings) and run
    `msiexec /a` — administrative install, read-only extract, no admin
    rights, no system mutation. External-cab MSIs fail here with the same
    'cab1.cab not found' error that broke v0.1.0 (#357).
    """
    relocated_dir = tmp_path_factory.mktemp("relocated")
    relocated = Path(shutil.copy(built_msi, relocated_dir / "hole.msi"))
    extract_dir = tmp_path_factory.mktemp("extract")
    abs_target = str(extract_dir.resolve())

    # Trailing backslash on TARGETDIR is required by msiexec.
    result = subprocess.run(
        ["msiexec", "/a", str(relocated.resolve()), f"TARGETDIR={abs_target}\\", "/qn"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, (
        f"msiexec /a failed (exit {result.returncode}) on a relocated MSI — "
        f"the same code path that failed for v0.1.0 end users.\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )

    extracted = {
        p.name
        for p in extract_dir.rglob("*") if p.is_file() and p.name in {"hole.exe", "v2ray-plugin.exe", "wintun.dll"}
    }
    assert extracted == {"hole.exe", "v2ray-plugin.exe",
                         "wintun.dll"}, (f"MSI extracted but expected payload missing: got {extracted}")
