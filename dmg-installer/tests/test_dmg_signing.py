"""Signature consistency checks for the built Hole.app.

These tests catch the failure mode behind issue #364: a Tauri-built .app
that ships with only the linker's ad-hoc Mach-O signature and no
`_CodeSignature/CodeResources` seal. Such a bundle launches "damaged"
under Gatekeeper quarantine because the Mach-O claims sealed resources
that don't exist.
"""

import subprocess
from pathlib import Path


def _codesign_dv(target: Path) -> str:
    """Return `codesign -dv --verbose=4` stderr (where codesign prints)."""
    result = subprocess.run(
        ["codesign", "-dv", "--verbose=4", str(target)],
        capture_output=True,
        text=True,
    )
    return result.stderr


def test_code_signature_directory_exists(installed_app: Path) -> None:
    assert (installed_app / "Contents" / "_CodeSignature" / "CodeResources").is_file()


def test_codesign_verify_strict_passes(installed_app: Path) -> None:
    result = subprocess.run(
        ["codesign", "--verify", "--strict", "--verbose=4", str(installed_app)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, f"codesign --verify --strict failed:\n{result.stderr}"


def test_codesign_verify_deep_strict_passes(installed_app: Path) -> None:
    result = subprocess.run(
        ["codesign", "--verify", "--deep", "--strict", "--verbose=4", str(installed_app)],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        f"codesign --verify --deep --strict failed:\n{result.stderr}"
    )


def test_bundle_has_sealed_resources(installed_app: Path) -> None:
    output = _codesign_dv(installed_app)
    assert "Sealed Resources=none" not in output, (
        f"bundle has no sealed resource envelope:\n{output}"
    )
    assert "Sealed Resources version=" in output, (
        f"bundle is missing Sealed Resources block:\n{output}"
    )


def test_main_binary_is_not_linker_signed(installed_app: Path) -> None:
    output = _codesign_dv(installed_app / "Contents" / "MacOS" / "hole")
    assert "linker-signed" not in output, (
        f"main binary still carries the linker-applied ad-hoc signature "
        f"(0x20000 flag bit) — Tauri's codesign step did not re-sign it:\n{output}"
    )


def test_sidecar_has_real_signature(installed_app: Path) -> None:
    output = _codesign_dv(installed_app / "Contents" / "MacOS" / "v2ray-plugin")
    assert "Identifier=a.out" not in output, (
        f"v2ray-plugin sidecar still has the Go-linker default identifier 'a.out' "
        f"— Tauri's codesign step did not re-sign it:\n{output}"
    )
    assert "linker-signed" not in output, (
        f"v2ray-plugin sidecar still carries the linker-applied ad-hoc signature:\n{output}"
    )
