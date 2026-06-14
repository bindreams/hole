"""Shared fixtures and constants for installer tests."""

import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from rich.console import Console

import msi_installer

NS = {"wix": "http://wixtoolset.org/schemas/v4/wxs"}
WXS_PATH = msi_installer.WXS_PATH
REPO_ROOT = msi_installer._find_repo_root()


def canonical_windows_bindir() -> set[str]:
    """Canonical Windows BINDIR filenames, from the single source of truth.

    Runs `cargo xtask bindir-names` so the installer manifest is checked
    against `bindir::bindir_dest_names`, not a hand-restated copy. Hard-depends
    on cargo (the `test-installer` lane installs Rust and runs `cargo xtask
    deps` before pytest); `check=True` surfaces a missing toolchain loudly
    rather than silently skipping.
    """
    out = subprocess.run(
        ["cargo", "xtask", "bindir-names", "--os", "windows"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    return set(json.loads(out.stdout))


# XML fixtures =========================================================================================================


@pytest.fixture(scope="session")
def wxs_tree() -> ET.ElementTree:
    return ET.parse(WXS_PATH)


@pytest.fixture(scope="session")
def root(wxs_tree: ET.ElementTree) -> ET.Element:
    return wxs_tree.getroot()


@pytest.fixture(scope="session")
def package(root: ET.Element) -> ET.Element:
    pkg = root.find("wix:Package", NS)
    assert pkg is not None, "<Package> element not found"
    return pkg


# WiX toolchain fixture ================================================================================================


@pytest.fixture(scope="session")
def wix_exe() -> Path:
    """Download/locate WiX toolchain. Fails if unavailable."""
    console = Console(stderr=True)
    return msi_installer.ensure_wix(REPO_ROOT, console)
