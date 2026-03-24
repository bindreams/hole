"""Shared fixtures and constants for installer tests."""

import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

NS = {"wix": "http://wixtoolset.org/schemas/v4/wxs"}
WXS_PATH = Path(__file__).parent / "hole.wxs"
REPO_ROOT = Path(__file__).resolve().parent.parent


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


@pytest.fixture(scope="session")
def wix_exe() -> Path:
    """Locate the cached WiX toolchain. Skips tests if not available."""
    cache_dir = REPO_ROOT / ".cache" / "wix"
    if not cache_dir.exists():
        pytest.skip("WiX toolchain not found in .cache/wix/")

    for child in sorted(cache_dir.iterdir()):
        if child.is_dir() and child.name.startswith("wix-v"):
            exe = next(child.rglob("wix.exe"), None)
            if exe is not None:
                return exe

    pytest.skip("wix.exe not found in .cache/wix/")
