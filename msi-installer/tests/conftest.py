"""Shared fixtures and constants for installer tests."""

import json
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest
from _pytest.mark import MarkMatcher
from _pytest.mark.expression import Expression
from rich.console import Console

import msi_installer

NS = {"wix": "http://wixtoolset.org/schemas/v4/wxs"}
WXS_PATH = msi_installer.WXS_PATH
REPO_ROOT = msi_installer._find_repo_root()


def canonical_windows_bindir() -> set[str]:
    """Canonical Windows BINDIR filenames, from the single source of truth.

    Runs `cargo xtask bindir-names` so the installer manifest is checked
    against `bindir::bindir_dest_names`, not a hand-restated copy. Hard-depends
    on cargo (the `installer-*` CI steps install Rust and runs `cargo xtask
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


# System-wide tests ====================================================================================================

# These change the machine, so a run selects them by name (`-m system_wide` / `-m cleanup`). `addopts = -m ...` cannot do
# this: an unrelated command-line `-m` (`-m "not wix"`) replaces it.
SYSTEM_WIDE_MARKERS = ("system_wide", "cleanup")


def _selected_by_name(expression: str, item: pytest.Item) -> bool:
    """Whether `-m` names `item`'s system-wide marker: the expression would not select the item without it.

    pytest has already dropped the items the expression is false for, so an item left here is selected;
    `-m "not wix"` selects it without the marker too, so does not name it.
    """
    if not expression:
        return False
    others = [m for m in item.iter_markers() if m.name not in SYSTEM_WIDE_MARKERS]
    return not Expression.compile(expression).evaluate(MarkMatcher.from_markers(others))


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    expression = config.getoption("markexpr") or ""
    kept, dropped = [], []
    for item in items:
        system_wide = any(item.get_closest_marker(m) for m in SYSTEM_WIDE_MARKERS)
        (dropped if system_wide and not _selected_by_name(expression, item) else kept).append(item)
    items[:] = kept
    config.hook.pytest_deselected(items=dropped)


# XML fixtures =========================================================================================================


@pytest.fixture(scope="session")
def wxs_tree() -> ET.ElementTree:
    return ET.parse(WXS_PATH)


@pytest.fixture(scope="session")
def root(wxs_tree: ET.ElementTree) -> ET.Element:
    return wxs_tree.getroot()


def find_package(root: ET.Element) -> ET.Element:
    pkg = root.find("wix:Package", NS)
    assert pkg is not None, "<Package> element not found"
    return pkg


@pytest.fixture(scope="session")
def package(root: ET.Element) -> ET.Element:
    return find_package(root)


# WiX toolchain fixture ================================================================================================


@pytest.fixture(scope="session")
def wix_exe() -> Path:
    """Download/locate WiX toolchain. Fails if unavailable."""
    console = Console(stderr=True)
    return msi_installer.ensure_wix(REPO_ROOT, console)
