"""Static validation tests for installer/hole.wxs.

Parse the WiX v6 source and verify structural correctness without building.
Run with: uv run pytest installer/test_hole_wxs.py -v
"""
# /// script
# requires-python = ">=3.11"
# dependencies = ["pytest"]
# ///

import re
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

NS = {"wix": "http://wixtoolset.org/schemas/v4/wxs"}
WXS_PATH = Path(__file__).parent / "hole.wxs"

# Known bind path variables passed by build-installer.py via `-bindpath`.
KNOWN_BINDPATHS = {"BinDir"}


# Fixtures =====


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


# GUID tests =====


def _collect_component_guids(package: ET.Element) -> list[tuple[str, str]]:
    """Return (component_id, guid) pairs for all Components."""
    result = []
    for comp in package.iter(f"{{{NS['wix']}}}Component"):
        comp_id = comp.get("Id", "<anonymous>")
        guid = comp.get("Guid")
        if guid is not None:
            result.append((comp_id, guid))
    return result


UUID_RE = re.compile(
    r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
)


def test_guids_are_unique(package: ET.Element) -> None:
    pairs = _collect_component_guids(package)
    guids = [g for _, g in pairs]
    assert len(guids) == len(set(guids)), (
        f"Duplicate component GUIDs: {[g for g in guids if guids.count(g) > 1]}"
    )


def test_guids_are_valid_format(package: ET.Element) -> None:
    for comp_id, guid in _collect_component_guids(package):
        assert UUID_RE.match(guid), (
            f"Component '{comp_id}' has invalid GUID format: {guid}"
        )


# Directory reference tests =====


def _collect_directory_ids(package: ET.Element) -> set[str]:
    """Collect all defined directory IDs (Directory and StandardDirectory elements)."""
    ids: set[str] = set()
    for tag in ("Directory", "StandardDirectory"):
        for elem in package.iter(f"{{{NS['wix']}}}{tag}"):
            dir_id = elem.get("Id")
            if dir_id:
                ids.add(dir_id)
    return ids


def test_custom_action_directories_defined(package: ET.Element) -> None:
    defined = _collect_directory_ids(package)
    for ca in package.iter(f"{{{NS['wix']}}}CustomAction"):
        dir_ref = ca.get("Directory")
        if dir_ref is not None:
            assert dir_ref in defined, (
                f"CustomAction '{ca.get('Id')}' references undefined directory '{dir_ref}'"
            )


# File source tests =====


BINDPATH_RE = re.compile(r"!\(bindpath\.(\w+)\)")


def test_file_sources_use_known_bindpaths(package: ET.Element) -> None:
    for file_elem in package.iter(f"{{{NS['wix']}}}File"):
        source = file_elem.get("Source", "")
        for match in BINDPATH_RE.finditer(source):
            var_name = match.group(1)
            assert var_name in KNOWN_BINDPATHS, (
                f"File '{file_elem.get('Id')}' uses unknown bindpath variable '{var_name}'. "
                f"Known: {KNOWN_BINDPATHS}"
            )


# Custom action sequencing tests =====


def _get_custom_entries(package: ET.Element) -> list[ET.Element]:
    """Return all <Custom> elements from InstallExecuteSequence."""
    seq = package.find("wix:InstallExecuteSequence", NS)
    assert seq is not None, "<InstallExecuteSequence> not found"
    return list(seq.findall("wix:Custom", NS))


def _is_install_condition(condition: str) -> bool:
    """Install conditions negate REMOVE (e.g. 'NOT REMOVE')."""
    return "NOT REMOVE" in condition or "REMOVE" not in condition


def _is_uninstall_condition(condition: str) -> bool:
    """Uninstall conditions test for REMOVE equality (e.g. 'REMOVE="ALL"')."""
    return 'REMOVE="' in condition or "REMOVE~=" in condition


def test_install_cas_sequenced_after_install_files(package: ET.Element) -> None:
    """Every install CA must be transitively After='InstallFiles'."""
    customs = _get_custom_entries(package)

    # Build a map: action -> what it's After
    after_map: dict[str, str] = {}
    for custom in customs:
        action = custom.get("Action", "")
        after = custom.get("After")
        if after:
            after_map[action] = after

    install_cas = [
        c for c in customs if _is_install_condition(c.get("Condition", ""))
    ]

    for custom in install_cas:
        action = custom.get("Action", "")
        # Walk the After chain to verify it reaches InstallFiles
        visited: set[str] = set()
        current = action
        found = False
        while current in after_map and current not in visited:
            visited.add(current)
            target = after_map[current]
            if target == "InstallFiles":
                found = True
                break
            current = target

        assert found, (
            f"Install CA '{action}' is not transitively After='InstallFiles'. "
            f"Chain: {' -> '.join(visited)}"
        )


def test_uninstall_cas_sequenced_before_remove_files(package: ET.Element) -> None:
    """Every uninstall CA must have a direct Before='RemoveFiles' constraint.

    MSI sequence numbers are absolute. Relying on transitive chains (e.g.
    After='X' where X is Before='RemoveFiles') couples correctness to
    the constraint solver's implementation. Requiring a direct anchor is
    a stronger, solver-independent guarantee.
    """
    customs = _get_custom_entries(package)
    uninstall_cas = [
        c for c in customs if _is_uninstall_condition(c.get("Condition", ""))
    ]

    for custom in uninstall_cas:
        action = custom.get("Action", "")
        before = custom.get("Before")
        assert before is not None, (
            f"Uninstall CA '{action}' has no Before attribute "
            "(must be directly anchored before a standard action)"
        )

        # The Before target must be RemoveFiles or another uninstall CA
        # that is itself directly Before RemoveFiles (i.e., the chain is
        # fully explicit).
        allowed_targets = {"RemoveFiles"}
        # Also allow Before another uninstall CA that itself has Before="RemoveFiles"
        for other in uninstall_cas:
            other_action = other.get("Action", "")
            if other.get("Before") == "RemoveFiles":
                allowed_targets.add(other_action)

        assert before in allowed_targets, (
            f"Uninstall CA '{action}' has Before='{before}', which is not 'RemoveFiles' "
            f"or another uninstall CA directly anchored to RemoveFiles. "
            f"Allowed targets: {allowed_targets}"
        )


# Package attribute tests =====


def test_package_version_is_preprocessor_variable(package: ET.Element) -> None:
    version = package.get("Version")
    assert version == "$(ProductVersion)", (
        f"Package Version should be '$(ProductVersion)', got '{version}'"
    )


def test_major_upgrade_exists(package: ET.Element) -> None:
    mu = package.find("wix:MajorUpgrade", NS)
    assert mu is not None, "MajorUpgrade element is required for upgrade support"


# Custom action attribute tests =====


def test_deferred_cas_not_impersonated(package: ET.Element) -> None:
    for ca in package.iter(f"{{{NS['wix']}}}CustomAction"):
        if ca.get("Execute") == "deferred":
            assert ca.get("Impersonate") == "no", (
                f"Deferred CA '{ca.get('Id')}' must have Impersonate='no' "
                "to run with elevated privileges"
            )


def _ca_map(package: ET.Element) -> dict[str, ET.Element]:
    """Map CustomAction Id → element."""
    return {
        ca.get("Id", ""): ca
        for ca in package.iter(f"{{{NS['wix']}}}CustomAction")
    }


def test_install_cas_return_check(package: ET.Element) -> None:
    cas = _ca_map(package)
    for custom in _get_custom_entries(package):
        if _is_install_condition(custom.get("Condition", "")):
            action = custom.get("Action", "")
            ca = cas.get(action)
            assert ca is not None, f"Custom references undefined CA '{action}'"
            assert ca.get("Return") == "check", (
                f"Install CA '{action}' should have Return='check' "
                "to fail the install on error"
            )


def test_uninstall_cas_return_ignore(package: ET.Element) -> None:
    cas = _ca_map(package)
    for custom in _get_custom_entries(package):
        if _is_uninstall_condition(custom.get("Condition", "")):
            action = custom.get("Action", "")
            ca = cas.get(action)
            assert ca is not None, f"Custom references undefined CA '{action}'"
            assert ca.get("Return") == "ignore", (
                f"Uninstall CA '{action}' should have Return='ignore' "
                "to avoid blocking uninstall"
            )


# Component key path tests =====


def test_every_component_has_key_path(package: ET.Element) -> None:
    for comp in package.iter(f"{{{NS['wix']}}}Component"):
        comp_id = comp.get("Id", "<anonymous>")
        key_path_children = [
            child for child in comp
            if child.get("KeyPath") == "yes"
        ]
        assert len(key_path_children) == 1, (
            f"Component '{comp_id}' must have exactly one child with KeyPath='yes', "
            f"found {len(key_path_children)}"
        )
