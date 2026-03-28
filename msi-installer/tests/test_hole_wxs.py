"""Static validation tests for hole.wxs.

Parse the WiX v6 source and verify structural correctness without building.
"""

import re
import xml.etree.ElementTree as ET

from conftest import NS

# Known bind path variables passed via `-bindpath` to `wix build`.
KNOWN_BINDPATHS = {"BinDir"}


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


def _collect_file_ids(package: ET.Element) -> set[str]:
    """Collect all File IDs defined in the WXS."""
    return {
        f.get("Id", "")
        for f in package.iter(f"{{{NS['wix']}}}File")
    }


def test_custom_actions_use_fileref(package: ET.Element) -> None:
    """Custom actions must use FileRef (Type 18), not Directory (Type 34).

    Type 34 fails to launch the exe from deferred custom actions (error 1721).
    Type 18 references the installed file directly by its File ID.
    """
    file_ids = _collect_file_ids(package)
    for ca in package.iter(f"{{{NS['wix']}}}CustomAction"):
        ca_id = ca.get("Id", "")
        assert ca.get("Directory") is None, (
            f"CustomAction '{ca_id}' uses Directory (Type 34) which fails in "
            "deferred execution. Use FileRef (Type 18) instead."
        )
        file_ref = ca.get("FileRef")
        if file_ref is not None:
            assert file_ref in file_ids, (
                f"CustomAction '{ca_id}' references undefined File '{file_ref}'"
            )


def test_install_dir_is_64bit(package: ET.Element) -> None:
    """Binary components must install under ProgramFiles64Folder, not ProgramFilesFolder."""
    std_dirs = [
        elem.get("Id")
        for elem in package.iter(f"{{{NS['wix']}}}StandardDirectory")
    ]
    assert "ProgramFiles64Folder" in std_dirs, (
        "Installation root must use ProgramFiles64Folder for 64-bit binaries. "
        f"Found StandardDirectory IDs: {std_dirs}"
    )
    assert "ProgramFilesFolder" not in std_dirs, (
        "ProgramFilesFolder (32-bit) must not be used; use ProgramFiles64Folder"
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
    """Install conditions negate REMOVE (e.g. 'NOT REMOVE').

    An empty condition means "always run" and is not classified as install-only.
    """
    if not condition:
        return False
    return "NOT REMOVE" in condition


def _is_uninstall_condition(condition: str) -> bool:
    """Uninstall conditions test for REMOVE equality (e.g. 'REMOVE="ALL"').

    Note: XML entities like &quot; are resolved by the parser, so the
    condition string contains literal double-quotes at runtime.
    """
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
    """Every uninstall CA must have a direct Before anchor that leads to RemoveFiles.

    Only one hop of indirection is allowed: Before='RemoveFiles' directly,
    or Before another uninstall CA that itself has Before='RemoveFiles'.
    This keeps the ordering fully explicit and solver-independent.
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
        # that is itself directly Before RemoveFiles.
        allowed_targets = {"RemoveFiles"}
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
    """Map CustomAction Id -> element."""
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


# Shortcut component tests =====


def test_shortcut_registry_uses_hkcu(package: ET.Element) -> None:
    """Shortcut components must use HKCU for their KeyPath registry value.

    Start Menu shortcuts are per-user artifacts. Using HKLM for the KeyPath
    triggers ICE38, ICE43, and ICE57 (mixed per-user/per-machine data).
    """
    for comp in package.iter(f"{{{NS['wix']}}}Component"):
        shortcuts = list(comp.iter(f"{{{NS['wix']}}}Shortcut"))
        if not shortcuts:
            continue

        comp_id = comp.get("Id", "<anonymous>")
        for reg in comp.iter(f"{{{NS['wix']}}}RegistryValue"):
            if reg.get("KeyPath") == "yes":
                root = reg.get("Root", "")
                assert root == "HKCU", (
                    f"Shortcut component '{comp_id}' has KeyPath RegistryValue "
                    f"with Root='{root}'; must be 'HKCU' to avoid ICE38/ICE43/ICE57"
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
