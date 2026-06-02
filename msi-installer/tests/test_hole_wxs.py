"""Static validation tests for hole.wxs.

Parse the WiX source (hole.wxs) and verify structural correctness without building.
"""

import re
import xml.etree.ElementTree as ET

from conftest import NS

# Known bind path variables passed via `-bindpath` to `wix build`.
KNOWN_BINDPATHS = {"BinDir", "IconDir", "LicenseDir"}

# Namespace for the WixUI extension elements (<ui:WixUI ...>).
UI_NS = "http://wixtoolset.org/schemas/v4/wxs/ui"

# GUID tests ===========================================================================================================


def _collect_component_guids(package: ET.Element) -> list[tuple[str, str]]:
    """Return (component_id, guid) pairs for all Components."""
    result = []
    for comp in package.iter(f"{{{NS['wix']}}}Component"):
        comp_id = comp.get("Id", "<anonymous>")
        guid = comp.get("Guid")
        if guid is not None:
            result.append((comp_id, guid))
    return result


UUID_RE = re.compile(r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$")


def test_guids_are_unique(package: ET.Element) -> None:
    pairs = _collect_component_guids(package)
    guids = [g for _, g in pairs]
    assert len(guids) == len(set(guids)), (f"Duplicate component GUIDs: {[g for g in guids if guids.count(g) > 1]}")


def test_guids_are_valid_format(package: ET.Element) -> None:
    for comp_id, guid in _collect_component_guids(package):
        assert UUID_RE.match(guid), (f"Component '{comp_id}' has invalid GUID format: {guid}")


# Directory reference tests ============================================================================================


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
            assert dir_ref in defined, (f"CustomAction '{ca.get('Id')}' references undefined directory '{dir_ref}'")


def _collect_file_ids(package: ET.Element) -> set[str]:
    """Collect all File IDs defined in the WXS."""
    return {f.get("Id", "") for f in package.iter(f"{{{NS['wix']}}}File")}


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
            assert file_ref in file_ids, (f"CustomAction '{ca_id}' references undefined File '{file_ref}'")


def test_install_dir_is_64bit(package: ET.Element) -> None:
    """Binary components must install under ProgramFiles64Folder, not ProgramFilesFolder."""
    std_dirs = [elem.get("Id") for elem in package.iter(f"{{{NS['wix']}}}StandardDirectory")]
    assert "ProgramFiles64Folder" in std_dirs, (
        "Installation root must use ProgramFiles64Folder for 64-bit binaries. "
        f"Found StandardDirectory IDs: {std_dirs}"
    )
    assert "ProgramFilesFolder" not in std_dirs, (
        "ProgramFilesFolder (32-bit) must not be used; use ProgramFiles64Folder"
    )


# File source tests ====================================================================================================

BINDPATH_RE = re.compile(r"!\(bindpath\.(\w+)\)")

# Elements that can bind a source path, mapped to the attribute they use.
# <File> uses Source; <Icon> uses SourceFile. Add new entries here when
# adding new source-bearing elements.
_SOURCE_BEARING_ELEMENTS = {
    "File": "Source",
    "Icon": "SourceFile",
}


def test_file_sources_use_known_bindpaths(package: ET.Element) -> None:
    for tag, attr in _SOURCE_BEARING_ELEMENTS.items():
        for elem in package.iter(f"{{{NS['wix']}}}{tag}"):
            source = elem.get(attr, "")
            for match in BINDPATH_RE.finditer(source):
                var_name = match.group(1)
                assert var_name in KNOWN_BINDPATHS, (
                    f"<{tag} Id='{elem.get('Id')}'> uses unknown bindpath variable '{var_name}'. "
                    f"Known: {KNOWN_BINDPATHS}"
                )


def test_wixvariable_values_use_known_bindpaths(package: ET.Element) -> None:
    for var_elem in package.iter(f"{{{NS['wix']}}}WixVariable"):
        value = var_elem.get("Value", "")
        for match in BINDPATH_RE.finditer(value):
            var_name = match.group(1)
            assert var_name in KNOWN_BINDPATHS, (
                f"WixVariable '{var_elem.get('Id')}' uses unknown bindpath variable "
                f"'{var_name}'. Known: {KNOWN_BINDPATHS}"
            )


# Custom action sequencing tests =======================================================================================


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


# CAs that launch the app after install — exempt from Return=check and After=InstallFiles rules.
_LAUNCH_CAS = {"LaunchApp"}


def test_install_cas_sequenced_after_install_files(package: ET.Element) -> None:
    """Every install CA (except launch CAs) must be transitively After='InstallFiles'."""
    customs = _get_custom_entries(package)

    # Build a map: action -> what it's After
    after_map: dict[str, str] = {}
    for custom in customs:
        action = custom.get("Action", "")
        after = custom.get("After")
        if after:
            after_map[action] = after

    install_cas = [c for c in customs if _is_install_condition(c.get("Condition", ""))]

    for custom in install_cas:
        action = custom.get("Action", "")
        if action in _LAUNCH_CAS:
            continue
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


def test_launch_ca_after_install_finalize(package: ET.Element) -> None:
    """Launch CAs must be After='InstallFinalize' and Return='asyncNoWait'."""
    cas = _ca_map(package)
    customs = _get_custom_entries(package)

    for custom in customs:
        action = custom.get("Action", "")
        if action not in _LAUNCH_CAS:
            continue
        assert custom.get("After") == "InstallFinalize", (f"Launch CA '{action}' must be After='InstallFinalize'")
        ca = cas[action]
        assert ca.get("Return") == "asyncNoWait", (f"Launch CA '{action}' must have Return='asyncNoWait'")
        assert ca.get("Impersonate"
                      ) == "yes", (f"Launch CA '{action}' must have Impersonate='yes' to run as the installing user")


def test_launch_ca_passes_show_dashboard(package: ET.Element) -> None:
    """Launch CA must pass --show-dashboard so the first-run UX is the dashboard, not tray-only."""
    assert _LAUNCH_CAS, "no launch CAs configured to test"
    cas = _ca_map(package)
    for action in _LAUNCH_CAS:
        ca = cas[action]
        assert ca.get("ExeCommand"
                      ) == "--show-dashboard", (f"Launch CA '{action}' must have ExeCommand='--show-dashboard'")


def test_uninstall_cas_sequenced_before_remove_files(package: ET.Element) -> None:
    """Every uninstall CA must have a direct Before anchor that leads to RemoveFiles.

    Only one hop of indirection is allowed: Before='RemoveFiles' directly,
    or Before another uninstall CA that itself has Before='RemoveFiles'.
    This keeps the ordering fully explicit and solver-independent.
    """
    customs = _get_custom_entries(package)
    uninstall_cas = [c for c in customs if _is_uninstall_condition(c.get("Condition", ""))]

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


# Package attribute tests ==============================================================================================


def test_package_version_is_preprocessor_variable(package: ET.Element) -> None:
    version = package.get("Version")
    assert version == "$(ProductVersion)", (f"Package Version should be '$(ProductVersion)', got '{version}'")


def test_major_upgrade_exists(package: ET.Element) -> None:
    mu = package.find("wix:MajorUpgrade", NS)
    assert mu is not None, "MajorUpgrade element is required for upgrade support"


def test_major_upgrade_allows_same_version(package: ET.Element) -> None:
    """Reinstalling the same version must not create duplicate uninstall entries."""
    mu = package.find("wix:MajorUpgrade", NS)
    assert mu is not None
    assert mu.get("AllowSameVersionUpgrades") == "yes", (
        "MajorUpgrade must have AllowSameVersionUpgrades='yes' to handle "
        "reinstalls of the same version without creating duplicate entries"
    )


def test_arp_product_icon_defined(package: ET.Element) -> None:
    """ARPPRODUCTICON must reference a declared <Icon> Id.

    Without this property, Windows's Add/Remove Programs UI falls back
    to a generic gray installer-box icon for the Hole entry (#359).
    """
    icon_ids = {icon.get("Id") for icon in package.iter(f"{{{NS['wix']}}}Icon")}
    arp_property = None
    for prop in package.iter(f"{{{NS['wix']}}}Property"):
        if prop.get("Id") == "ARPPRODUCTICON":
            arp_property = prop
            break
    assert arp_property is not None, (
        "Missing <Property Id='ARPPRODUCTICON'>. Without it, the Add/Remove "
        "Programs entry shows a generic installer icon (#359)."
    )
    value = arp_property.get("Value", "")
    assert value in icon_ids, (
        f"ARPPRODUCTICON value '{value}' does not match any declared <Icon Id=...>. "
        f"Declared Icon Ids: {sorted(icon_ids)}"
    )


def test_media_template_embeds_cab(package: ET.Element) -> None:
    """<Package> must declare <MediaTemplate EmbedCab='yes'>.

    Without it, WiX v4+ defaults to external cabinets, which makes the
    .msi unusable when downloaded alone (#357 — v0.1.0).
    """
    template = package.find("wix:MediaTemplate", NS)
    assert template is not None, (
        "<Package> must declare <MediaTemplate EmbedCab='yes'>. Without it "
        "WiX defaults to external cabs and the MSI fails to install when "
        "downloaded alone."
    )
    assert template.get("EmbedCab") == "yes", (
        f"<MediaTemplate> must set EmbedCab='yes', got "
        f"EmbedCab='{template.get('EmbedCab')}'."
    )


# Launch-condition tests ===============================================================================================
#
# Hole's #397 DNS refactor uses `SetInterfaceDnsSettings`, which is
# missing on Windows builds older than 19041 (version 2004, May 2020).
# The MSI must refuse to install on older builds rather than letting
# the bridge crash at first proxy-start.


def test_win10build_property_uses_registry_search(package: ET.Element) -> None:
    """The WIN10BUILD property must read HKLM CurrentBuildNumber.

    The Windows-version gate (Launch condition) reads from the
    `CurrentBuildNumber` registry value, which is a `REG_SZ` whose
    numeric content WiX's expression evaluator can compare as an
    integer. The bridge requires build >= 19041 (#397).
    """
    win10build = None
    for prop in package.iter(f"{{{NS['wix']}}}Property"):
        if prop.get("Id") == "WIN10BUILD":
            win10build = prop
            break
    assert win10build is not None, "Missing <Property Id='WIN10BUILD'> — #397 launch condition cannot evaluate"

    search = win10build.find("wix:RegistrySearch", NS)
    assert search is not None, "<Property Id='WIN10BUILD'> must contain a <RegistrySearch> child"
    assert search.get("Root") == "HKLM", f"RegistrySearch Root must be HKLM, got {search.get('Root')}"
    assert search.get("Key") == r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", (
        f"RegistrySearch Key must point at CurrentVersion, got {search.get('Key')}"
    )
    assert search.get("Name") == "CurrentBuildNumber", (
        f"RegistrySearch Name must be CurrentBuildNumber, got {search.get('Name')}"
    )
    assert search.get("Type") == "raw", (
        f"RegistrySearch Type must be 'raw' so the REG_SZ flows back numerically, got {search.get('Type')}"
    )


def test_launch_condition_requires_build_19041(package: ET.Element) -> None:
    """A <Launch> condition must gate install on WIN10BUILD >= 19041.

    Must be an integer comparison (no quotes around 19041) so MSI's
    expression evaluator coerces the REG_SZ to int. The 'Installed OR'
    prefix is required so uninstall + repair don't re-evaluate the gate
    on older builds where an old install already exists.
    """
    launches = list(package.iter(f"{{{NS['wix']}}}Launch"))
    assert launches, "No <Launch> condition in hole.wxs — #397 Windows-version gate missing"

    matches = [el for el in launches if "WIN10BUILD" in (el.get("Condition") or "")]
    assert len(matches) == 1, (
        f"Expected exactly one <Launch> condition referencing WIN10BUILD, got {len(matches)}. "
        f"Conditions: {[el.get('Condition') for el in launches]}"
    )

    launch = matches[0]
    assert launch.get("Condition") == "Installed OR WIN10BUILD >= 19041", (
        f"Launch condition must be exactly 'Installed OR WIN10BUILD >= 19041' "
        f"(integer-shaped RHS — no quotes around 19041). Got: '{launch.get('Condition')}'"
    )
    message = launch.get("Message") or ""
    assert "2004" in message or "19041" in message, (
        f"Launch condition message must name the required Windows version "
        f"so end users can act on the refusal. Got: '{message}'"
    )


# Custom action attribute tests ========================================================================================


def test_deferred_cas_not_impersonated(package: ET.Element) -> None:
    for ca in package.iter(f"{{{NS['wix']}}}CustomAction"):
        if ca.get("Execute") == "deferred":
            assert ca.get("Impersonate") == "no", (
                f"Deferred CA '{ca.get('Id')}' must have Impersonate='no' "
                "to run with elevated privileges"
            )


def _ca_map(package: ET.Element) -> dict[str, ET.Element]:
    """Map CustomAction Id -> element."""
    return {ca.get("Id", ""): ca for ca in package.iter(f"{{{NS['wix']}}}CustomAction")}


def test_install_cas_return_check(package: ET.Element) -> None:
    cas = _ca_map(package)
    for custom in _get_custom_entries(package):
        if _is_install_condition(custom.get("Condition", "")):
            action = custom.get("Action", "")
            if action in _LAUNCH_CAS:
                continue
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


# Shortcut component tests =============================================================================================


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


# Component key path tests =============================================================================================


def test_every_component_has_key_path(package: ET.Element) -> None:
    for comp in package.iter(f"{{{NS['wix']}}}Component"):
        comp_id = comp.get("Id", "<anonymous>")
        key_path_children = [child for child in comp if child.get("KeyPath") == "yes"]
        assert len(key_path_children) == 1, (
            f"Component '{comp_id}' must have exactly one child with KeyPath='yes', "
            f"found {len(key_path_children)}"
        )


# UI property tests ====================================================================================================


def _find_property(package: ET.Element, prop_id: str) -> ET.Element | None:
    for prop in package.iter(f"{{{NS['wix']}}}Property"):
        if prop.get("Id") == prop_id:
            return prop
    return None


def _find_component(package: ET.Element, comp_id: str) -> ET.Element | None:
    for comp in package.iter(f"{{{NS['wix']}}}Component"):
        if comp.get("Id") == comp_id:
            return comp
    return None


def test_install_start_menu_default_is_on(package: ET.Element) -> None:
    """Silent auto-update path: defaulting to 1 preserves existing users' Start Menu shortcut."""
    prop = _find_property(package, "INSTALL_START_MENU")
    assert prop is not None, "Property INSTALL_START_MENU is required"
    assert prop.get("Value") == "1", (
        f"INSTALL_START_MENU must default to '1' for upgrade safety (auto-updater runs silent); "
        f"got '{prop.get('Value')}'"
    )
    assert prop.get("Secure") == "yes", (
        "Public properties driving Component conditions must be Secure='yes' to "
        "propagate from UI sequence to deferred execute sequence"
    )


def test_install_desktop_icon_default_is_off(package: ET.Element) -> None:
    """Silent auto-update path: defaulting to 0 prevents surprise desktop icons on upgrade."""
    prop = _find_property(package, "INSTALL_DESKTOP_ICON")
    assert prop is not None, "Property INSTALL_DESKTOP_ICON is required"
    assert prop.get("Value") == "0", (
        f"INSTALL_DESKTOP_ICON must default to '0' for upgrade safety; "
        f"got '{prop.get('Value')}'"
    )
    assert prop.get("Secure") == "yes", (
        "Public properties driving Component conditions must be Secure='yes' to "
        "propagate from UI sequence to deferred execute sequence"
    )


def test_start_menu_shortcut_is_conditioned_on_property(package: ET.Element) -> None:
    comp = _find_component(package, "StartMenuShortcut")
    assert comp is not None
    condition = comp.get("Condition", "")
    assert 'INSTALL_START_MENU="1"' in condition, (
        f"StartMenuShortcut must be conditioned on INSTALL_START_MENU; got Condition='{condition}'"
    )


def test_desktop_shortcut_is_conditioned_on_property(package: ET.Element) -> None:
    comp = _find_component(package, "DesktopShortcut")
    assert comp is not None
    condition = comp.get("Condition", "")
    assert 'INSTALL_DESKTOP_ICON="1"' in condition, (
        f"DesktopShortcut must be conditioned on INSTALL_DESKTOP_ICON; got Condition='{condition}'"
    )


def test_shortcut_components_have_distinct_registry_names(package: ET.Element) -> None:
    """Each shortcut component must own its own HKCU KeyPath.

    Two components sharing Software\\Hole\\Installed would race during uninstall —
    whichever runs last would no-op when the regkey is already gone, leaving its
    shortcut orphaned.
    """
    names: dict[str, str] = {}  # registry name -> component id
    for comp_id in ("StartMenuShortcut", "DesktopShortcut"):
        comp = _find_component(package, comp_id)
        assert comp is not None, f"Component '{comp_id}' missing"
        reg = next(
            (r for r in comp.iter(f"{{{NS['wix']}}}RegistryValue") if r.get("KeyPath") == "yes"),
            None,
        )
        assert reg is not None, f"Component '{comp_id}' has no KeyPath RegistryValue"
        name = reg.get("Name", "")
        assert name not in names, (
            f"Components '{comp_id}' and '{names[name]}' share HKCU registry Name='{name}' "
            "as KeyPath. Each component must own a distinct registry value."
        )
        names[name] = comp_id


def test_ui_extension_referenced(package: ET.Element) -> None:
    """WixUI_InstallDir dialog set must be activated via <ui:WixUI>."""
    wixui = package.find(f"{{{UI_NS}}}WixUI")
    assert wixui is not None, "<ui:WixUI> element is required to activate the dialog set"
    assert wixui.get("Id") == "WixUI_InstallDir", (f"Expected WixUI Id='WixUI_InstallDir'; got '{wixui.get('Id')}'")
    assert wixui.get("InstallDirectory") == "INSTALLFOLDER", (
        f"InstallDirectory must bind picker to INSTALLFOLDER; got '{wixui.get('InstallDirectory')}'"
    )


def test_wixui_license_rtf_bindpath(package: ET.Element) -> None:
    """The License dialog reads license.rtf from the LicenseDir bindpath."""
    for var in package.iter(f"{{{NS['wix']}}}WixVariable"):
        if var.get("Id") == "WixUILicenseRtf":
            value = var.get("Value", "")
            assert "!(bindpath.LicenseDir)" in value, (
                f"WixUILicenseRtf must reference !(bindpath.LicenseDir); got '{value}'"
            )
            assert value.endswith("license.rtf"), (f"WixUILicenseRtf must point to license.rtf; got '{value}'")
            return
    raise AssertionError("WixVariable Id='WixUILicenseRtf' is required for the License dialog")


def test_main_feature_wraps_all_component_groups(package: ET.Element) -> None:
    """A single hidden Feature must group all components for the dialog set."""
    feature = next(
        (f for f in package.iter(f"{{{NS['wix']}}}Feature") if f.get("Id") == "Main"),
        None,
    )
    assert feature is not None, "<Feature Id='Main'> is required"
    refs = {ref.get("Id") for ref in feature.iter(f"{{{NS['wix']}}}ComponentGroupRef")}
    expected = {"BinaryComponents", "ShortcutComponents", "DesktopShortcutComponents"}
    assert refs == expected, (f"Feature 'Main' must reference exactly {expected}; got {refs}")


# Attribution file tests ===============================================================================================


def test_notices_md_component_exists(package: ET.Element) -> None:
    """NOTICES.md must ship alongside binaries (Apache-2.0 §4(d) attribution).

    The License dialog displays only GPL-3.0 text; the NOTICE file preserving
    Apache-2.0 attribution for galoshes/garter must be installed on disk.
    """
    comp = _find_component(package, "NoticesMd")
    assert comp is not None, "Component 'NoticesMd' is required for Apache-2.0 attribution"
    file_elem = next(
        (f for f in comp.iter(f"{{{NS['wix']}}}File") if f.get("Id") == "NOTICES.md"),
        None,
    )
    assert file_elem is not None, "NoticesMd component must contain <File Id='NOTICES.md'>"
    source = file_elem.get("Source", "")
    assert "!(bindpath.BinDir)" in source, (f"NOTICES.md File Source must resolve via BinDir bindpath; got '{source}'")


# Sticky-preference tests ==============================================================================================


def _find_registry_search_property(package: ET.Element, prop_id: str) -> ET.Element | None:
    """Return the <Property> if it contains a <RegistrySearch> child, else None."""
    for prop in package.iter(f"{{{NS['wix']}}}Property"):
        if prop.get("Id") != prop_id:
            continue
        if next(prop.iter(f"{{{NS['wix']}}}RegistrySearch"), None) is not None:
            return prop
    return None


def test_start_menu_registry_search_exists(package: ET.Element) -> None:
    """RegistrySearch reads the prior install's HKCU regkey to keep choices sticky."""
    prop = _find_registry_search_property(package, "HOLE_START_MENU_INSTALLED")
    assert prop is not None, "Property 'HOLE_START_MENU_INSTALLED' with <RegistrySearch> is required"
    search = next(prop.iter(f"{{{NS['wix']}}}RegistrySearch"))
    assert search.get("Root") == "HKCU", "Sticky-preference search must be HKCU (matches shortcut KeyPath)"
    assert search.get("Key") == "Software\\Hole"
    assert search.get("Name"
                      ) == "Installed", ("Must search for the same regkey Name written by StartMenuShortcut's KeyPath")


def test_desktop_registry_search_exists(package: ET.Element) -> None:
    prop = _find_registry_search_property(package, "HOLE_DESKTOP_INSTALLED")
    assert prop is not None, "Property 'HOLE_DESKTOP_INSTALLED' with <RegistrySearch> is required"
    search = next(prop.iter(f"{{{NS['wix']}}}RegistrySearch"))
    assert search.get("Root") == "HKCU"
    assert search.get("Key") == "Software\\Hole"
    assert search.get("Name") == "DesktopShortcutInstalled", (
        "Must search for the same regkey Name written by DesktopShortcut's KeyPath"
    )


def _find_set_property(package: ET.Element, prop_id: str) -> ET.Element | None:
    for sp in package.iter(f"{{{NS['wix']}}}SetProperty"):
        if sp.get("Id") == prop_id:
            return sp
    return None


def test_sticky_start_menu_setproperty(package: ET.Element) -> None:
    """On upgrade, if prior install LACKED Start Menu regkey, override default 1 to 0.

    Without this, an interactive install where the user unchecked Start Menu
    would silently re-enable it on the next auto-update (defaults apply).
    """
    sp = _find_set_property(package, "INSTALL_START_MENU")
    assert sp is not None, ("<SetProperty Id='INSTALL_START_MENU'> is required to make the choice sticky on upgrade")
    assert sp.get("Value"
                  ) == "0", (f"Sticky override must set value to '0' (preserve un-checked); got '{sp.get('Value')}'")
    assert sp.get("After") == "AppSearch", (
        f"SetProperty must run After='AppSearch' so RegistrySearch results are populated; "
        f"got After='{sp.get('After')}'"
    )
    condition = sp.get("Condition", "")
    assert "WIX_UPGRADE_DETECTED" in condition, (
        f"Condition must gate on WIX_UPGRADE_DETECTED so fresh installs keep defaults; "
        f"got Condition='{condition}'"
    )
    assert "NOT HOLE_START_MENU_INSTALLED" in condition, (
        f"Condition must fire only when prior install lacked the regkey; got '{condition}'"
    )


def test_sticky_desktop_setproperty(package: ET.Element) -> None:
    """On upgrade, if prior install HAD Desktop regkey, override default 0 to 1.

    Without this, an interactive install where the user checked Desktop would
    silently lose its icon on the next auto-update (defaults apply, 0=off).
    """
    sp = _find_set_property(package, "INSTALL_DESKTOP_ICON")
    assert sp is not None, ("<SetProperty Id='INSTALL_DESKTOP_ICON'> is required to make the choice sticky on upgrade")
    assert sp.get("Value"
                  ) == "1", (f"Sticky override must set value to '1' (preserve checked); got '{sp.get('Value')}'")
    assert sp.get("After") == "AppSearch"
    condition = sp.get("Condition", "")
    assert "WIX_UPGRADE_DETECTED" in condition
    assert "HOLE_DESKTOP_INSTALLED" in condition and "NOT HOLE_DESKTOP_INSTALLED" not in condition, (
        f"Condition must fire only when prior install HAD the regkey (positive check); "
        f"got '{condition}'"
    )


# ShortcutsDlg structural tests ========================================================================================


def _find_dialog(package: ET.Element, dialog_id: str) -> ET.Element | None:
    for ui in package.iter(f"{{{NS['wix']}}}UI"):
        for dlg in ui.iter(f"{{{NS['wix']}}}Dialog"):
            if dlg.get("Id") == dialog_id:
                return dlg
    return None


def test_shortcutsdlg_has_three_pushbuttons(package: ET.Element) -> None:
    dlg = _find_dialog(package, "ShortcutsDlg")
    assert dlg is not None, "<Dialog Id='ShortcutsDlg'> is required"
    buttons = [c for c in dlg.iter(f"{{{NS['wix']}}}Control") if c.get("Type") == "PushButton"]
    button_ids = sorted(b.get("Id", "") for b in buttons)
    assert button_ids == [
        "Back", "Cancel", "Next"
    ], (f"ShortcutsDlg must have exactly three PushButtons (Back, Cancel, Next); got {button_ids}")


def test_shortcutsdlg_cancel_spawns_canceldlg(package: ET.Element) -> None:
    dlg = _find_dialog(package, "ShortcutsDlg")
    assert dlg is not None
    cancel = next(
        (c for c in dlg.iter(f"{{{NS['wix']}}}Control") if c.get("Id") == "Cancel"),
        None,
    )
    assert cancel is not None, "ShortcutsDlg must have a Control Id='Cancel'"
    publishes = list(cancel.iter(f"{{{NS['wix']}}}Publish"))
    spawn = [p for p in publishes if p.get("Event") == "SpawnDialog" and p.get("Value") == "CancelDlg"]
    assert len(spawn) == 1, (
        "ShortcutsDlg Cancel button must have child <Publish Event='SpawnDialog' Value='CancelDlg'> "
        f"(matches upstream WixUI dialogs); got {len(spawn)} matching Publish elements"
    )


def test_shortcutsdlg_has_two_checkboxes(package: ET.Element) -> None:
    dlg = _find_dialog(package, "ShortcutsDlg")
    assert dlg is not None
    checkboxes = {
        c.get("Property"): c.get("CheckBoxValue")
        for c in dlg.iter(f"{{{NS['wix']}}}Control") if c.get("Type") == "CheckBox"
    }
    assert checkboxes == {"INSTALL_START_MENU": "1", "INSTALL_DESKTOP_ICON": "1"}, (
        "ShortcutsDlg must have two CheckBox controls bound to INSTALL_START_MENU "
        f"and INSTALL_DESKTOP_ICON with CheckBoxValue='1'; got {checkboxes}"
    )


# UI Publish navigation tests ==========================================================================================


def _ui_publishes(package: ET.Element) -> list[ET.Element]:
    """Publishes at top-level of <UI> (not nested under Controls)."""
    result: list[ET.Element] = []
    for ui in package.iter(f"{{{NS['wix']}}}UI"):
        for child in ui:
            if child.tag == f"{{{NS['wix']}}}Publish":
                result.append(child)
    return result


def _find_publish(publishes: list[ET.Element], dialog: str, control: str, event: str, value: str) -> ET.Element | None:
    for p in publishes:
        if (
            p.get("Dialog") == dialog and p.get("Control") == control and p.get("Event") == event
            and p.get("Value") == value
        ):
            return p
    return None


def test_installdirdlg_next_publishes_to_shortcutsdlg(package: ET.Element) -> None:
    """Override of upstream WixUI_InstallDir's Order=4 NewDialog→VerifyReadyDlg.

    Our Order must be strictly greater than 4 (upstream's value, verified from
    WiX v6.0.2 source) so MSI processes our row after, making our NewDialog win.
    """
    pub = _find_publish(_ui_publishes(package), "InstallDirDlg", "Next", "NewDialog", "ShortcutsDlg")
    assert pub is not None, (
        "Missing <Publish Dialog='InstallDirDlg' Control='Next' Event='NewDialog' "
        "Value='ShortcutsDlg'> — required to inject ShortcutsDlg into the wizard"
    )
    order = int(pub.get("Order", "0"))
    assert order > 4, (
        f"InstallDirDlg.Next→ShortcutsDlg must use Order > 4 to beat upstream's "
        f"Order=4 NewDialog→VerifyReadyDlg; got Order={order}"
    )


def test_shortcutsdlg_back_publishes_to_installdirdlg(package: ET.Element) -> None:
    pub = _find_publish(_ui_publishes(package), "ShortcutsDlg", "Back", "NewDialog", "InstallDirDlg")
    assert pub is not None, "ShortcutsDlg Back must publish NewDialog→InstallDirDlg"


def test_shortcutsdlg_next_publishes_to_verifyreadydlg(package: ET.Element) -> None:
    pub = _find_publish(_ui_publishes(package), "ShortcutsDlg", "Next", "NewDialog", "VerifyReadyDlg")
    assert pub is not None, "ShortcutsDlg Next must publish NewDialog→VerifyReadyDlg"


def test_verifyreadydlg_back_publishes_to_shortcutsdlg(package: ET.Element) -> None:
    """Override of upstream WixUI_InstallDir's Order=1 NewDialog→InstallDirDlg (Condition='NOT Installed').

    Our Order must be strictly greater than 1 to win. The condition must match
    upstream so we only override the install path, not maintenance/patch flows.
    """
    pub = _find_publish(_ui_publishes(package), "VerifyReadyDlg", "Back", "NewDialog", "ShortcutsDlg")
    assert pub is not None, (
        "Missing <Publish Dialog='VerifyReadyDlg' Control='Back' Event='NewDialog' "
        "Value='ShortcutsDlg'> — needed for Back-button regression"
    )
    order = int(pub.get("Order", "0"))
    assert order > 1, (
        f"VerifyReadyDlg.Back→ShortcutsDlg must use Order > 1 to beat upstream's "
        f"Order=1 NewDialog→InstallDirDlg; got Order={order}"
    )
    condition = pub.get("Condition", "")
    assert "NOT Installed" in condition, (
        f"VerifyReadyDlg.Back→ShortcutsDlg must condition on 'NOT Installed' to avoid "
        f"intercepting maintenance/patch flows; got Condition='{condition}'"
    )
