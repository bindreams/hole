"""Static config-drift guard.

A future Tauri config refactor must not silently drop the `bundle.macOS`
block. This test fails fast in CI (no DMG build needed) if `signingIdentity`
is missing or set to anything other than ad-hoc.
"""

import json

import dmg_installer

REPO_ROOT = dmg_installer._find_repo_root()


def test_tauri_conf_macos_signing_identity_is_ad_hoc() -> None:
    conf_path = REPO_ROOT / "crates" / "hole" / "tauri.conf.json"
    with open(conf_path) as f:
        conf = json.load(f)

    bundle = conf["bundle"]
    assert "macOS" in bundle, (
        f"{conf_path} has no `bundle.macOS` block — Tauri will skip codesign "
        "and produce a 'damaged' .app under Gatekeeper quarantine (issue #364)."
    )
    assert bundle["macOS"].get("signingIdentity") == "-", (
        f"{conf_path} `bundle.macOS.signingIdentity` must be `-` (ad-hoc) "
        f"until Developer ID signing lands (issue #365), got "
        f"{bundle['macOS'].get('signingIdentity')!r}"
    )


def test_tauri_targets_are_app_only() -> None:
    conf_path = REPO_ROOT / "crates" / "hole" / "tauri.conf.json"
    with open(conf_path) as f:
        conf = json.load(f)

    assert conf["bundle"]["targets"] == ["app"], (
        f"{conf_path} `bundle.targets` must be ['app'] — the DMG is assembled by "
        "dmg-installer's dmgbuild builder, and re-enabling Tauri's 'dmg' target "
        "would reintroduce the flaky Finder/bundle_dmg pipeline it replaced "
        f"(issue #609). Got {conf['bundle'].get('targets')!r}."
    )
