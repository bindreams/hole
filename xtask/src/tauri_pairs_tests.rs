use super::plugin_version_drift;

const NPM_LOCK: &str = r#"{
  "packages": {
    "": { "name": "hole" },
    "node_modules/@tauri-apps/api": { "version": "2.11.0" },
    "node_modules/@tauri-apps/plugin-log": { "version": "2.9.0" },
    "node_modules/@tauri-apps/plugin-shell": { "version": "2.3.0" }
  }
}"#;

const CARGO_LOCK: &str = r#"
[[package]]
name = "tauri-plugin-log"
version = "2.9.0"

[[package]]
name = "tauri-plugin-shell"
version = "2.3.1"

[[package]]
name = "tauri-plugin-single-instance"
version = "2.4.2"
"#;

#[skuld::test]
fn aligned_pairs_report_no_drift() {
    assert!(plugin_version_drift(NPM_LOCK, CARGO_LOCK).unwrap().is_empty());
}

/// Patch versions move independently on each side; only major.minor is compared.
#[skuld::test]
fn patch_level_difference_is_not_drift() {
    let drift = plugin_version_drift(NPM_LOCK, CARGO_LOCK).unwrap();
    assert!(!drift.iter().any(|(p, ..)| p == "plugin-shell"), "got: {drift:?}");
}

#[skuld::test]
fn a_minor_bump_on_one_side_is_drift() {
    let npm = NPM_LOCK.replace("\"version\": \"2.9.0\"", "\"version\": \"2.8.0\"");

    let drift = plugin_version_drift(&npm, CARGO_LOCK).unwrap();

    assert_eq!(
        drift,
        vec![("plugin-log".to_string(), "2.8.0".to_string(), "2.9.0".to_string())]
    );
}

/// A crate with no npm counterpart (or vice versa) is not a pair.
#[skuld::test]
fn unpaired_packages_are_ignored() {
    let drift = plugin_version_drift(NPM_LOCK, CARGO_LOCK).unwrap();
    assert!(
        !drift.iter().any(|(p, ..)| p == "plugin-single-instance"),
        "got: {drift:?}"
    );
}

/// The guard: this repo's own lockfiles must agree, or `npx tauri build` fails
/// at bundle time (#679).
#[skuld::test]
fn this_repo_has_no_tauri_plugin_drift() {
    let root = xtask_lib::repo_root::repo_root().unwrap();
    let npm = std::fs::read_to_string(root.join("package-lock.json")).unwrap();
    let cargo = std::fs::read_to_string(root.join("Cargo.lock")).unwrap();

    let drift = plugin_version_drift(&npm, &cargo).unwrap();

    assert!(
        drift.is_empty(),
        "npm/crate Tauri pairs disagree on major.minor; `npx tauri build` will refuse to bundle: {drift:?}"
    );
}
