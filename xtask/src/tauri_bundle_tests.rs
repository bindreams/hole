//! Conformance: the Tauri bundle must ship every plugin sidecar.

use crate::bindir::plugin_sidecar_names;

/// Basenames of `crates/hole/tauri.conf.json`'s `bundle.externalBin` entries.
fn external_bin_basenames() -> Vec<String> {
    let root = crate::repo_root().expect("repo root");
    let text = std::fs::read_to_string(root.join("crates/hole/tauri.conf.json")).expect("read tauri.conf.json");
    let conf: serde_json::Value = serde_json::from_str(&text).expect("parse tauri.conf.json");
    conf["bundle"]["externalBin"]
        .as_array()
        .expect("bundle.externalBin array")
        .iter()
        .map(|e| {
            e.as_str()
                .expect("externalBin entry is a string")
                .rsplit('/')
                .next()
                .unwrap()
                .to_string()
        })
        .collect()
}

#[skuld::test]
fn external_bin_covers_every_plugin_sidecar() {
    // Tauri's bundler ships only `externalBin` sidecars into Contents/MacOS/,
    // so every plugin binary must be listed there or the macOS DMG can't run
    // it (this is how galoshes was missing from the DMG — #512).
    let external = external_bin_basenames();
    for sidecar in plugin_sidecar_names() {
        assert!(
            external.contains(&sidecar.to_string()),
            "tauri.conf.json externalBin is missing plugin sidecar {sidecar:?} — the macOS DMG \
             would not ship it (#512). Have: {external:?}"
        );
    }
}
