//! Conformance: the Tauri bundle config must ship every canonical macOS BINDIR
//! file (the macOS DMG analog of the WiX `<File>` conformance in
//! `msi-installer/tests/test_hole_wxs.py`).
//!
//! Tauri ships files into the `.app` through three config mechanisms, none of
//! which Tauri cross-checks against the BINDIR source of truth:
//! `bundle.externalBin` (sidecars → `Contents/MacOS/`), `bundle.resources`
//! (→ `Contents/Resources/`), and `bundle.macOS.files` (→ `Contents/<dest>`).
//! A file dropped from all three is silently missing from the DMG.

use std::collections::BTreeSet;

use crate::bindir::{bindir_dest_names, bundle_payload_names, plugin_sidecar_names};
use crate::manifest::Os;

/// The config `tauri-build` reads for `os`: `crates/hole/tauri.conf.json` with the platform file merged over it.
fn tauri_conf(os: Os) -> serde_json::Value {
    let triple = match os {
        Os::Darwin => "aarch64-apple-darwin",
        Os::Windows => "x86_64-pc-windows-msvc",
        Os::Linux => "x86_64-unknown-linux-gnu",
    };
    let root = crate::repo_root().expect("repo root");
    xtask_lib::tauri_config::merged_tauri_config(triple, &root.join("crates/hole"))
        .expect("read the merged Tauri config")
        .0
}

/// Last path segment of a Tauri config path (they use `/`). `rsplit` always
/// yields at least one element, so the `unwrap` is infallible.
fn basename(s: &str) -> String {
    s.rsplit('/').next().unwrap().to_string()
}

/// Basenames of `bundle.externalBin` (sidecars → `Contents/MacOS/`). Each entry
/// is a `<dir>/<name>` source stem; the shipped file is `<name>`.
fn external_bin_basenames(conf: &serde_json::Value) -> Vec<String> {
    match conf["bundle"].get("externalBin") {
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(entries) => entries
            .as_array()
            .expect("bundle.externalBin array")
            .iter()
            .map(|e| basename(e.as_str().expect("externalBin entry is a string")))
            .collect(),
    }
}

/// Dest basenames of `bundle.resources` (→ `Contents/Resources/`). The map form
/// is `{ source: dest }`, so the shipped name is the *value*; the list form
/// ships each entry at its own basename. Absent → empty.
fn resources_dest_basenames(conf: &serde_json::Value) -> Vec<String> {
    match &conf["bundle"]["resources"] {
        serde_json::Value::Object(map) => map
            .values()
            .map(|v| basename(v.as_str().expect("resource dest is a string")))
            .collect(),
        serde_json::Value::Array(list) => list
            .iter()
            .map(|e| basename(e.as_str().expect("resource entry is a string")))
            .collect(),
        serde_json::Value::Null => Vec::new(),
        other => panic!("bundle.resources must be a map, list, or absent; got {other}"),
    }
}

/// Dest basenames of `bundle.macOS.files` (→ `Contents/<dest>`). The map form is
/// `{ dest: source }` — the opposite direction from `resources` — so the
/// shipped name is the basename of the *key*. Absent → empty.
fn macos_files_dest_basenames(conf: &serde_json::Value) -> Vec<String> {
    match conf["bundle"]["macOS"].get("files") {
        Some(serde_json::Value::Object(map)) => map.keys().map(|k| basename(k)).collect(),
        None | Some(serde_json::Value::Null) => Vec::new(),
        Some(other) => panic!("bundle.macOS.files must be a map or absent; got {other}"),
    }
}

#[skuld::test]
fn macos_merged_config_has_no_external_bin() {
    // macOS embeds both plugins in `hole`: the app bundle must not also ship them as sidecars (the service would
    // not run them from there).
    let external = external_bin_basenames(&tauri_conf(Os::Darwin));

    assert!(
        external.is_empty(),
        "the macOS bundle still ships sidecars: {external:?}"
    );
}

#[skuld::test]
fn windows_and_linux_merged_configs_keep_the_plugin_sidecars() {
    // Tauri's bundler ships only `externalBin` sidecars next to the binary, so on the platforms that run the
    // plugins from files every plugin binary must be listed there.
    for os in [Os::Windows, Os::Linux] {
        let external = external_bin_basenames(&tauri_conf(os));
        for sidecar in plugin_sidecar_names() {
            assert!(
                external.contains(&sidecar.to_string()),
                "tauri.conf.json externalBin is missing plugin sidecar {sidecar:?} on {os}. Have: {external:?}"
            );
        }
    }
}

#[skuld::test]
fn bundle_covers_the_bundle_payload_names_for_darwin() {
    // Every file the macOS bundle must hold ships through some Tauri mechanism or the DMG silently drops it.
    // The first entry is the app's own binary, which Tauri bundles implicitly as Contents/MacOS/<bin>; every other
    // entry must appear in externalBin, resources, or macOS.files. The plugins are not among them: `hole` embeds them.
    let conf = tauri_conf(Os::Darwin);
    let names = bundle_payload_names(Os::Darwin);
    let (main_binary, payload) = names.split_first().expect("bundle_payload_names is non-empty");
    assert_eq!(
        main_binary.as_str(),
        "hole",
        "expected the app binary first in bundle_payload_names(Darwin); got {main_binary:?}"
    );

    let mut shipped: BTreeSet<String> = BTreeSet::new();
    shipped.extend(external_bin_basenames(&conf));
    shipped.extend(resources_dest_basenames(&conf));
    shipped.extend(macos_files_dest_basenames(&conf));

    let missing: Vec<&String> = payload.iter().filter(|n| !shipped.contains(*n)).collect();
    assert!(
        missing.is_empty(),
        "the macOS bundle config has no DMG home for file(s) {missing:?} — add each to resources or macOS.files          (e.g. hole.dSYM as a sibling of the binary at MacOS/hole.dSYM). Shipped basenames: {shipped:?}"
    );
}

#[skuld::test]
fn dsym_ships_as_a_sibling_of_the_binary() {
    // The coverage test above is basename-only, so a dSYM mis-routed to
    // Contents/Resources/ would still pass it. But std's backtrace symbolizer
    // finds a dSYM ONLY by scanning the running binary's own directory and
    // UUID-matching — so the dSYM must ship at MacOS/<name> (next to
    // Contents/MacOS/hole) or production backtraces never resolve. Lock the dest
    // directory here so a misroute fails on any host, not just the darwin DMG
    // lane (which proves it on the real bundle via test_dsym_is_sibling_of_binary).
    let conf = tauri_conf(Os::Darwin);
    let dsym = bindir_dest_names(Os::Darwin)
        .into_iter()
        .find(|n| n.ends_with(".dSYM"))
        .expect("darwin bindir_dest_names includes a .dSYM");
    let files = conf["bundle"]["macOS"]["files"]
        .as_object()
        .expect("bundle.macOS.files must be a map shipping the dSYM");
    let dest = files.keys().find(|k| basename(k) == dsym).unwrap_or_else(|| {
        panic!(
            "bundle.macOS.files ships no {dsym}; have {:?}",
            files.keys().collect::<Vec<_>>()
        )
    });
    // MacOS/ is the fixed app-bundle dir Tauri places the main binary in; the
    // dSYM is its sibling there.
    assert_eq!(
        *dest,
        format!("MacOS/{dsym}"),
        "{dsym} must ship at MacOS/{dsym} (sibling of Contents/MacOS/hole) so runtime backtraces \
         resolve; got dest {dest:?}"
    );
}
