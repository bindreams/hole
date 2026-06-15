//! Conformance: the Tauri bundle config must ship every canonical macOS BINDIR
//! file (the macOS DMG analog of the WiX `<File>` conformance in
//! `msi-installer/tests/test_hole_wxs.py`).
//!
//! Tauri ships files into the `.app` through three config mechanisms, none of
//! which Tauri cross-checks against the BINDIR source of truth:
//! `bundle.externalBin` (sidecars → `Contents/MacOS/`), `bundle.resources`
//! (→ `Contents/Resources/`), and `bundle.macOS.files` (→ `Contents/<dest>`).
//! A file dropped from all three is silently missing from the DMG — exactly how
//! galoshes (#512) and `hole.dSYM` (#512 defer-1) went missing.

use std::collections::BTreeSet;

use crate::bindir::{bindir_dest_names, plugin_sidecar_names};
use crate::manifest::Os;

/// Parse `crates/hole/tauri.conf.json`.
fn tauri_conf() -> serde_json::Value {
    let root = crate::repo_root().expect("repo root");
    let text = std::fs::read_to_string(root.join("crates/hole/tauri.conf.json")).expect("read tauri.conf.json");
    serde_json::from_str(&text).expect("parse tauri.conf.json")
}

/// Last path segment of a Tauri config path (they use `/`). `rsplit` always
/// yields at least one element, so the `unwrap` is infallible.
fn basename(s: &str) -> String {
    s.rsplit('/').next().unwrap().to_string()
}

/// Basenames of `bundle.externalBin` (sidecars → `Contents/MacOS/`). Each entry
/// is a `<dir>/<name>` source stem; the shipped file is `<name>`.
fn external_bin_basenames(conf: &serde_json::Value) -> Vec<String> {
    conf["bundle"]["externalBin"]
        .as_array()
        .expect("bundle.externalBin array")
        .iter()
        .map(|e| basename(e.as_str().expect("externalBin entry is a string")))
        .collect()
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
fn external_bin_covers_every_plugin_sidecar() {
    // Tauri's bundler ships only `externalBin` sidecars into Contents/MacOS/, so
    // every plugin binary must be listed there or the macOS DMG can't run it
    // (this is how galoshes was missing from the DMG — #512).
    let external = external_bin_basenames(&tauri_conf());
    for sidecar in plugin_sidecar_names() {
        assert!(
            external.contains(&sidecar.to_string()),
            "tauri.conf.json externalBin is missing plugin sidecar {sidecar:?} — the macOS DMG \
             would not ship it (#512). Have: {external:?}"
        );
    }
}

#[skuld::test]
fn tauri_bundle_covers_full_darwin_bindir() {
    // Every canonical macOS BINDIR file must ship through some Tauri mechanism or
    // the DMG silently drops it (#512). The first entry is the app's own binary,
    // which Tauri bundles implicitly as Contents/MacOS/<bin>; every other entry
    // must appear in externalBin, resources, or macOS.files.
    let conf = tauri_conf();
    let names = bindir_dest_names(Os::Darwin);
    let (main_binary, payload) = names.split_first().expect("bindir_dest_names is non-empty");
    assert_eq!(
        main_binary.as_str(),
        "hole",
        "expected the app binary first in bindir_dest_names(Darwin); got {main_binary:?}"
    );

    let mut shipped: BTreeSet<String> = BTreeSet::new();
    shipped.extend(external_bin_basenames(&conf));
    shipped.extend(resources_dest_basenames(&conf));
    shipped.extend(macos_files_dest_basenames(&conf));

    let missing: Vec<&String> = payload.iter().filter(|n| !shipped.contains(*n)).collect();
    assert!(
        missing.is_empty(),
        "tauri.conf.json bundle has no DMG home for canonical macOS BINDIR file(s) {missing:?} — \
         add each to externalBin (sidecars), resources, or macOS.files (e.g. hole.dSYM as a \
         sibling of the binary at MacOS/hole.dSYM). Shipped basenames: {shipped:?}"
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
    let conf = tauri_conf();
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
