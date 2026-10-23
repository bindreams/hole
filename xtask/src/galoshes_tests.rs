use crate::galoshes::cache_sidecar_name;
use crate::target::host_target_triple;

#[skuld::test]
fn cache_sidecar_name_matches_host_triple() {
    // Must match exactly what Tauri appends to the externalBin path, or the
    // macOS DMG bundles nothing. Assert the full name, not just a prefix.
    let exe = if cfg!(target_os = "windows") { ".exe" } else { "" };
    let expected = format!("galoshes-{}{exe}", host_target_triple());
    assert_eq!(cache_sidecar_name(), expected);
}

use crate::galoshes::build_args;

#[skuld::test]
fn crash_dumps_opt_in_adds_the_feature_only_for_windows() {
    // `.dmp` is a Windows-only branch: `minidump-writer` is declared under
    // `[target.'cfg(windows)'.dependencies]`, and since #842 the macOS
    // `on_crash` has no dump branch at all (crates/tombstone/src/crash.rs
    // module doc).
    assert_eq!(
        build_args(true, true),
        vec![
            "build",
            "--release",
            "-p",
            "galoshes",
            "--features",
            "galoshes/crash-dumps"
        ]
    );
}

#[skuld::test]
fn crash_dumps_opt_in_is_a_no_op_off_windows() {
    // Not merely "changes no behaviour" — it must produce the IDENTICAL
    // command line. A different feature set is a different cargo
    // fingerprint, so `cargo xtask run hole` on darwin paid a full release
    // rebuild of galoshes + tombstone for a feature that links nothing.
    assert_eq!(build_args(true, false), build_args(false, false));
    assert_eq!(build_args(true, false), vec!["build", "--release", "-p", "galoshes"]);
}
