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
