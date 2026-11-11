use crate::bindir::*;

#[skuld::test]
fn dest_names_per_os_are_exact() {
    // Exact-equality is intentional: adding a BINDIR file forces an update
    // here AND in every installer manifest (caught by the conformance tests).
    assert_eq!(
        bindir_dest_names(Os::Windows),
        vec![
            "hole.exe",
            "hole.pdb",
            "ex-ray.exe",
            "galoshes.exe",
            "wintun.dll",
            "NOTICES.md"
        ]
    );
    assert_eq!(
        bindir_dest_names(Os::Darwin),
        vec!["hole", "hole.dSYM", "ex-ray", "galoshes", "NOTICES.md"]
    );
    assert_eq!(
        bindir_dest_names(Os::Linux),
        vec!["hole", "ex-ray", "galoshes", "NOTICES.md"]
    );
}

#[skuld::test]
fn plugin_sidecars_are_ex_ray_and_galoshes() {
    assert_eq!(plugin_sidecar_names(), &["ex-ray", "galoshes"]);
}

#[skuld::test]
fn embedded_plugin_names_per_os() {
    // macOS carries both plugins inside `hole`; the other platforms ship them as files.
    assert_eq!(embedded_plugin_names(Os::Darwin), plugin_sidecar_names());
    assert!(embedded_plugin_names(Os::Windows).is_empty());
    assert!(embedded_plugin_names(Os::Linux).is_empty());
}

#[skuld::test]
fn bundle_payload_names_drop_only_the_embedded_names() {
    assert_eq!(
        bundle_payload_names(Os::Darwin),
        vec!["hole", "hole.dSYM", "NOTICES.md"]
    );
    for os in [Os::Windows, Os::Linux] {
        assert_eq!(bundle_payload_names(os), bindir_dest_names(os), "{os}");
    }
}

#[skuld::test]
fn bindir_dest_names_still_lists_the_plugins_for_every_os() {
    // Dev staging, the MSI conformance test and the Windows cutover want the whole set whoever embeds what.
    for os in [Os::Windows, Os::Darwin, Os::Linux] {
        let names = bindir_dest_names(os);
        for plugin in plugin_sidecar_names() {
            assert!(names.iter().any(|n| n.starts_with(plugin)), "{os}: {plugin}");
        }
    }
}

#[skuld::test]
fn cache_sidecar_path_is_what_tauri_appends_to_the_external_bin_entry() {
    use std::path::Path;
    let root = Path::new("repo");
    assert_eq!(
        cache_sidecar_path(root, "ex-ray", "aarch64-apple-darwin", false),
        root.join(".cache").join("ex-ray").join("ex-ray-aarch64-apple-darwin")
    );
    assert_eq!(
        cache_sidecar_path(root, "galoshes", "x86_64-pc-windows-msvc", true),
        root.join(".cache")
            .join("galoshes")
            .join("galoshes-x86_64-pc-windows-msvc.exe")
    );
    assert_eq!(
        cache_sidecar_file_name("ex-ray", "x86_64-apple-darwin", false),
        "ex-ray-x86_64-apple-darwin"
    );
}
