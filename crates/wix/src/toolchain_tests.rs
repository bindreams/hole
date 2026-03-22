use super::*;

#[skuld::test]
fn version_is_nonempty() {
    let v = wix_version();
    assert!(!v.is_empty(), "wix_version() should return a non-empty string");
}

#[skuld::test]
fn version_is_semver() {
    let v = wix_version();
    let parts: Vec<&str> = v.split('.').collect();
    assert_eq!(parts.len(), 3, "version should have 3 parts: {v}");
    for part in &parts {
        part.parse::<u32>()
            .unwrap_or_else(|_| panic!("version part '{part}' is not a number in '{v}'"));
    }
}

#[skuld::test]
fn cache_dir_contains_version() {
    let dir = wix_cache_dir();
    let dir_str = dir.to_string_lossy();
    assert!(
        dir_str.contains(&format!("wix-v{}", wix_version())),
        "cache dir should contain version: {dir_str}"
    );
}

#[skuld::test]
fn cache_dir_is_under_cargo_wix() {
    let dir = wix_cache_dir();
    let dir_str = dir.to_string_lossy();
    assert!(
        dir_str.contains("cargo-wix"),
        "cache dir should be under 'cargo-wix': {dir_str}"
    );
}

#[skuld::test]
fn toolchain_toml_has_required_fields() {
    let tc = toolchain();
    assert!(!tc.version.is_empty());
    assert!(tc.url.contains(&tc.version));
    assert_eq!(tc.sha256.len(), 64);
    assert!(tc.sha256.chars().all(|c| c.is_ascii_hexdigit()));
}

#[skuld::test]
fn wix_bundle_is_nonempty() {
    assert!(!WIX_BUNDLE.is_empty(), "bundled WiX zip should not be empty");
}

#[skuld::test]
fn wix_bundle_is_valid_zip() {
    let cursor = std::io::Cursor::new(WIX_BUNDLE);
    let archive = zip::ZipArchive::new(cursor).expect("bundled WiX should be a valid zip");
    assert!(!archive.is_empty(), "zip should contain files");
}

#[skuld::test]
fn wix_bundle_contains_wix_exe() {
    let cursor = std::io::Cursor::new(WIX_BUNDLE);
    let archive = zip::ZipArchive::new(cursor).expect("bundled WiX should be a valid zip");
    let names: Vec<String> = (0..archive.len())
        .filter_map(|i| archive.name_for_index(i).map(|n| n.to_string()))
        .collect();
    assert!(
        names.iter().any(|n| n.ends_with("wix.exe")),
        "zip should contain wix.exe, found: {names:?}"
    );
}
