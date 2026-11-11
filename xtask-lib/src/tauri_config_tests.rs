use crate::tauri_config::merged_tauri_config;

fn config_dir(base: &str, macos: Option<&str>) -> tempfile::TempDir {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("tauri.conf.json"), base).unwrap();
    if let Some(text) = macos {
        std::fs::write(dir.path().join("tauri.macos.conf.json"), text).unwrap();
    }
    dir
}

const BASE: &str = r#"{"productName": "x", "bundle": {"externalBin": ["a/b"], "icon": ["i.png"]}}"#;

#[skuld::test]
fn the_platform_file_is_merged_over_the_base_only_for_its_platform() {
    let dir = config_dir(BASE, Some(r#"{"bundle": {"externalBin": null}}"#));

    let (mac, paths) = merged_tauri_config("aarch64-apple-darwin", dir.path()).unwrap();
    let (windows, windows_paths) = merged_tauri_config("x86_64-pc-windows-msvc", dir.path()).unwrap();

    assert!(
        mac["bundle"].get("externalBin").is_none(),
        "null removes the key: {mac}"
    );
    assert_eq!(mac["bundle"]["icon"][0], "i.png", "the rest of the base stays");
    assert_eq!(paths.len(), 2, "both files are watched");
    assert_eq!(windows["bundle"]["externalBin"][0], "a/b");
    assert_eq!(windows_paths.len(), 1);
}

#[skuld::test]
fn a_missing_base_config_is_an_error_naming_the_target() {
    let dir = tempfile::tempdir().unwrap();

    let err = merged_tauri_config("aarch64-apple-darwin", dir.path()).unwrap_err();

    assert!(format!("{err:#}").contains("aarch64-apple-darwin"), "{err:#}");
}
