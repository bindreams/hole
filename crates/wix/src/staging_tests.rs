use std::collections::BTreeMap;

use super::*;

const TEST_TRIPLE: &str = "x86_64-pc-windows-msvc";

fn make_files(entries: &[(&str, &[(&str, &str)])]) -> BTreeMap<String, BTreeMap<String, String>> {
    entries
        .iter()
        .map(|(bindpath, files)| {
            let files = files
                .iter()
                .map(|(dest, src)| (dest.to_string(), src.to_string()))
                .collect();
            (bindpath.to_string(), files)
        })
        .collect()
}

#[skuld::test]
fn expand_target_placeholder() {
    let expanded = expand_vars(
        "{target}/hole.exe",
        std::path::Path::new("/build/target/release"),
        TEST_TRIPLE,
    );
    assert_eq!(expanded, "/build/target/release/hole.exe");
}

#[skuld::test]
fn expand_arch_placeholder() {
    let expanded = expand_vars(
        ".cache/v2ray-plugin-{arch}.exe",
        std::path::Path::new("/build/target/release"),
        TEST_TRIPLE,
    );
    assert_eq!(expanded, ".cache/v2ray-plugin-x86_64-pc-windows-msvc.exe");
}

#[skuld::test]
fn expand_no_placeholder() {
    let expanded = expand_vars(
        ".cache/wintun/wintun.dll",
        std::path::Path::new("/build/target/release"),
        TEST_TRIPLE,
    );
    assert_eq!(expanded, ".cache/wintun/wintun.dll");
}

#[skuld::test]
fn stage_copies_files() {
    let workspace = tempfile::tempdir().unwrap();
    let target_dir = workspace.path().join("target").join("release");
    std::fs::create_dir_all(&target_dir).unwrap();

    // Create source files
    std::fs::write(target_dir.join("app.exe"), b"app binary").unwrap();
    let cache_dir = workspace.path().join(".cache");
    std::fs::create_dir_all(&cache_dir).unwrap();
    std::fs::write(cache_dir.join("lib.dll"), b"library").unwrap();

    let files = make_files(&[(
        "BinDir",
        &[("app.exe", "{target}/app.exe"), ("lib.dll", ".cache/lib.dll")],
    )]);

    let (staging_dir, bindpaths) = stage(&files, workspace.path(), &target_dir, TEST_TRIPLE).unwrap();

    assert!(bindpaths.contains_key("BinDir"));
    let bin_dir = &bindpaths["BinDir"];
    assert!(bin_dir.join("app.exe").exists());
    assert!(bin_dir.join("lib.dll").exists());

    assert_eq!(std::fs::read_to_string(bin_dir.join("app.exe")).unwrap(), "app binary");
    assert_eq!(std::fs::read_to_string(bin_dir.join("lib.dll")).unwrap(), "library");

    // TempDir should be valid
    assert!(staging_dir.path().exists());
}

#[skuld::test]
fn stage_multiple_bindpaths() {
    let workspace = tempfile::tempdir().unwrap();
    let target_dir = workspace.path().join("target").join("release");
    std::fs::create_dir_all(&target_dir).unwrap();
    std::fs::write(target_dir.join("a.exe"), b"a").unwrap();

    let data_dir = workspace.path().join("data");
    std::fs::create_dir_all(&data_dir).unwrap();
    std::fs::write(data_dir.join("config.toml"), b"conf").unwrap();

    let files = make_files(&[
        ("BinDir", &[("a.exe", "{target}/a.exe")]),
        ("DataDir", &[("config.toml", "data/config.toml")]),
    ]);

    let (_staging_dir, bindpaths) = stage(&files, workspace.path(), &target_dir, TEST_TRIPLE).unwrap();

    assert_eq!(bindpaths.len(), 2);
    assert!(bindpaths["BinDir"].join("a.exe").exists());
    assert!(bindpaths["DataDir"].join("config.toml").exists());
}

#[skuld::test]
fn stage_missing_source_file_errors() {
    let workspace = tempfile::tempdir().unwrap();
    let target_dir = workspace.path().join("target").join("release");
    std::fs::create_dir_all(&target_dir).unwrap();

    let files = make_files(&[("BinDir", &[("missing.exe", "{target}/missing.exe")])]);

    let result = stage(&files, workspace.path(), &target_dir, TEST_TRIPLE);
    assert!(result.is_err());
    let err = result.unwrap_err().to_string();
    assert!(err.contains("missing.exe"), "error should mention the file: {err}");
}

#[skuld::test]
fn stage_empty_files_returns_empty_bindpaths() {
    let workspace = tempfile::tempdir().unwrap();
    let target_dir = workspace.path().join("target").join("release");

    let files = BTreeMap::new();
    let (_staging_dir, bindpaths) = stage(&files, workspace.path(), &target_dir, TEST_TRIPLE).unwrap();
    assert!(bindpaths.is_empty());
}
