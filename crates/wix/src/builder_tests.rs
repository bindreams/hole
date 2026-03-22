use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::Path;

use super::*;

fn os(s: &str) -> OsString {
    OsString::from(s)
}

#[skuld::test]
fn wix_args_minimal() {
    let builder = Builder::new("installer/main.wxs")
        .workspace_root("/project")
        .target_dir("/project/target/release");

    let wix_exe = Path::new("/cache/wix.exe");
    let output = Path::new("/project/target/release/out.msi");
    let bindpaths = BTreeMap::new();

    let args = builder.wix_args(wix_exe, output, &bindpaths);

    assert_eq!(args[0], os("build"));
    // wxs path should be present
    assert!(args.contains(&os("installer/main.wxs")));
    // output flag
    let o_idx = args.iter().position(|a| a == "-o").unwrap();
    assert_eq!(args[o_idx + 1], output.as_os_str());
}

#[skuld::test]
fn wix_args_with_defines() {
    let builder = Builder::new("a.wxs")
        .workspace_root("/project")
        .target_dir("/project/target/release")
        .define("ProductVersion", "1.0.0")
        .define("ProductName", "Test");

    let wix_exe = Path::new("wix.exe");
    let output = Path::new("out.msi");
    let bindpaths = BTreeMap::new();

    let args = builder.wix_args(wix_exe, output, &bindpaths);

    // Check -d flags are present (BTreeMap: ProductName before ProductVersion)
    let args_str: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();
    let d_indices: Vec<usize> = args_str
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "-d")
        .map(|(i, _)| i)
        .collect();

    assert_eq!(d_indices.len(), 2, "should have 2 -d flags");
    assert_eq!(args_str[d_indices[0] + 1], "ProductName=Test");
    assert_eq!(args_str[d_indices[1] + 1], "ProductVersion=1.0.0");
}

#[skuld::test]
fn wix_args_with_bindpaths() {
    let builder = Builder::new("a.wxs")
        .workspace_root("/project")
        .target_dir("/project/target/release");

    let wix_exe = Path::new("wix.exe");
    let output = Path::new("out.msi");
    let mut bindpaths = BTreeMap::new();
    bindpaths.insert("BinDir".to_string(), std::path::PathBuf::from("/staging/BinDir"));

    let args = builder.wix_args(wix_exe, output, &bindpaths);
    let args_str: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();

    let bp_idx = args_str
        .iter()
        .position(|a| a == "-bindpath")
        .expect("should have -bindpath");
    assert_eq!(args_str[bp_idx + 1], "BinDir=/staging/BinDir");
}

#[skuld::test]
fn builder_new_sets_wxs() {
    let builder = Builder::new("installer/hole.wxs");
    assert_eq!(builder.wxs_file, std::path::Path::new("installer/hole.wxs"));
}

#[skuld::test]
fn builder_defaults() {
    let builder = Builder::new("a.wxs");
    assert!(builder.build_first);
    assert!(builder.output.is_none());
    assert!(builder.defines.is_empty());
    assert!(builder.files.is_empty());
    assert!(builder.extra_bindpaths.is_empty());
    assert!(builder.target_triple.is_empty());
}

#[skuld::test]
fn builder_fluent_api() {
    let builder = Builder::new("a.wxs")
        .build_first(false)
        .output("out.msi")
        .define("K", "V")
        .bindpath("BinDir", "/bin");

    assert!(!builder.build_first);
    assert_eq!(builder.output.as_deref(), Some(std::path::Path::new("out.msi")));
    assert_eq!(builder.defines["K"], "V");
    assert_eq!(builder.extra_bindpaths["BinDir"], std::path::Path::new("/bin"));
}
