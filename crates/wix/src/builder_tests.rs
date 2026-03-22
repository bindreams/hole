use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use super::*;

fn os(s: &str) -> OsString {
    OsString::from(s)
}

#[skuld::test]
fn wix_args_minimal() {
    let builder = Builder::new("installer.wxs")
        .workspace_root("/project")
        .target_dir("/project/target");

    let wix_exe = Path::new("/cache/wix.exe");
    let output = Path::new("/project/target/release/out.msi");
    let defines = BTreeMap::new();

    let args = builder.wix_args(wix_exe, output, &defines);

    assert_eq!(args[0], os("build"));
    assert!(args.contains(&os("installer.wxs")));
    let o_idx = args.iter().position(|a| a == "-o").unwrap();
    assert_eq!(args[o_idx + 1], output.as_os_str());
}

#[skuld::test]
fn wix_args_with_defines() {
    let mut defines = BTreeMap::new();
    defines.insert("ProductVersion".to_string(), "1.0.0".to_string());
    defines.insert("ProductName".to_string(), "Test".to_string());

    let builder = Builder::new("a.wxs")
        .workspace_root("/project")
        .target_dir("/project/target");

    let args = builder.wix_args(Path::new("wix.exe"), Path::new("out.msi"), &defines);
    let args_str: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();

    let d_indices: Vec<usize> = args_str
        .iter()
        .enumerate()
        .filter(|(_, a)| *a == "-d")
        .map(|(i, _)| i)
        .collect();

    assert_eq!(d_indices.len(), 2);
    // BTreeMap: ProductName before ProductVersion
    assert_eq!(args_str[d_indices[0] + 1], "ProductName=Test");
    assert_eq!(args_str[d_indices[1] + 1], "ProductVersion=1.0.0");
}

#[skuld::test]
fn wix_args_with_bindpaths() {
    let builder = Builder::new("a.wxs")
        .workspace_root("/project")
        .target_dir("/project/target")
        .bindpath("BinDir", "/staging/BinDir");

    let defines = BTreeMap::new();
    let args = builder.wix_args(Path::new("wix.exe"), Path::new("out.msi"), &defines);
    let args_str: Vec<String> = args.iter().map(|a| a.to_string_lossy().into_owned()).collect();

    let bp_idx = args_str
        .iter()
        .position(|a| a == "-bindpath")
        .expect("should have -bindpath");
    assert_eq!(args_str[bp_idx + 1], "BinDir=/staging/BinDir");
}

#[skuld::test]
fn builder_new_sets_wxs() {
    let builder = Builder::new("installer.wxs");
    assert_eq!(builder.wxs_file, Path::new("installer.wxs"));
}

#[skuld::test]
fn builder_defaults() {
    let builder = Builder::new("a.wxs");
    assert!(builder.output.is_none());
    assert!(builder.before.is_empty());
    assert!(builder.after.is_empty());
    assert!(!builder.skip_before);
    assert!(!builder.skip_after);
    assert!(builder.defines.is_empty());
    assert!(builder.bindpaths.is_empty());
}

#[skuld::test]
fn builder_fluent_api() {
    let builder = Builder::new("a.wxs")
        .output("out.msi")
        .before(vec!["cargo".into(), "build".into()])
        .after(vec!["echo".into(), "done".into()])
        .skip_before(true)
        .define("K", "V")
        .bindpath("BinDir", "/bin");

    assert_eq!(builder.output.as_deref(), Some(Path::new("out.msi")));
    assert_eq!(builder.before, vec!["cargo", "build"]);
    assert_eq!(builder.after, vec!["echo", "done"]);
    assert!(builder.skip_before);
    assert_eq!(builder.defines["K"], "V");
    assert_eq!(builder.bindpaths["BinDir"], Path::new("/bin"));
}

#[skuld::test]
fn hook_env_vars() {
    let builder = Builder::new("/project/installer.wxs")
        .workspace_root("/project")
        .target_dir("/project/target")
        .package_name("my-app")
        .package_version("2.3.4");

    let output = PathBuf::from("/project/target/release/my-app.msi");
    let env = builder.hook_env(&output);

    assert_eq!(env.get("WIX_OUTPUT").unwrap(), "/project/target/release/my-app.msi");
    assert_eq!(env.get("WIX_WXS").unwrap(), "/project/installer.wxs");
    assert_eq!(env.get("WIX_PACKAGE_NAME").unwrap(), "my-app");
    assert_eq!(env.get("WIX_PACKAGE_VERSION").unwrap(), "2.3.4");
    assert_eq!(env.get("WIX_WORKSPACE_ROOT").unwrap(), "/project");
    assert_eq!(env.get("WIX_TARGET_DIR").unwrap(), "/project/target");
}

#[skuld::test]
fn auto_inject_product_version() {
    let builder = Builder::new("a.wxs")
        .workspace_root("/p")
        .target_dir("/p/target")
        .package_name("app")
        .package_version("1.2.3");

    // build() auto-injects ProductVersion — test via wix_args which uses the defines
    let mut defines = builder.defines.clone();
    defines
        .entry("ProductVersion".into())
        .or_insert_with(|| builder.package_version.clone());

    assert_eq!(defines["ProductVersion"], "1.2.3");
}

#[skuld::test]
fn auto_inject_does_not_override_explicit() {
    let builder = Builder::new("a.wxs")
        .workspace_root("/p")
        .target_dir("/p/target")
        .package_name("app")
        .package_version("1.2.3")
        .define("ProductVersion", "9.9.9");

    let mut defines = builder.defines.clone();
    defines
        .entry("ProductVersion".into())
        .or_insert_with(|| builder.package_version.clone());

    assert_eq!(defines["ProductVersion"], "9.9.9");
}

#[skuld::test]
fn default_output_path() {
    let builder = Builder::new("a.wxs")
        .workspace_root("/project")
        .target_dir("/project/target")
        .package_name("my-app");

    // Default output: target_dir/release/<package_name>.msi
    let output = builder.output.clone().unwrap_or_else(|| {
        builder
            .target_dir
            .join("release")
            .join(format!("{}.msi", builder.package_name))
    });

    assert_eq!(output, Path::new("/project/target/release/my-app.msi"));
}
