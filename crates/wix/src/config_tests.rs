use super::*;

#[skuld::test]
fn parse_minimal_config() {
    let toml_str = r#"wxs = "installer/main.wxs""#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.wxs, std::path::Path::new("installer/main.wxs"));
    assert!(config.build);
    assert!(config.output.is_none());
    assert!(config.defines.is_empty());
    assert!(config.files.is_empty());
}

#[skuld::test]
fn parse_full_config() {
    let toml_str = r#"
wxs = "installer/hole.wxs"
build = false
output = "target/release/hole.msi"

[defines]
ProductVersion = "1.0.0"
ProductName = "Hole"

[files.BinDir]
"hole.exe" = "{target}/hole.exe"
"wintun.dll" = ".cache/gui/wintun/wintun.dll"
"#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.wxs, std::path::Path::new("installer/hole.wxs"));
    assert!(!config.build);
    assert_eq!(
        config.output.as_deref(),
        Some(std::path::Path::new("target/release/hole.msi"))
    );
    assert_eq!(config.defines.len(), 2);
    assert_eq!(config.defines["ProductVersion"], "1.0.0");
    assert_eq!(config.files.len(), 1);
    assert_eq!(config.files["BinDir"].len(), 2);
    assert_eq!(config.files["BinDir"]["hole.exe"], "{target}/hole.exe");
}

#[skuld::test]
fn build_defaults_to_true() {
    let toml_str = r#"wxs = "a.wxs""#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert!(config.build);
}

#[skuld::test]
fn missing_wxs_fails() {
    let toml_str = r#"build = false"#;
    let result = toml::from_str::<WixConfig>(toml_str);
    assert!(result.is_err());
}

#[skuld::test]
fn multiple_bindpath_groups() {
    let toml_str = r#"
wxs = "a.wxs"

[files.BinDir]
"a.exe" = "target/release/a.exe"

[files.DataDir]
"data.txt" = "data/data.txt"
"#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.files.len(), 2);
    assert!(config.files.contains_key("BinDir"));
    assert!(config.files.contains_key("DataDir"));
}
