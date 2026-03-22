use super::*;

#[skuld::test]
fn parse_minimal_config() {
    let toml_str = r#"wxs = "installer.wxs""#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.wxs, std::path::Path::new("installer.wxs"));
    assert!(config.package.is_none());
    assert!(config.output.is_none());
    assert!(config.before.is_empty());
    assert!(config.after.is_empty());
    assert!(config.defines.is_empty());
    assert!(config.bindpaths.is_empty());
}

#[skuld::test]
fn parse_full_config() {
    let toml_str = r#"
wxs = "installer.wxs"
package = "hole-gui"
output = "target/release/hole.msi"
before = ["cargo", "build", "--release"]
after = ["echo", "done"]

[defines]
ProductName = "Hole"

[bindpaths]
BinDir = "target/release/installer-stage"
DataDir = "data"
"#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert_eq!(config.wxs, std::path::Path::new("installer.wxs"));
    assert_eq!(
        config.output.as_deref(),
        Some(std::path::Path::new("target/release/hole.msi"))
    );
    assert_eq!(config.package.as_deref(), Some("hole-gui"));
    assert_eq!(config.before, vec!["cargo", "build", "--release"]);
    assert_eq!(config.after, vec!["echo", "done"]);
    assert_eq!(config.defines["ProductName"], "Hole");
    assert_eq!(config.bindpaths.len(), 2);
    assert_eq!(
        config.bindpaths["BinDir"],
        std::path::Path::new("target/release/installer-stage")
    );
}

#[skuld::test]
fn parse_no_hooks() {
    let toml_str = r#"wxs = "a.wxs""#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert!(config.before.is_empty());
    assert!(config.after.is_empty());
}

#[skuld::test]
fn missing_wxs_fails() {
    let toml_str = r#"output = "out.msi""#;
    let result = toml::from_str::<WixConfig>(toml_str);
    assert!(result.is_err());
}

#[skuld::test]
fn parse_empty_hooks() {
    let toml_str = r#"
wxs = "a.wxs"
before = []
after = []
"#;
    let config: WixConfig = toml::from_str(toml_str).unwrap();
    assert!(config.before.is_empty());
    assert!(config.after.is_empty());
}
