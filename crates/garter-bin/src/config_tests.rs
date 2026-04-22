use std::path::Path;

use crate::config::ChainConfig;

#[skuld::test]
fn parse_valid_config() {
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
    options: "tls;host=example.com"
  - plugin: /usr/bin/obfs-plugin
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    assert_eq!(config.chain.len(), 2);
    assert_eq!(config.chain[0].plugin, Path::new("/usr/bin/v2ray-plugin"));
    assert_eq!(config.chain[0].options.as_deref(), Some("tls;host=example.com"));
    assert!(config.chain[1].options.is_none());
}

#[skuld::test]
fn parse_empty_chain_is_error() {
    let yaml = "chain: []";
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    assert!(config.chain.is_empty());
}

#[skuld::test]
fn resolve_relative_paths() {
    let yaml = r#"
chain:
  - plugin: ./plugins/v2ray-plugin
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    let config_dir = Path::new("/etc/shadowsocks");
    let resolved = config.resolve_paths(config_dir);
    let expected = Path::new("/etc/shadowsocks").join("plugins").join("v2ray-plugin");
    assert_eq!(resolved.chain[0].plugin, expected);
}

#[skuld::test]
fn absolute_paths_unchanged() {
    let yaml = r#"
chain:
  - plugin: /usr/bin/v2ray-plugin
"#;
    let config: ChainConfig = yaml_serde::from_str(yaml).unwrap();
    let resolved = config.resolve_paths(Path::new("/somewhere/else"));
    assert_eq!(resolved.chain[0].plugin, Path::new("/usr/bin/v2ray-plugin"));
}
