use super::load_config_or_default;
use hole_common::config::AppConfig;
use skuld::temp_dir;
use std::path::Path;

#[skuld::test]
fn load_config_or_default_falls_back_on_corrupt_file(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    std::fs::write(&path, "{ this is not valid json").unwrap();

    let config = load_config_or_default(&path);

    assert_eq!(
        config,
        AppConfig::default(),
        "a corrupt config must fall back to defaults, not panic or propagate"
    );
}

#[skuld::test]
fn load_config_or_default_reads_a_valid_file(#[fixture(temp_dir)] dir: &Path) {
    // Use a NON-default value so this can't pass by accidentally falling back.
    let path = dir.join("config.json");
    let saved = AppConfig {
        local_port: 5555,
        ..AppConfig::default()
    };
    saved.save(&path).unwrap();

    let config = load_config_or_default(&path);

    assert_eq!(config.local_port, 5555);
}
