use super::*;
use crate::config::ServerEntry;
use skuld::temp_dir;
use std::path::Path;
use time::macros::datetime;

const NOW: time::OffsetDateTime = datetime!(2026-06-10 14:23:05 UTC);

#[skuld::test]
fn load_valid_file_returns_config_and_no_recovery(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let original = AppConfig {
        servers: vec![ServerEntry::default_placeholder()],
        local_port: 5555,
        ..Default::default()
    };
    original.save(&path).unwrap();

    let (store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, original);
    assert!(recovery.is_none());
    assert_eq!(store.path(), path);
    // No stray backup or temp files.
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 1);
}

#[skuld::test]
fn load_missing_file_returns_defaults_and_no_recovery(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");

    let (_store, config, recovery) = ConfigStore::load(path.clone(), NOW);

    assert_eq!(config, AppConfig::default());
    assert!(recovery.is_none());
    assert!(!path.exists());
    assert_eq!(std::fs::read_dir(dir).unwrap().count(), 0);
}

#[skuld::test]
fn save_roundtrips_through_store(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let (store, mut config, _) = ConfigStore::load(path.clone(), NOW);

    config.local_port = 6666;
    store.save(&config).unwrap();

    let (_, reloaded, recovery) = ConfigStore::load(path, NOW);
    assert_eq!(reloaded, config);
    assert!(recovery.is_none());
}
