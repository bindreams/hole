use super::*;

#[skuld::test]
fn save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let state = PluginState {
        version: SCHEMA_VERSION,
        plugins: vec![
            PluginRecord {
                pid: 1234,
                start_time_unix_ms: 1000,
            },
            PluginRecord {
                pid: 5678,
                start_time_unix_ms: 2000,
            },
        ],
    };
    save(dir.path(), &state).unwrap();
    let loaded = load(dir.path()).expect("should load saved state");
    assert_eq!(loaded, state);
}

#[skuld::test]
fn append_record_preserves_prior() {
    let dir = tempfile::tempdir().unwrap();
    let r1 = PluginRecord {
        pid: 100,
        start_time_unix_ms: 1000,
    };
    let r2 = PluginRecord {
        pid: 200,
        start_time_unix_ms: 2000,
    };

    append_record(dir.path(), r1.clone()).unwrap();
    append_record(dir.path(), r2.clone()).unwrap();

    let loaded = load(dir.path()).expect("should load after append");
    assert_eq!(loaded.plugins, vec![r1, r2]);
}

#[skuld::test]
fn append_record_creates_file_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    let r = PluginRecord {
        pid: 42,
        start_time_unix_ms: 999,
    };
    append_record(dir.path(), r.clone()).unwrap();

    let loaded = load(dir.path()).expect("should load after first append");
    assert_eq!(loaded.plugins, vec![r]);
}

#[skuld::test]
fn load_missing_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_malformed_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), b"not json").unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn load_version_mismatch_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let state = PluginState {
        version: 999,
        plugins: vec![],
    };
    save(dir.path(), &state).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn clear_removes_file() {
    let dir = tempfile::tempdir().unwrap();
    let state = PluginState {
        version: SCHEMA_VERSION,
        plugins: vec![PluginRecord {
            pid: 1,
            start_time_unix_ms: 1,
        }],
    };
    save(dir.path(), &state).unwrap();
    assert!(dir.path().join(STATE_FILE_NAME).exists());
    clear(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn clear_tolerates_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    clear(dir.path()).unwrap();
}

#[skuld::test]
fn load_unknown_field_returns_none() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "plugins": [{"pid": 1, "start_time_unix_ms": 1, "extra": true}],
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(load(dir.path()).is_none());
}

#[skuld::test]
fn save_creates_missing_dir() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("a").join("b");
    let state = PluginState {
        version: SCHEMA_VERSION,
        plugins: vec![],
    };
    save(&nested, &state).unwrap();
    assert!(nested.join(STATE_FILE_NAME).exists());
}
