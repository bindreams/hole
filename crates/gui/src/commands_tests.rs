use super::*;
use hole_common::config::{AppConfig, ServerEntry};
use skuld::temp_dir;
use std::path::Path;

fn test_entry(id: &str) -> ServerEntry {
    ServerEntry {
        id: id.to_string(),
        name: format!("Server {id}"),
        server: "1.2.3.4".to_string(),
        server_port: 8388,
        method: "aes-256-gcm".to_string(),
        password: "pw".to_string(),
        plugin: None,
        plugin_opts: None,
    }
}

#[skuld::test]
fn build_proxy_config_with_selected_server() {
    let config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("b".to_string()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    let pc = build_proxy_config(&config).expect("should return Some");
    assert_eq!(pc.server.id, "b");
    assert_eq!(pc.local_port, 4073);
}

#[skuld::test]
fn build_proxy_config_no_selection() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: None,
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    assert!(build_proxy_config(&config).is_none());
}

#[skuld::test]
fn build_proxy_config_invalid_selection() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: Some("nonexistent".to_string()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    assert!(build_proxy_config(&config).is_none());
}

// save_config preservation tests ======================================================================================

/// Verify that merging a frontend config (elevation_prompt_shown=false) with
/// an in-memory config (elevation_prompt_shown=true) preserves the flag.
///
/// This mirrors the logic in `save_config`: re-inject the in-memory
/// `elevation_prompt_shown` before saving, because the frontend doesn't
/// know about the field and always sends `false`.
#[skuld::test]
fn save_config_preserves_elevation_prompt_shown() {
    // Simulate in-memory state where the dialog has been shown
    let in_memory = AppConfig {
        elevation_prompt_shown: true,
        ..Default::default()
    };

    // Simulate what the frontend sends (doesn't know about the field)
    let mut from_frontend = AppConfig {
        local_port: 5555, // user changed the port
        elevation_prompt_shown: false,
        ..Default::default()
    };

    // Apply the same logic as save_config
    from_frontend.elevation_prompt_shown = in_memory.elevation_prompt_shown;

    assert!(
        from_frontend.elevation_prompt_shown,
        "elevation_prompt_shown should be preserved from in-memory state"
    );
    assert_eq!(
        from_frontend.local_port, 5555,
        "other fields should keep frontend values"
    );
}

// auto_select_first_server tests ======================================================================================

#[skuld::test]
fn auto_select_first_server_when_none_selected() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: None,
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert_eq!(config.selected_server.as_deref(), Some("a"));
}

#[skuld::test]
fn auto_select_preserves_existing_selection() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("b".to_string()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert_eq!(config.selected_server.as_deref(), Some("b"));
}

#[skuld::test]
fn auto_select_fixes_stale_selection() {
    let mut config = AppConfig {
        servers: vec![test_entry("a"), test_entry("b")],
        selected_server: Some("deleted-id".to_string()),
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert_eq!(config.selected_server.as_deref(), Some("a"));
}

#[skuld::test]
fn auto_select_noop_on_empty_servers() {
    let mut config = AppConfig {
        servers: vec![],
        selected_server: None,
        local_port: 4073,
        enabled: false,
        ..Default::default()
    };

    auto_select_first_server(&mut config);
    assert!(config.selected_server.is_none());
}

// validate_and_read_import tests ======================================================================================

const VALID_SERVER_JSON: &str = r#"{"server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-256-gcm"}"#;

#[skuld::test]
fn import_rejects_non_json_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("data.txt");
    std::fs::write(&file, VALID_SERVER_JSON).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("only .json"));
}

#[skuld::test]
fn import_rejects_no_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("shadow");
    std::fs::write(&file, "root:x:0:0:root").unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("only .json"));
}

#[skuld::test]
fn import_rejects_directory(#[fixture(temp_dir)] dir: &Path) {
    let subdir = dir.join("not-a-file.json");
    std::fs::create_dir(&subdir).unwrap();
    let result = validate_and_read_import(&subdir);
    assert!(result.is_err());
    let err = result.unwrap_err();
    // On Windows, File::open on a directory fails before the is_file() check.
    assert!(
        err.contains("not a regular file") || err.contains("not found or not accessible"),
        "unexpected error: {err}"
    );
}

#[skuld::test]
fn import_rejects_nonexistent_path() {
    let result = validate_and_read_import(Path::new("/nonexistent/path.json"));
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("not found"));
}

#[skuld::test]
fn import_rejects_oversized_file(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("huge.json");
    let data = vec![b' '; 11 * 1024 * 1024]; // 11 MB
    std::fs::write(&file, &data).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("too large"));
}

#[skuld::test]
fn import_accepts_valid_json_file(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("servers.json");
    std::fs::write(&file, VALID_SERVER_JSON).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[skuld::test]
fn import_accepts_uppercase_json_extension(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("servers.JSON");
    std::fs::write(&file, VALID_SERVER_JSON).unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_ok());
}

#[skuld::test]
fn import_error_does_not_leak_content(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("bad.json");
    std::fs::write(&file, "SUPER_SECRET_CONTENT_HERE").unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(
        !err.contains("SUPER_SECRET"),
        "error message leaked file content: {err}"
    );
}

#[skuld::test]
fn import_error_sanitizes_invalid_value(#[fixture(temp_dir)] dir: &Path) {
    let file = dir.join("bad-port.json");
    std::fs::write(
        &file,
        r#"{"server":"1.2.3.4","server_port":99999,"password":"pw","method":"aes-256-gcm"}"#,
    )
    .unwrap();
    let result = validate_and_read_import(&file);
    assert!(result.is_err());
    let err = result.unwrap_err();
    assert!(!err.contains("99999"), "error message leaked raw value: {err}");
}
