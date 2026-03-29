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
    };

    let pc = build_proxy_config(&config).expect("should return Some");
    assert_eq!(pc.server.id, "b");
    assert_eq!(pc.local_port, 4073);
    assert!(pc.plugin_path.is_none());
}

#[skuld::test]
fn build_proxy_config_no_selection() {
    let config = AppConfig {
        servers: vec![test_entry("a")],
        selected_server: None,
        local_port: 4073,
        enabled: false,
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
    };

    assert!(build_proxy_config(&config).is_none());
}

// validate_and_read_import tests =====

const VALID_SERVER_JSON: &str =
    r#"{"server":"1.2.3.4","server_port":8388,"password":"pw","method":"aes-256-gcm"}"#;

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
    assert!(!err.contains("SUPER_SECRET"), "error message leaked file content: {err}");
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
