use super::*;
use skuld::temp_dir;
use std::path::Path;

#[skuld::test]
fn load_nonexistent_returns_defaults(#[fixture(temp_dir)] dir: &Path) {
    let config = AppConfig::load(&dir.join("nonexistent.json")).unwrap();
    assert_eq!(config.local_port, 4073);
    assert!(config.servers.is_empty());
    assert!(!config.enabled);
    assert_eq!(config.selected_server, None);
}

#[skuld::test]
fn load_valid_json_roundtrips(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let original = AppConfig {
        servers: vec![ServerEntry {
            id: "abc-123".to_string(),
            name: "Test".to_string(),
            server: "1.2.3.4".to_string(),
            server_port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "secret".to_string(),
            plugin: None,
            plugin_opts: None,
            validation: None,
        }],
        selected_server: Some("abc-123".to_string()),
        local_port: 5555,
        enabled: true,
        ..Default::default()
    };
    original.save(&path).unwrap();
    let loaded = AppConfig::load(&path).unwrap();
    assert_eq!(original, loaded);
}

#[skuld::test]
fn load_corrupt_json_returns_error(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("bad.json");
    std::fs::write(&path, "not json at all {{{").unwrap();
    let err = AppConfig::load(&path).unwrap_err();
    assert!(err.to_string().contains("parse"));
}

#[skuld::test]
fn save_creates_parent_dirs(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("nested").join("deep").join("config.json");
    AppConfig::default().save(&path).unwrap();
    assert!(path.exists());
}

#[skuld::test]
fn save_then_load_is_identity(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let config = AppConfig::default();
    config.save(&path).unwrap();
    let loaded = AppConfig::load(&path).unwrap();
    assert_eq!(config, loaded);
}

#[skuld::test]
fn default_selected_server_is_none() {
    assert_eq!(AppConfig::default().selected_server, None);
}

#[skuld::test]
fn selected_entry_with_unknown_uuid_returns_none() {
    let config = AppConfig {
        selected_server: Some("nonexistent-uuid".to_string()),
        servers: vec![ServerEntry {
            id: "abc".to_string(),
            name: "S".to_string(),
            server: "1.2.3.4".to_string(),
            server_port: 8388,
            method: "aes-256-gcm".to_string(),
            password: "pw".to_string(),
            plugin: None,
            plugin_opts: None,
            validation: None,
        }],
        ..Default::default()
    };
    assert!(config.selected_entry().is_none());
}

#[skuld::test]
fn selected_entry_with_valid_uuid_returns_correct_entry() {
    let config = AppConfig {
        selected_server: Some("target-id".to_string()),
        servers: vec![
            ServerEntry {
                id: "other-id".to_string(),
                name: "Other".to_string(),
                server: "1.1.1.1".to_string(),
                server_port: 1111,
                method: "aes-256-gcm".to_string(),
                password: "pw1".to_string(),
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
            ServerEntry {
                id: "target-id".to_string(),
                name: "Target".to_string(),
                server: "2.2.2.2".to_string(),
                server_port: 2222,
                method: "chacha20-ietf-poly1305".to_string(),
                password: "pw2".to_string(),
                plugin: None,
                plugin_opts: None,
                validation: None,
            },
        ],
        ..Default::default()
    };
    let entry = config.selected_entry().unwrap();
    assert_eq!(entry.name, "Target");
    assert_eq!(entry.server, "2.2.2.2");
}

#[skuld::test]
fn deserialize_with_missing_fields_uses_defaults() {
    let json = r#"{"servers": []}"#;
    let config: AppConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.local_port, 4073);
    assert!(!config.enabled);
    assert_eq!(config.selected_server, None);
}

#[skuld::test]
fn deserialize_with_extra_unknown_fields_succeeds() {
    let json = r#"{"servers": [], "future_field": 42, "another": "hi"}"#;
    let config: AppConfig = serde_json::from_str(json).unwrap();
    assert_eq!(config.local_port, 4073);
}

// elevation_prompt_shown tests ----------------------------------------------------------------------------------------

#[skuld::test]
fn deserialize_without_elevation_prompt_shown_defaults_to_false() {
    let json = r#"{"servers": [], "local_port": 4073}"#;
    let config: AppConfig = serde_json::from_str(json).unwrap();
    assert!(!config.elevation_prompt_shown);
}

#[skuld::test]
fn elevation_prompt_shown_roundtrips(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let config = AppConfig {
        elevation_prompt_shown: true,
        ..Default::default()
    };
    config.save(&path).unwrap();

    let loaded = AppConfig::load(&path).unwrap();
    assert!(loaded.elevation_prompt_shown);
}

// macOS permission tests ----------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
#[skuld::test]
fn save_creates_file_with_owner_only_permissions(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join("hole").join("config.json");
    AppConfig::default().save(&path).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "config file should be 0600, got {mode:o}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn save_creates_directory_with_owner_only_permissions(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let config_dir = dir.join("hole");
    let path = config_dir.join("config.json");
    AppConfig::default().save(&path).unwrap();

    let mode = std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "config dir should be 0700, got {mode:o}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn save_fixes_existing_file_permissions(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let path = dir.join("config.json");
    // Simulate old behavior: world-readable file
    std::fs::write(&path, "{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

    AppConfig::default().save(&path).unwrap();

    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "config file should be tightened to 0600, got {mode:o}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn save_fixes_existing_directory_permissions(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let config_dir = dir.join("hole");
    std::fs::create_dir_all(&config_dir).unwrap();
    std::fs::set_permissions(&config_dir, std::fs::Permissions::from_mode(0o755)).unwrap();

    let path = config_dir.join("config.json");
    AppConfig::default().save(&path).unwrap();

    let mode = std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "config dir should be tightened to 0700, got {mode:o}");
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn save_preserves_permissions_on_repeated_saves(#[fixture(temp_dir)] dir: &Path) {
    use std::os::unix::fs::PermissionsExt;

    let config_dir = dir.join("hole");
    let path = config_dir.join("config.json");

    AppConfig::default().save(&path).unwrap();
    AppConfig::default().save(&path).unwrap();

    let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    let dir_mode = std::fs::metadata(&config_dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        file_mode, 0o600,
        "file permissions should stay 0600 after repeated saves"
    );
    assert_eq!(dir_mode, 0o700, "dir permissions should stay 0700 after repeated saves");
}

// Debug redaction tests -----------------------------------------------------------------------------------------------

#[skuld::test]
fn server_entry_debug_redacts_password() {
    let entry = ServerEntry {
        id: "test-id".to_string(),
        name: "Test".to_string(),
        server: "1.2.3.4".to_string(),
        server_port: 8388,
        method: "aes-256-gcm".to_string(),
        password: "super-secret-do-not-leak".to_string(),
        plugin: None,
        plugin_opts: None,
        validation: None,
    };
    let debug_output = format!("{:?}", entry);
    assert!(
        !debug_output.contains("super-secret-do-not-leak"),
        "Debug output must not contain the actual password: {debug_output}"
    );
    assert!(
        debug_output.contains("<redacted>"),
        "Debug output must contain redacted placeholder: {debug_output}"
    );
}

#[skuld::test]
fn server_entry_debug_shows_non_sensitive_fields() {
    let entry = ServerEntry {
        id: "unique-id-123".to_string(),
        name: "MyServer".to_string(),
        server: "10.20.30.40".to_string(),
        server_port: 9999,
        method: "chacha20-ietf-poly1305".to_string(),
        password: "do-not-show-this".to_string(),
        plugin: Some("v2ray-plugin".to_string()),
        plugin_opts: Some("server;tls".to_string()),
        validation: None,
    };
    let debug_output = format!("{:?}", entry);
    assert!(debug_output.contains("unique-id-123"), "should contain id");
    assert!(debug_output.contains("MyServer"), "should contain name");
    assert!(debug_output.contains("10.20.30.40"), "should contain server");
    assert!(debug_output.contains("9999"), "should contain server_port");
    assert!(debug_output.contains("chacha20-ietf-poly1305"), "should contain method");
    assert!(debug_output.contains("v2ray-plugin"), "should contain plugin");
    assert!(debug_output.contains("server;tls"), "should contain plugin_opts");
}

// Filter types --------------------------------------------------------------------------------------------------------

#[skuld::test]
fn filter_rule_roundtrips_via_json() {
    let rule = FilterRule {
        address: "google.com".to_string(),
        matching: MatchType::WithSubdomains,
        action: FilterAction::Bypass,
    };
    let json = serde_json::to_string(&rule).unwrap();
    let parsed: FilterRule = serde_json::from_str(&json).unwrap();
    assert_eq!(rule, parsed);
}

#[skuld::test]
fn match_type_serializes_as_lowercase() {
    let json = serde_json::to_string(&MatchType::WithSubdomains).unwrap();
    assert_eq!(json, r#""with_subdomains""#);
}

#[skuld::test]
fn filter_action_serializes_as_lowercase() {
    let json = serde_json::to_string(&FilterAction::Bypass).unwrap();
    assert_eq!(json, r#""bypass""#);
}

// New AppConfig fields ------------------------------------------------------------------------------------------------

#[skuld::test]
fn deserialize_old_config_without_new_fields_uses_defaults() {
    let json = r#"{"servers": [], "local_port": 4073, "enabled": false}"#;
    let config: AppConfig = serde_json::from_str(json).unwrap();
    assert!(config.filters.is_empty());
    assert!(!config.start_on_login);
    assert_eq!(config.on_startup, StartupBehavior::RestoreLastState);
    assert_eq!(config.theme, Theme::Dark);
    assert!(config.proxy_server_enabled);
    assert!(config.proxy_socks5);
    assert!(!config.proxy_http);
    assert_eq!(config.local_port_http, 4074);
}

#[skuld::test]
fn new_config_fields_roundtrip(#[fixture(temp_dir)] dir: &Path) {
    let path = dir.join("config.json");
    let config = AppConfig {
        filters: vec![FilterRule {
            address: "*.example.com".to_string(),
            matching: MatchType::Wildcard,
            action: FilterAction::Block,
        }],
        start_on_login: true,
        on_startup: StartupBehavior::AlwaysConnect,
        theme: Theme::Light,
        proxy_server_enabled: false,
        proxy_socks5: false,
        proxy_http: true,
        local_port_http: 5555,
        ..Default::default()
    };
    config.save(&path).unwrap();
    let loaded = AppConfig::load(&path).unwrap();
    assert_eq!(config.filters, loaded.filters);
    assert_eq!(config.start_on_login, loaded.start_on_login);
    assert_eq!(config.on_startup, loaded.on_startup);
    assert_eq!(config.theme, loaded.theme);
    assert_eq!(config.proxy_server_enabled, loaded.proxy_server_enabled);
    assert_eq!(config.proxy_socks5, loaded.proxy_socks5);
    assert_eq!(config.proxy_http, loaded.proxy_http);
    assert_eq!(config.local_port_http, loaded.local_port_http);
}

#[skuld::test]
fn startup_behavior_all_variants_roundtrip() {
    for variant in [
        StartupBehavior::DoNotConnect,
        StartupBehavior::RestoreLastState,
        StartupBehavior::AlwaysConnect,
    ] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: StartupBehavior = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}

#[skuld::test]
fn theme_all_variants_roundtrip() {
    for variant in [Theme::Light, Theme::Dark, Theme::System] {
        let json = serde_json::to_string(&variant).unwrap();
        let parsed: Theme = serde_json::from_str(&json).unwrap();
        assert_eq!(variant, parsed);
    }
}

// Plugin name validation ==============================================================================================

#[skuld::test]
fn valid_plugin_names_accepted() {
    assert!(is_valid_plugin_name("v2ray-plugin"));
    assert!(is_valid_plugin_name("kcptun"));
    assert!(is_valid_plugin_name("simple-obfs"));
    assert!(is_valid_plugin_name("xray-plugin"));
    assert!(is_valid_plugin_name("plugin_v2"));
    assert!(is_valid_plugin_name("plugin.exe"));
}

#[skuld::test]
fn plugin_name_with_forward_slash_rejected() {
    assert!(!is_valid_plugin_name("/usr/bin/evil"));
    assert!(!is_valid_plugin_name("../evil"));
}

#[skuld::test]
fn plugin_name_with_backslash_rejected() {
    assert!(!is_valid_plugin_name("..\\evil"));
    assert!(!is_valid_plugin_name("C:\\Windows\\evil.exe"));
}

#[skuld::test]
fn plugin_name_with_null_byte_rejected() {
    assert!(!is_valid_plugin_name("evil\0"));
}

#[skuld::test]
fn plugin_name_empty_rejected() {
    assert!(!is_valid_plugin_name(""));
}

#[skuld::test]
fn plugin_name_with_space_rejected() {
    assert!(!is_valid_plugin_name("evil plugin"));
}

#[skuld::test]
fn plugin_name_dot_and_dotdot_rejected() {
    assert!(!is_valid_plugin_name("."));
    assert!(!is_valid_plugin_name(".."));
    assert!(!is_valid_plugin_name("..."));
}

#[skuld::test]
fn plugin_name_shell_metacharacters_rejected() {
    assert!(!is_valid_plugin_name("evil;rm"));
    assert!(!is_valid_plugin_name("evil|cat"));
    assert!(!is_valid_plugin_name("evil$PATH"));
    assert!(!is_valid_plugin_name("evil`id`"));
    assert!(!is_valid_plugin_name("evil(1)"));
    assert!(!is_valid_plugin_name("evil{1}"));
}
