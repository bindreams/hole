use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::TunnelMode;

fn test_config() -> ProxyConfig {
    ProxyConfig {
        server: ServerEntry {
            id: "test-id".into(),
            name: "test-server".into(),
            server: "example.invalid".into(),
            server_port: 8388,
            password: "super-secret-password".into(),
            method: "aes-256-gcm".into(),
            plugin: None,
            plugin_opts: None,
            validation: None,
        },
        local_port: 1080,
        tunnel_mode: TunnelMode::Full,
        filters: Vec::new(),
        dns: hole_common::config::DnsConfig {
            enabled: false,
            ..hole_common::config::DnsConfig::default()
        },
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
        diagnostic_plugin_tap: false,
    }
}

// Task 1: persistence =================================================================================================

#[skuld::test]
fn an_absent_target_file_reads_off() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), Target::Off);
}

#[skuld::test]
fn a_corrupt_target_file_reads_off_and_warns() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir_all(tmp.path()).unwrap();
    std::fs::write(tmp.path().join(STATE_FILE_NAME), b"not json").unwrap();
    assert_eq!(
        load(tmp.path()),
        Target::Unreadable,
        "a corrupt file must not be silently treated as a decided target"
    );
}

#[skuld::test]
fn a_saved_connected_target_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let config = test_config();
    let target = Target::Connected {
        config: Box::new(config.clone()),
    };
    save(tmp.path(), &target, None).unwrap();
    assert_eq!(
        load(tmp.path()),
        Target::Connected {
            config: Box::new(config)
        }
    );
}

#[skuld::test]
fn the_target_file_never_carries_the_server_address() {
    use dump::Dump;
    let config = test_config();
    let target = Target::Connected {
        config: Box::new(config),
    };
    // Render through the actual redacting formatter (default
    // `redact_secrets: true`) rather than inspecting the raw `DumpValue`
    // tree, whose `Tagged("secret", ...)` node still carries the plaintext
    // value — redaction is a rendering-time property, not a `dump()`-time
    // one. This is the artifact that actually reaches a log or bundle.
    let rendered = dump::YamlFormatter::default().to_string(&target.dump());
    assert!(
        !rendered.contains("example.invalid"),
        "rendered dump must not carry the configured host in clear, got: {rendered}"
    );
    assert!(
        !rendered.contains("super-secret-password"),
        "rendered dump must not carry the password in clear, got: {rendered}"
    );
    assert!(
        rendered.contains("REDACTED"),
        "rendered dump must show a redaction marker, got: {rendered}"
    );
}

#[skuld::test]
fn a_saved_target_file_is_owner_only_in_an_owner_only_directory() {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let tmp = tempfile::tempdir().unwrap();
        let target = Target::Connected {
            config: Box::new(test_config()),
        };
        save(tmp.path(), &target, None).unwrap();

        let dir_mode = std::fs::metadata(tmp.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "state dir must be 0700, got {dir_mode:o}");

        let file_mode = std::fs::metadata(tmp.path().join(STATE_FILE_NAME))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(file_mode, 0o600, "target file must be 0600, got {file_mode:o}");
    }
}
