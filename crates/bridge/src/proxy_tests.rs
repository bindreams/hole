use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;

// Helpers =============================================================================================================

fn sample_server() -> ServerEntry {
    ServerEntry {
        id: "test-id".to_string(),
        name: "Test".to_string(),
        server: "1.2.3.4".to_string(),
        server_port: 8388,
        method: "aes-256-gcm".to_string(),
        password: "secret".to_string(),
        plugin: None,
        plugin_opts: None,
        validation: None,
    }
}

fn sample_config() -> ProxyConfig {
    ProxyConfig {
        server: sample_server(),
        local_port: 4073,
        tunnel_mode: hole_common::protocol::TunnelMode::Full,
        filters: Vec::new(),
    }
}

// Server config tests =================================================================================================

#[skuld::test]
fn builds_one_server_entry() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    assert_eq!(ss.server.len(), 1);
}

#[skuld::test]
fn server_has_correct_address() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    let srv = &ss.server[0].config;
    assert_eq!(srv.addr().host(), "1.2.3.4");
    assert_eq!(srv.addr().port(), 8388);
}

#[skuld::test]
fn server_has_correct_password() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    assert_eq!(ss.server[0].config.password(), "secret");
}

#[skuld::test]
fn server_has_correct_method() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    let method = ss.server[0].config.method();
    assert_eq!(method.to_string(), "aes-256-gcm");
}

#[skuld::test]
fn invalid_method_returns_error() {
    let mut cfg = sample_config();
    cfg.server.method = "definitely-not-a-cipher".to_string();
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidMethod(_)));
}

// Local instances tests ===============================================================================================

#[skuld::test]
fn creates_one_local_instance() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    assert_eq!(ss.local.len(), 1, "only SOCKS5 local, no TUN");
}

#[skuld::test]
fn local_is_socks5() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    assert_eq!(ss.local[0].config.protocol.as_str(), "socks");
}

#[skuld::test]
fn socks5_mode_is_tcp_and_udp() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    let mode = ss.local[0].config.mode;
    // Mode doesn't impl PartialEq; use Debug string comparison.
    assert_eq!(format!("{mode:?}"), "TcpAndUdp");
}

#[skuld::test]
fn socks5_binds_to_localhost_on_configured_port() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    let addr = ss.local[0].config.addr.as_ref().unwrap();
    assert_eq!(addr.host(), "127.0.0.1");
    assert_eq!(addr.port(), 4073);
}

#[skuld::test]
fn socks5_uses_custom_port() {
    let mut cfg = sample_config();
    cfg.local_port = 9999;
    let ss = build_ss_config(&cfg, None).unwrap();
    let addr = ss.local[0].config.addr.as_ref().unwrap();
    assert_eq!(addr.port(), 9999);
}

// TunnelMode::SocksOnly ===============================================================================================

#[skuld::test]
fn socks_only_mode_creates_exactly_one_local() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss = build_ss_config(&cfg, None).unwrap();
    assert_eq!(ss.local.len(), 1, "SocksOnly must skip the TUN local entirely");
}

#[skuld::test]
fn socks_only_mode_only_local_is_socks5() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss = build_ss_config(&cfg, None).unwrap();
    assert_eq!(ss.local[0].config.protocol.as_str(), "socks");
}

#[skuld::test]
fn socks_only_mode_binds_socks5_to_configured_port() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    cfg.local_port = 12345;
    let ss = build_ss_config(&cfg, None).unwrap();
    let addr = ss.local[0].config.addr.as_ref().unwrap();
    assert_eq!(addr.host(), "127.0.0.1");
    assert_eq!(addr.port(), 12345);
}

#[skuld::test]
fn socks_only_mode_has_no_tun_local() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss = build_ss_config(&cfg, None).unwrap();
    for local in &ss.local {
        assert_ne!(
            local.config.protocol.as_str(),
            "tun",
            "SocksOnly config must not contain any TUN local: {:?}",
            ss.local
        );
    }
}

// Plugin tests ========================================================================================================

#[skuld::test]
fn no_plugin_when_absent() {
    let ss = build_ss_config(&sample_config(), None).unwrap();
    assert!(ss.server[0].config.plugin().is_none());
}

#[skuld::test]
fn no_plugin_config_even_when_plugin_name_present() {
    // Garter manages the plugin lifecycle externally — build_ss_config
    // should never set PluginConfig on the server. The plugin name in
    // the ServerEntry is used by proxy_manager to start a PluginChain.
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".to_string());
    cfg.server.plugin_opts = Some("tls;host=example.com".to_string());
    let ss = build_ss_config(&cfg, None).unwrap();
    assert!(ss.server[0].config.plugin().is_none());
}

// Plugin name validation tests ========================================================================================

#[skuld::test]
fn plugin_name_with_forward_slash_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("/usr/bin/evil".to_string());
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_with_backslash_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("..\\evil".to_string());
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_with_null_byte_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("evil\0".to_string());
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_empty_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("".to_string());
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_with_space_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("evil plugin".to_string());
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_bare_name_accepted() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".to_string());
    assert!(build_ss_config(&cfg, None).is_ok());
}

// Plugin path resolution tests ========================================================================================

#[skuld::test]
fn resolve_falls_back_to_bare_name_when_not_found() {
    let nonexistent = std::path::PathBuf::from("/nonexistent/dir/hole");
    let result = resolve_plugin_path_inner("v2ray-plugin", Some(nonexistent));
    assert_eq!(result, "v2ray-plugin");
}

#[skuld::test]
fn resolve_falls_back_when_exe_unknown() {
    let result = resolve_plugin_path_inner("v2ray-plugin", None);
    assert_eq!(result, "v2ray-plugin");
}

#[skuld::test]
fn resolve_finds_sibling_binary() {
    let dir = std::env::temp_dir().join(format!("hole-resolve-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    let plugin_name = if cfg!(windows) {
        "test-plugin.exe"
    } else {
        "test-plugin"
    };
    let plugin_file = dir.join(plugin_name);
    std::fs::write(&plugin_file, b"fake").unwrap();

    let fake_exe = dir.join(if cfg!(windows) { "hole.exe" } else { "hole" });
    std::fs::write(&fake_exe, b"fake").unwrap();

    let result = resolve_plugin_path_inner("test-plugin", Some(fake_exe));

    let canonical = std::fs::canonicalize(&plugin_file).unwrap();
    assert_eq!(result, canonical.to_string_lossy());

    let _ = std::fs::remove_dir_all(&dir);
}

#[skuld::test]
fn resolve_finds_sibling_when_name_has_exe_suffix() {
    let dir = std::env::temp_dir().join(format!("hole-resolve-exe-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();

    // Create "test-plugin.exe" as a sibling — same name on all platforms for this test.
    let plugin_file = dir.join("test-plugin.exe");
    std::fs::write(&plugin_file, b"fake").unwrap();

    let fake_exe = dir.join(if cfg!(windows) { "hole.exe" } else { "hole" });
    std::fs::write(&fake_exe, b"fake").unwrap();

    // Name already has .exe — should NOT double-append on Windows
    let result = resolve_plugin_path_inner("test-plugin.exe", Some(fake_exe));

    let canonical = std::fs::canonicalize(&plugin_file).unwrap();
    assert_eq!(result, canonical.to_string_lossy());

    let _ = std::fs::remove_dir_all(&dir);
}
