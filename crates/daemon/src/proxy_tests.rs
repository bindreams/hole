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
    }
}

fn sample_config() -> ProxyConfig {
    ProxyConfig {
        server: sample_server(),
        local_port: 4073,
        plugin_path: None,
    }
}

// Server config tests =================================================================================================

#[skuld::test]
fn builds_one_server_entry() {
    let ss = build_ss_config(&sample_config()).unwrap();
    assert_eq!(ss.server.len(), 1);
}

#[skuld::test]
fn server_has_correct_address() {
    let ss = build_ss_config(&sample_config()).unwrap();
    let srv = &ss.server[0].config;
    assert_eq!(srv.addr().host(), "1.2.3.4");
    assert_eq!(srv.addr().port(), 8388);
}

#[skuld::test]
fn server_has_correct_password() {
    let ss = build_ss_config(&sample_config()).unwrap();
    assert_eq!(ss.server[0].config.password(), "secret");
}

#[skuld::test]
fn server_has_correct_method() {
    let ss = build_ss_config(&sample_config()).unwrap();
    let method = ss.server[0].config.method();
    assert_eq!(method.to_string(), "aes-256-gcm");
}

#[skuld::test]
fn invalid_method_returns_error() {
    let mut cfg = sample_config();
    cfg.server.method = "definitely-not-a-cipher".to_string();
    let err = build_ss_config(&cfg).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidMethod(_)));
}

// Local instances tests ===============================================================================================

#[skuld::test]
fn creates_two_local_instances() {
    let ss = build_ss_config(&sample_config()).unwrap();
    assert_eq!(ss.local.len(), 2);
}

#[skuld::test]
fn first_local_is_tun() {
    let ss = build_ss_config(&sample_config()).unwrap();
    assert_eq!(ss.local[0].config.protocol.as_str(), "tun");
}

#[skuld::test]
fn tun_has_correct_subnet() {
    let ss = build_ss_config(&sample_config()).unwrap();
    let addr = ss.local[0].config.tun_interface_address.unwrap();
    assert_eq!(addr.to_string(), "10.255.0.1/24");
}

#[skuld::test]
fn second_local_is_socks5() {
    let ss = build_ss_config(&sample_config()).unwrap();
    assert_eq!(ss.local[1].config.protocol.as_str(), "socks");
}

#[skuld::test]
fn socks5_binds_to_localhost_on_configured_port() {
    let ss = build_ss_config(&sample_config()).unwrap();
    let addr = ss.local[1].config.addr.as_ref().unwrap();
    assert_eq!(addr.host(), "127.0.0.1");
    assert_eq!(addr.port(), 4073);
}

#[skuld::test]
fn socks5_uses_custom_port() {
    let mut cfg = sample_config();
    cfg.local_port = 9999;
    let ss = build_ss_config(&cfg).unwrap();
    let addr = ss.local[1].config.addr.as_ref().unwrap();
    assert_eq!(addr.port(), 9999);
}

// Plugin tests ========================================================================================================

#[skuld::test]
fn no_plugin_when_absent() {
    let ss = build_ss_config(&sample_config()).unwrap();
    assert!(ss.server[0].config.plugin().is_none());
}

#[skuld::test]
fn plugin_set_when_present() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".to_string());
    cfg.server.plugin_opts = Some("tls;host=example.com".to_string());
    let ss = build_ss_config(&cfg).unwrap();
    let plugin = ss.server[0].config.plugin().unwrap();
    assert_eq!(plugin.plugin, "v2ray-plugin");
    assert_eq!(plugin.plugin_opts.as_deref(), Some("tls;host=example.com"));
}

#[skuld::test]
fn plugin_uses_plugin_path_when_provided() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".to_string());
    cfg.plugin_path = Some("/usr/local/bin/v2ray-plugin".into());
    let ss = build_ss_config(&cfg).unwrap();
    let plugin = ss.server[0].config.plugin().unwrap();
    assert_eq!(plugin.plugin, "/usr/local/bin/v2ray-plugin");
}

#[skuld::test]
fn plugin_falls_back_to_plugin_name_without_path() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".to_string());
    cfg.plugin_path = None;
    let ss = build_ss_config(&cfg).unwrap();
    let plugin = ss.server[0].config.plugin().unwrap();
    assert_eq!(plugin.plugin, "v2ray-plugin");
}
