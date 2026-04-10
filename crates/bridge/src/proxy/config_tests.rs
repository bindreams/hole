use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;

fn sample_server() -> ServerEntry {
    ServerEntry {
        id: "test".into(),
        name: "Test".into(),
        server: "1.2.3.4".into(),
        server_port: 8388,
        method: "aes-256-gcm".into(),
        password: "secret".into(),
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
        filters: vec![],
    }
}

#[skuld::test]
fn udp_available_without_plugin() {
    assert!(udp_proxy_available(&sample_config()));
}

#[skuld::test]
fn udp_unavailable_with_plugin() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".into());
    assert!(!udp_proxy_available(&cfg));
}
