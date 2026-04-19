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
        proxy_socks5: true,
        proxy_http: false,
        local_port_http: 4074,
    }
}

#[skuld::test]
fn udp_available_without_plugin() {
    assert!(plugin_supports_udp(&sample_config()));
}

#[skuld::test]
fn udp_unavailable_with_v2ray_plugin() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".into());
    assert!(!plugin_supports_udp(&cfg));
}

#[skuld::test]
fn udp_available_with_galoshes() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("galoshes".into());
    assert!(plugin_supports_udp(&cfg));
}

#[skuld::test]
fn udp_unavailable_with_unknown_plugin() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("some-custom-plugin".into());
    assert!(!plugin_supports_udp(&cfg));
}

#[skuld::test]
fn config_with_plugin_local_overrides_server_address() {
    let cfg = sample_config();
    let plugin_local: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let ss_config = build_ss_config(&cfg, Some(plugin_local)).unwrap();

    // Server address should be the plugin's local address, not the original server.
    let svr = &ss_config.server[0].config;
    match svr.addr() {
        shadowsocks::config::ServerAddr::SocketAddr(addr) => {
            assert_eq!(*addr, plugin_local);
        }
        other => panic!("expected SocketAddr, got {other:?}"),
    }
}

#[skuld::test]
fn config_without_plugin_local_uses_original_server() {
    let cfg = sample_config();
    let ss_config = build_ss_config(&cfg, None).unwrap();

    let svr = &ss_config.server[0].config;
    match svr.addr() {
        shadowsocks::config::ServerAddr::DomainName(host, port) => {
            assert_eq!(host, "1.2.3.4");
            assert_eq!(*port, 8388);
        }
        other => panic!("expected DomainName, got {other:?}"),
    }
}

#[skuld::test]
fn config_with_plugin_local_has_no_plugin_config() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".into());
    let plugin_local: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let ss_config = build_ss_config(&cfg, Some(plugin_local)).unwrap();

    // No PluginConfig should be set — Garter manages the plugin lifecycle.
    let svr = &ss_config.server[0].config;
    assert!(svr.plugin().is_none());
}
