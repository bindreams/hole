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
        dns: hole_common::config::DnsConfig::default(),
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

// Listener selection --------------------------------------------------------------------------------------------------

#[skuld::test]
fn socks5_only_produces_one_socks_local() {
    let cfg = sample_config();
    let ss_config = build_ss_config(&cfg, None).unwrap();

    assert_eq!(ss_config.local.len(), 1);
    let local = &ss_config.local[0].config;
    assert!(matches!(local.protocol, ProtocolType::Socks));
    let addr = local.addr.as_ref().expect("local must have addr");
    match addr {
        ServerAddr::SocketAddr(s) => assert_eq!(s.port(), cfg.local_port),
        other => panic!("expected SocketAddr, got {other:?}"),
    }
}

#[skuld::test]
fn http_only_produces_one_http_local() {
    let mut cfg = sample_config();
    cfg.proxy_socks5 = false;
    cfg.proxy_http = true;
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss_config = build_ss_config(&cfg, None).unwrap();

    assert_eq!(ss_config.local.len(), 1);
    let local = &ss_config.local[0].config;
    assert!(matches!(local.protocol, ProtocolType::Http));
    assert!(matches!(local.mode, Mode::TcpOnly));
    let addr = local.addr.as_ref().expect("local must have addr");
    match addr {
        ServerAddr::SocketAddr(s) => assert_eq!(s.port(), cfg.local_port_http),
        other => panic!("expected SocketAddr, got {other:?}"),
    }
}

#[skuld::test]
fn both_enabled_produces_two_locals() {
    let mut cfg = sample_config();
    cfg.proxy_http = true;
    cfg.local_port_http = 4074;
    let ss_config = build_ss_config(&cfg, None).unwrap();

    assert_eq!(ss_config.local.len(), 2);
    let socks = &ss_config.local[0].config;
    let http = &ss_config.local[1].config;
    assert!(matches!(socks.protocol, ProtocolType::Socks));
    assert!(
        matches!(socks.mode, Mode::TcpAndUdp),
        "Full mode SOCKS5 listener must be TcpAndUdp, got {:?}",
        socks.mode
    );
    assert!(matches!(http.protocol, ProtocolType::Http));
    assert!(matches!(http.mode, Mode::TcpOnly));
}

#[skuld::test]
fn http_listener_is_tcp_only_in_full_mode() {
    // The HTTP listener's mode must never be promoted to TcpAndUdp, even
    // when the overall tunnel_mode is Full. HTTP CONNECT is TCP-only per
    // RFC 7231 §4.3.6; mis-set mode would make shadowsocks-service try to
    // open a UDP server under the HTTP protocol, which is nonsense.
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::Full;
    cfg.proxy_http = true;
    let ss_config = build_ss_config(&cfg, None).unwrap();
    let http = ss_config
        .local
        .iter()
        .find(|l| matches!(l.config.protocol, ProtocolType::Http))
        .expect("HTTP local must be present");
    assert!(matches!(http.config.mode, Mode::TcpOnly));
}

#[skuld::test]
fn socks5_full_mode_is_tcp_and_udp() {
    // Regression guard for the existing (pre-#242) behaviour: Full mode +
    // SOCKS5 enabled => TcpAndUdp, which lets the dispatcher use UDP
    // ASSOCIATE.
    let cfg = sample_config();
    assert_eq!(cfg.tunnel_mode, hole_common::protocol::TunnelMode::Full);
    let ss_config = build_ss_config(&cfg, None).unwrap();
    let socks = &ss_config.local[0].config;
    assert!(matches!(socks.mode, Mode::TcpAndUdp));
}

#[skuld::test]
fn socks5_socks_only_mode_is_tcp_only() {
    // Keeps #189 regression pinned: SocksOnly must not enable UDP on the
    // SOCKS5 listener.
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss_config = build_ss_config(&cfg, None).unwrap();
    let socks = &ss_config.local[0].config;
    assert!(matches!(socks.mode, Mode::TcpOnly));
}

// Validation errors ---------------------------------------------------------------------------------------------------

#[skuld::test]
fn full_mode_without_socks5_errors() {
    let mut cfg = sample_config();
    cfg.proxy_socks5 = false;
    cfg.proxy_http = true;
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::Full;
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(
        matches!(err, ProxyError::TunnelRequiresSocks5),
        "expected TunnelRequiresSocks5, got {err:?}"
    );
}

#[skuld::test]
fn no_listeners_enabled_errors() {
    let mut cfg = sample_config();
    cfg.proxy_socks5 = false;
    cfg.proxy_http = false;
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let err = build_ss_config(&cfg, None).unwrap_err();
    assert!(
        matches!(err, ProxyError::NoListenersEnabled),
        "expected NoListenersEnabled, got {err:?}"
    );
}

#[skuld::test]
fn same_port_errors() {
    let mut cfg = sample_config();
    cfg.proxy_http = true;
    cfg.local_port_http = cfg.local_port;
    let err = build_ss_config(&cfg, None).unwrap_err();
    match err {
        ProxyError::DuplicateListenerPort { port } => assert_eq!(port, cfg.local_port),
        other => panic!("expected DuplicateListenerPort, got {other:?}"),
    }
}

#[skuld::test]
fn port_zero_errors_socks5() {
    let mut cfg = sample_config();
    cfg.local_port = 0;
    let err = build_ss_config(&cfg, None).unwrap_err();
    match err {
        ProxyError::InvalidListenerPort { field } => assert_eq!(field, "local_port"),
        other => panic!("expected InvalidListenerPort(local_port), got {other:?}"),
    }
}

#[skuld::test]
fn port_zero_errors_http() {
    let mut cfg = sample_config();
    cfg.proxy_http = true;
    cfg.local_port_http = 0;
    let err = build_ss_config(&cfg, None).unwrap_err();
    match err {
        ProxyError::InvalidListenerPort { field } => assert_eq!(field, "local_port_http"),
        other => panic!("expected InvalidListenerPort(local_port_http), got {other:?}"),
    }
}
