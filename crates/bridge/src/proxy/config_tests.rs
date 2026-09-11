use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::net::{IpAddr, Ipv4Addr};

/// The resolved server IP a bare-SS happy-path test threads in. The sample
/// server's literal `1.2.3.4` resolves to itself, so reusing it keeps the
/// existing host/port assertions intact.
const SAMPLE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

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

// UDP-drop capability is derived at runtime from the plugin's reported
// sitrep `transports` (`udp_available_from_chain` in `proxy_manager.rs`),
// tested in `proxy_manager_tests.rs`.

#[skuld::test]
fn config_with_plugin_local_overrides_server_address() {
    let cfg = sample_config();
    let plugin_local: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let ss_config = build_ss_config(&cfg, Some(plugin_local), SAMPLE_IP, None).unwrap();

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
fn config_without_plugin_local_uses_resolved_server() {
    // No plugin: the SS endpoint is the resolved IP socket (the literal server
    // resolves to itself), never a DomainName the OS resolver would re-resolve.
    let cfg = sample_config();
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();

    let svr = &ss_config.server[0].config;
    match svr.addr() {
        ServerAddr::SocketAddr(addr) => {
            assert_eq!(addr.ip(), SAMPLE_IP);
            assert_eq!(addr.port(), 8388);
        }
        other => panic!("expected SocketAddr (resolved IP), got {other:?}"),
    }
}

#[skuld::test]
fn bare_ss_uses_resolved_ip_not_hostname() {
    // No-plugin (bare SS) with a HOSTNAME server: the SS endpoint must be the
    // DoH-resolved IP, NOT the hostname — otherwise shadowsocks-rust OS-resolves
    // the proxy domain at connect time, re-leaking it via plaintext DNS.
    let mut cfg = sample_config();
    cfg.server.server = "proxy.example".into();
    let resolved: IpAddr = "203.0.113.7".parse().unwrap();
    let ss_config = build_ss_config(&cfg, None, resolved, None).unwrap();

    let svr = &ss_config.server[0].config;
    match svr.addr() {
        ServerAddr::SocketAddr(addr) => {
            assert_eq!(addr.ip(), resolved, "bare-SS endpoint must be the resolved IP");
            assert_eq!(addr.port(), cfg.server.server_port);
        }
        other => panic!("expected SocketAddr (resolved IP), got {other:?}"),
    }
}

#[skuld::test]
fn plugin_local_endpoint_ignores_resolved_ip() {
    // The plugin path's SS endpoint is the local plugin loopback; the resolved
    // server IP must not override it (the plugin owns the real-server connect).
    let mut cfg = sample_config();
    cfg.server.server = "proxy.example".into();
    let plugin_local: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let resolved: IpAddr = "203.0.113.7".parse().unwrap();
    let ss_config = build_ss_config(&cfg, Some(plugin_local), resolved, None).unwrap();

    let svr = &ss_config.server[0].config;
    match svr.addr() {
        ServerAddr::SocketAddr(addr) => assert_eq!(*addr, plugin_local),
        other => panic!("expected the plugin loopback, got {other:?}"),
    }
}

#[skuld::test]
fn config_with_plugin_local_has_no_plugin_config() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".into());
    let plugin_local: std::net::SocketAddr = "127.0.0.1:54321".parse().unwrap();
    let ss_config = build_ss_config(&cfg, Some(plugin_local), SAMPLE_IP, None).unwrap();

    // No PluginConfig should be set — Garter manages the plugin lifecycle.
    let svr = &ss_config.server[0].config;
    assert!(svr.plugin().is_none());
}

// Listener selection --------------------------------------------------------------------------------------------------

#[skuld::test]
fn socks5_only_produces_one_socks_local() {
    let cfg = sample_config();
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();

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
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();

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
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();

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
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    let http = ss_config
        .local
        .iter()
        .find(|l| matches!(l.config.protocol, ProtocolType::Http))
        .expect("HTTP local must be present");
    assert!(matches!(http.config.mode, Mode::TcpOnly));
}

#[skuld::test]
fn socks5_full_mode_is_tcp_and_udp() {
    // Full mode + SOCKS5 enabled => TcpAndUdp, which lets the dispatcher
    // use UDP ASSOCIATE.
    let cfg = sample_config();
    assert_eq!(cfg.tunnel_mode, hole_common::protocol::TunnelMode::Full);
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    let socks = &ss_config.local[0].config;
    assert!(matches!(socks.mode, Mode::TcpAndUdp));
}

#[skuld::test]
fn socks5_socks_only_mode_is_tcp_and_udp() {
    // SocksOnly exposes UDP-ASSOCIATE to local SOCKS5 clients
    // (hev-socks5-tunnel, ss-tunnel, proxychains-ng UDP, the in-bridge
    // DNS forwarder's UDP path), so the SOCKS5 listener is TcpAndUdp.
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    let socks = &ss_config.local[0].config;
    assert!(matches!(socks.mode, Mode::TcpAndUdp));
}

// Validation errors ---------------------------------------------------------------------------------------------------

#[skuld::test]
fn full_mode_without_socks5_errors() {
    let mut cfg = sample_config();
    cfg.proxy_socks5 = false;
    cfg.proxy_http = true;
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::Full;
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
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
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
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
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    match err {
        ProxyError::DuplicateListenerPort { port } => assert_eq!(port, cfg.local_port),
        other => panic!("expected DuplicateListenerPort, got {other:?}"),
    }
}

#[skuld::test]
fn port_zero_errors_socks5() {
    let mut cfg = sample_config();
    cfg.local_port = 0;
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
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
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    match err {
        ProxyError::InvalidListenerPort { field } => assert_eq!(field, "local_port_http"),
        other => panic!("expected InvalidListenerPort(local_port_http), got {other:?}"),
    }
}

// Pure-VPN (#459) -----------------------------------------------------------------------------------------------------

#[skuld::test]
fn full_mode_pure_vpn_binds_internal_socks5_only() {
    let mut cfg = sample_config();
    cfg.proxy_socks5 = false;
    cfg.proxy_http = false;
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, Some(54321)).unwrap();

    assert_eq!(ss_config.local.len(), 1, "exactly one internal SOCKS5 instance");
    let socks = &ss_config.local[0].config;
    assert!(matches!(socks.mode, Mode::TcpAndUdp));
    let addr = socks.addr.as_ref().expect("local must have addr");
    match addr {
        ServerAddr::SocketAddr(s) => {
            assert_eq!(s.ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
            assert_eq!(s.port(), 54321);
        }
        other => panic!("expected SocketAddr, got {other:?}"),
    }
}

#[skuld::test]
fn full_mode_pure_vpn_ignores_configured_ports() {
    // With both user-facing listeners off, the configured ports are inert:
    // port checks are flag-conditioned and the internal instance uses the
    // caller-allocated port.
    let mut cfg = sample_config();
    cfg.proxy_socks5 = false;
    cfg.proxy_http = false;
    cfg.local_port = 0;
    cfg.local_port_http = 0;
    let ss_config = build_ss_config(&cfg, None, SAMPLE_IP, Some(54321)).unwrap();
    assert_eq!(ss_config.local.len(), 1);
}

#[skuld::test]
fn doh_bootstrap_display_is_pii_free_and_clear() {
    use crate::dns::bootstrap::BootstrapError;
    let e = ProxyError::DohBootstrap(BootstrapError::NoAnswer);
    let s = e.to_string();
    assert!(s.contains("secure DNS"), "user-facing wording: {s}");
    // PII-free by construction: no host, no filesystem path.
    assert!(
        !s.contains('/') && !s.contains('\\'),
        "no filesystem path in toast text: {s}"
    );
}

#[skuld::test]
fn proxy_error_converts_to_start_error() {
    use hole_common::protocol::StartError;
    assert_eq!(StartError::from(&ProxyError::Cancelled), StartError::Cancelled);
    assert_eq!(
        StartError::from(&ProxyError::AlreadyRunning),
        StartError::AlreadyRunning
    );
    assert_eq!(
        StartError::from(&ProxyError::NetworkBlocked),
        StartError::NetworkBlocked
    );
    match StartError::from(&ProxyError::RouteSetup("nope".into())) {
        StartError::Failed { message } => assert!(message.contains("nope")),
        other => panic!("expected Failed, got {other:?}"),
    }
}

/// The tunnel's ULA must carry a *generated* RFC 4193 §3.2.2 global ID, not
/// the hand-typed `fd00::` (global ID zero) that WireGuard examples, Docker,
/// Proxmox and NAS defaults hand out. `hole-tun` holds this prefix as a real
/// on-link route, so a zero global ID would let the tunnel swallow a user's
/// own ULA network — `fc00::/7` alone does not rule that out.
#[skuld::test]
fn tun_subnet6_is_a_generated_unique_local_64() {
    let cidr: smoltcp::wire::Ipv6Cidr = TUN_SUBNET6.parse().expect("TUN_SUBNET6 parses as an IPv6 CIDR");
    assert_eq!(cidr.prefix_len(), 64, "the TUN's v6 prefix is a /64");

    let octets = cidr.address().octets();
    assert_eq!(octets[0] & 0xfe, 0xfc, "the address is inside fc00::/7");

    let global_id = &octets[1..6];
    assert!(
        global_id.iter().any(|b| *b != 0),
        "the 40-bit global ID must be generated, not zero (fd00::); got {global_id:02x?}"
    );
}

// DispatcherStartError conversion =====================================================================================

/// `Dispatcher::new` used to flatten every `tun_engine::DeviceError` into an
/// opaque `io::Error` before it ever reached this conversion, which made
/// `ProxyError::ForeignAdapter` unreachable from `start_inner` regardless of
/// what `Device::build` returned. Asserts the conversion's SHAPE, not any
/// string embedded in it — a string match would pass even if the variant
/// were wrong.
#[skuld::test]
fn foreign_adapter_device_error_converts_to_the_matching_proxy_error() {
    let alias = "hole-tun".to_string();
    let err = crate::dispatcher::DispatcherStartError::Device(tun_engine::DeviceError::ForeignAdapter {
        alias: alias.clone(),
    });
    match ProxyError::from(err) {
        ProxyError::ForeignAdapter { alias: got } => assert_eq!(got, alias),
        other => panic!("expected ProxyError::ForeignAdapter, got {other:?}"),
    }
}

/// The paired negative: an `Io` arm must convert to `ProxyError::Runtime`,
/// never accidentally to `ForeignAdapter` — without this, a match arm typo
/// swallowing every variant into `ForeignAdapter` would still pass the test
/// above.
#[skuld::test]
fn io_dispatcher_start_error_converts_to_runtime() {
    let err = crate::dispatcher::DispatcherStartError::Io(std::io::Error::other("boom"));
    match ProxyError::from(err) {
        ProxyError::Runtime(_) => {}
        other => panic!("expected ProxyError::Runtime, got {other:?}"),
    }
}

// Key-material classification -----------------------------------------------------------------------------------------
//
// The 2022-blake3 ciphers take the password as base64 key material, so
// `ServerConfig::new` can reject it. Upstream's `ServerConfigError::Display`
// renders the offending symbol and its offset — one character of the user's
// key — and `ProxyError::Display` reaches a GUI toast and `bridge.log`.

/// 32 zero bytes: the right key length for `2022-blake3-aes-256-gcm`.
const PSK32: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
/// 16 zero bytes: the wrong length for that cipher.
const PSK16: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
/// Not base64. `@` is the symbol upstream would name in its message.
const NOT_BASE64: &str = "abc@def";

fn aead2022_config(password: &str) -> ProxyConfig {
    let mut cfg = sample_config();
    cfg.server.method = "2022-blake3-aes-256-gcm".into();
    cfg.server.password = password.into();
    cfg
}

#[skuld::test]
fn aead2022_accepts_a_well_formed_psk() {
    build_ss_config(&aead2022_config(PSK32), None, SAMPLE_IP, None).expect("a correct PSK must build");
}

#[skuld::test]
fn a_password_that_is_not_base64_is_a_key_fault_not_a_method_fault() {
    let cfg = aead2022_config(NOT_BASE64);
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    match &err {
        ProxyError::InvalidKeyMaterial { method, fault } => {
            assert_eq!(method, "2022-blake3-aes-256-gcm");
            assert_eq!(*fault, KeyMaterialFault::PskNotBase64);
        }
        other => panic!("expected InvalidKeyMaterial, got {other:?}"),
    }
}

/// The load-bearing assertion: no byte of the key, and no detail that could
/// locate one, survives into anything user-visible.
///
/// Equality, not a substring hunt. Upstream renders the offending byte as a
/// *number* ("Invalid symbol 64, offset 3."), so `!contains('@')` passes
/// vacuously; pinning the whole message is what actually proves no upstream
/// detail survived.
#[skuld::test]
fn a_key_decode_failure_leaks_no_decode_detail() {
    const EXPECTED: &str = "invalid key for cipher 2022-blake3-aes-256-gcm: the password is not valid base64";

    let cfg = aead2022_config(NOT_BASE64);
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert_eq!(err.to_string(), EXPECTED);

    // `Debug` is the other sink — `?err` in a tracing field, or `{err:?}` in
    // a panic message.
    let debugged = format!("{err:?}");
    assert!(!debugged.contains("offset"), "{debugged}");
    assert!(!debugged.contains("symbol"), "{debugged}");

    // And the toast, which is the `StartError` this maps to.
    match hole_common::protocol::StartError::from(&err) {
        hole_common::protocol::StartError::Failed { message } => assert_eq!(message, EXPECTED),
        other => panic!("expected StartError::Failed, got {other:?}"),
    }
}

/// A wrong-length key is a different cause from a malformed one and keeps its
/// own variant — the lengths are the whole diagnostic and carry no key bytes.
#[skuld::test]
fn a_psk_of_the_wrong_length_reports_both_lengths() {
    let cfg = aead2022_config(PSK16);
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    match &err {
        ProxyError::InvalidKeyMaterial {
            fault: KeyMaterialFault::PskLength { expected, found },
            ..
        } => {
            assert_eq!((*expected, *found), (32, 16));
        }
        other => panic!("expected InvalidKeyMaterial{{PskLength}}, got {other:?}"),
    }
    let rendered = err.to_string();
    assert!(rendered.contains("32") && rendered.contains("16"), "{rendered}");
}

/// The EIH form is `iPSK:…:uPSK`, and its identity keys decode through a
/// different upstream arm with the same `DecodeError` inside it.
#[skuld::test]
fn a_malformed_identity_key_is_classified_separately() {
    let cfg = aead2022_config(&format!("{NOT_BASE64}:{PSK32}"));
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    match &err {
        ProxyError::InvalidKeyMaterial { fault, .. } => {
            assert_eq!(*fault, KeyMaterialFault::IdentityKeyNotBase64);
        }
        other => panic!("expected InvalidKeyMaterial, got {other:?}"),
    }
    assert_eq!(
        err.to_string(),
        "invalid key for cipher 2022-blake3-aes-256-gcm: an identity key in the password is not valid base64"
    );
}

#[skuld::test]
fn an_identity_key_of_the_wrong_length_reports_both_lengths() {
    let cfg = aead2022_config(&format!("{PSK16}:{PSK32}"));
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    match &err {
        ProxyError::InvalidKeyMaterial {
            fault: KeyMaterialFault::IdentityKeyLength { expected, found },
            ..
        } => assert_eq!((*expected, *found), (32, 16)),
        other => panic!("expected InvalidKeyMaterial{{IdentityKeyLength}}, got {other:?}"),
    }
}

/// The paired negative for the rename: a cipher name Hole does not know is
/// still `InvalidMethod`, which is the field the user has to fix.
#[skuld::test]
fn an_unknown_cipher_name_is_still_a_method_fault() {
    let mut cfg = sample_config();
    cfg.server.method = "not-a-cipher".into();
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    match &err {
        ProxyError::InvalidMethod(m) => assert_eq!(m, "not-a-cipher"),
        other => panic!("expected InvalidMethod, got {other:?}"),
    }
}
