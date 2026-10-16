use super::*;
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::net::{IpAddr, Ipv4Addr};

// Helpers =============================================================================================================

/// Resolved server IP threaded into `build_ss_config`. Matches the sample
/// server's literal so host/port assertions are unaffected.
const SAMPLE_IP: IpAddr = IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4));

fn sample_server() -> ServerEntry {
    ServerEntry {
        id: "test-id".to_string(),
        name: "Test".to_string(),
        server: "1.2.3.4".into(),
        server_port: 8388,
        method: "aes-256-gcm".to_string(),
        password: "secret".to_string().into(),
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

// Server config tests =================================================================================================

#[skuld::test]
fn builds_one_server_entry() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    assert_eq!(ss.server.len(), 1);
}

#[skuld::test]
fn server_has_correct_address() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    let srv = &ss.server[0].config;
    assert_eq!(srv.addr().host(), "1.2.3.4");
    assert_eq!(srv.addr().port(), 8388);
}

#[skuld::test]
fn server_has_correct_password() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    assert_eq!(ss.server[0].config.password(), "secret");
}

#[skuld::test]
fn server_has_correct_method() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    let method = ss.server[0].config.method();
    assert_eq!(method.to_string(), "aes-256-gcm");
}

#[skuld::test]
fn invalid_method_returns_error() {
    let mut cfg = sample_config();
    cfg.server.method = "definitely-not-a-cipher".to_string();
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidMethod(_)));
}

// Local instances tests ===============================================================================================

#[skuld::test]
fn creates_one_local_instance() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    assert_eq!(ss.local.len(), 1, "only SOCKS5 local, no TUN");
}

#[skuld::test]
fn local_is_socks5() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    assert_eq!(ss.local[0].config.protocol.as_str(), "socks");
}

#[skuld::test]
fn full_mode_socks5_is_tcp_and_udp() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    let mode = ss.local[0].config.mode;
    // Mode doesn't impl PartialEq; use Debug string comparison.
    assert_eq!(format!("{mode:?}"), "TcpAndUdp");
}

#[skuld::test]
fn socks_only_mode_socks5_is_tcp_and_udp() {
    // Post-#250: SocksOnly listener also exposes UDP-ASSOCIATE.
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    let mode = ss.local[0].config.mode;
    assert_eq!(format!("{mode:?}"), "TcpAndUdp");
}

#[skuld::test]
fn socks5_binds_to_localhost_on_configured_port() {
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
    let addr = ss.local[0].config.addr.as_ref().unwrap();
    assert_eq!(addr.host(), "127.0.0.1");
    assert_eq!(addr.port(), 4073);
}

#[skuld::test]
fn socks5_uses_custom_port() {
    let mut cfg = sample_config();
    cfg.local_port = 9999;
    let ss = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    let addr = ss.local[0].config.addr.as_ref().unwrap();
    assert_eq!(addr.port(), 9999);
}

// TunnelMode::SocksOnly ===============================================================================================

#[skuld::test]
fn socks_only_mode_creates_exactly_one_local() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    assert_eq!(ss.local.len(), 1, "SocksOnly must skip the TUN local entirely");
}

#[skuld::test]
fn socks_only_mode_only_local_is_socks5() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    assert_eq!(ss.local[0].config.protocol.as_str(), "socks");
}

#[skuld::test]
fn socks_only_mode_binds_socks5_to_configured_port() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    cfg.local_port = 12345;
    let ss = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    let addr = ss.local[0].config.addr.as_ref().unwrap();
    assert_eq!(addr.host(), "127.0.0.1");
    assert_eq!(addr.port(), 12345);
}

#[skuld::test]
fn socks_only_mode_has_no_tun_local() {
    let mut cfg = sample_config();
    cfg.tunnel_mode = hole_common::protocol::TunnelMode::SocksOnly;
    let ss = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
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
    let ss = build_ss_config(&sample_config(), None, SAMPLE_IP, None).unwrap();
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
    let ss = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap();
    assert!(ss.server[0].config.plugin().is_none());
}

// Plugin name validation tests ========================================================================================

#[skuld::test]
fn plugin_name_with_forward_slash_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("/usr/bin/evil".to_string());
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_with_backslash_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("..\\evil".to_string());
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_with_null_byte_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("evil\0".to_string());
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_empty_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("".to_string());
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_with_space_rejected() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("evil plugin".to_string());
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert!(matches!(err, ProxyError::InvalidPluginName(_)));
}

#[skuld::test]
fn plugin_name_bare_name_accepted() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("v2ray-plugin".to_string());
    assert!(build_ss_config(&cfg, None, SAMPLE_IP, None).is_ok());
}

// Plugin path resolution tests ========================================================================================
//
// The privileged bridge runs only the plugins Hole ships, found next to its own
// executable. No path through the resolver yields a bare name for the spawner
// to look up on `PATH`.

/// A directory standing in for the install dir, holding a fake bridge exe.
struct FakeInstall {
    dir: tempfile::TempDir,
    exe: std::path::PathBuf,
}

impl FakeInstall {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(if cfg!(windows) { "hole.exe" } else { "hole" });
        std::fs::write(&exe, b"fake").unwrap();
        Self { dir, exe }
    }

    /// Drop a fake sibling binary named `binary` (platform extension added).
    fn add_sibling(&self, binary: &str) -> std::path::PathBuf {
        let file = self.dir.path().join(if cfg!(windows) {
            format!("{binary}.exe")
        } else {
            binary.to_string()
        });
        std::fs::write(&file, b"fake").unwrap();
        file
    }

    fn resolve(&self, name: &str) -> Result<PluginPath, PluginResolveError> {
        resolve_plugin_path_inner(name, Some(self.exe.clone()))
    }
}

#[skuld::test]
fn resolve_v2ray_plugin_name_finds_ex_ray_sibling() {
    // The interop promise: a `plugin=v2ray-plugin` config resolves to a
    // path ending in `ex-ray{.exe}`, NOT `v2ray-plugin.exe` (#414).
    let install = FakeInstall::new();
    let plugin_file = install.add_sibling("ex-ray");

    let resolved = install.resolve("v2ray-plugin").unwrap();

    let canonical = std::fs::canonicalize(&plugin_file).unwrap();
    assert_eq!(resolved.as_path(), canonical);
}

#[skuld::test]
fn resolve_finds_every_bundled_plugin_next_to_the_bridge() {
    for name in hole_common::plugin::known_plugin_names() {
        let install = FakeInstall::new();
        let binary = hole_common::plugin::lookup(name).unwrap().binary_name;
        let plugin_file = install.add_sibling(binary);

        let resolved = install.resolve(name).unwrap();

        assert_eq!(
            resolved.as_path(),
            std::fs::canonicalize(&plugin_file).unwrap(),
            "{name}"
        );
        assert!(resolved.as_path().is_absolute(), "{name}");
    }
}

#[skuld::test]
fn resolve_refuses_an_unbundled_plugin_even_when_a_sibling_of_that_name_exists() {
    // The binary is right there next to the bridge: the refusal is about the
    // name, not about whether the file can be found.
    let install = FakeInstall::new();
    install.add_sibling("some-custom-plugin");

    let err = install.resolve("some-custom-plugin").unwrap_err();

    assert!(
        matches!(&err, PluginResolveError::NotBundled { name } if name == "some-custom-plugin"),
        "got: {err:?}"
    );
}

#[skuld::test]
fn resolve_refuses_an_unbundled_plugin_without_a_bridge_exe() {
    // Unbundled is decided before the executable is consulted, so an unknown
    // exe cannot turn the refusal into some other error.
    let err = resolve_plugin_path_inner("some-custom-plugin", None).unwrap_err();
    assert!(matches!(err, PluginResolveError::NotBundled { .. }), "got: {err:?}");
}

#[skuld::test]
fn resolve_a_bundled_plugin_missing_next_to_the_bridge_is_a_typed_error_not_a_bare_name() {
    let install = FakeInstall::new();

    let err = install.resolve("v2ray-plugin").unwrap_err();

    assert!(
        matches!(&err, PluginResolveError::BinaryMissing { plugin, binary } if plugin == "v2ray-plugin" && *binary == "ex-ray"),
        "got: {err:?}"
    );
}

#[skuld::test]
fn resolve_a_directory_named_like_the_binary_is_not_the_plugin() {
    let install = FakeInstall::new();
    let name = if cfg!(windows) { "ex-ray.exe" } else { "ex-ray" };
    std::fs::create_dir(install.dir.path().join(name)).unwrap();

    let err = install.resolve("v2ray-plugin").unwrap_err();

    assert!(matches!(err, PluginResolveError::BinaryMissing { .. }), "got: {err:?}");
}

#[skuld::test]
fn resolve_without_a_bridge_exe_is_a_typed_error() {
    let err = resolve_plugin_path_inner("galoshes", None).unwrap_err();
    assert!(
        matches!(&err, PluginResolveError::ExeUnknown { plugin } if plugin == "galoshes"),
        "got: {err:?}"
    );
}

#[skuld::test]
fn resolve_with_a_relative_bridge_exe_is_a_typed_error() {
    // A relative exe would make the sibling path relative, i.e. cwd-dependent.
    let err = resolve_plugin_path_inner("galoshes", Some("hole".into())).unwrap_err();
    assert!(matches!(err, PluginResolveError::ExeUnknown { .. }), "got: {err:?}");
}

#[skuld::test]
fn plugin_path_rejects_a_bare_name_and_a_relative_path() {
    assert!(PluginPath::from_absolute("ex-ray").is_none());
    assert!(PluginPath::from_absolute("./ex-ray").is_none());
    assert!(PluginPath::from_absolute("bin/ex-ray").is_none());
}

#[skuld::test]
fn plugin_path_accepts_an_absolute_path() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("ex-ray");
    let path = PluginPath::from_absolute(file.clone()).unwrap();
    assert_eq!(path.as_path(), file);
}

#[skuld::test]
fn the_not_bundled_message_names_the_plugin_and_lists_the_bundled_ones() {
    let err = PluginResolveError::NotBundled {
        name: "kcptun".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("kcptun"), "{msg}");
    assert!(msg.contains("only its bundled plugins"), "{msg}");
    assert!(msg.contains("Bundled plugins: v2ray-plugin, galoshes"), "{msg}");
}

#[skuld::test]
fn validate_refuses_an_unbundled_plugin_with_a_typed_error() {
    let mut cfg = sample_config();
    cfg.server.plugin = Some("kcptun".to_string());

    let err = validate_proxy_config(&cfg).unwrap_err();
    assert!(
        matches!(&err, ProxyError::PluginResolve(PluginResolveError::NotBundled { name }) if name == "kcptun"),
        "got: {err:?}"
    );
    // `build_ss_config` runs the same validation.
    let err = build_ss_config(&cfg, None, SAMPLE_IP, None).unwrap_err();
    assert!(matches!(err, ProxyError::PluginResolve(_)), "got: {err:?}");
}

#[skuld::test]
fn validate_accepts_every_bundled_plugin_name() {
    for name in hole_common::plugin::known_plugin_names() {
        let mut cfg = sample_config();
        cfg.server.plugin = Some(name.to_string());
        validate_proxy_config(&cfg).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[skuld::test]
fn a_refused_plugin_reaches_the_gui_as_a_failed_start_carrying_the_message() {
    let err = ProxyError::PluginResolve(PluginResolveError::NotBundled {
        name: "kcptun".to_string(),
    });
    match hole_common::protocol::StartError::from(&err) {
        hole_common::protocol::StartError::Failed { message } => {
            assert!(
                message.contains("kcptun") && message.contains("Bundled plugins:"),
                "{message}"
            );
        }
        other => panic!("expected Failed, got {other:?}"),
    }
}
