use super::*;
use crate::proxy::{BridgeExe, PluginSource};
use crate::test_support::plugin_install::{empty_install, sibling_path};
use hole_common::config::ServerEntry;
use hole_common::protocol::ProxyConfig;
use std::env::consts::EXE_SUFFIX;
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
    // A SocksOnly listener also exposes UDP-ASSOCIATE.
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

// Plugin path resolution tests ========================================================================================

/// A directory standing in for the install dir, holding a fake bridge exe.
struct FakeInstall {
    _dir: tempfile::TempDir,
    exe: std::path::PathBuf,
}

impl FakeInstall {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let exe = empty_install(dir.path());
        Self { _dir: dir, exe }
    }

    /// Drop a fake sibling binary named `binary` (platform extension added).
    fn add_sibling(&self, binary: &str) -> std::path::PathBuf {
        let file = sibling_path(&self.exe, binary);
        std::fs::write(&file, b"fake").unwrap();
        file
    }

    fn resolve(&self, name: &str) -> Result<BundledPlugin, PluginResolveError> {
        PluginSource::build_dir(BridgeExe::At(self.exe.clone())).resolve(name)
    }
}

#[skuld::test]
fn resolve_v2ray_plugin_name_finds_ex_ray_sibling() {
    // The interop promise: a `plugin=v2ray-plugin` config resolves to a
    // path ending in `ex-ray{.exe}`, NOT `v2ray-plugin.exe`.
    let install = FakeInstall::new();
    let plugin_file = install.add_sibling("ex-ray");

    let resolved = install.resolve("v2ray-plugin").unwrap();

    let canonical = std::fs::canonicalize(&plugin_file).unwrap();
    assert_eq!(resolved.path(), canonical);
    assert_eq!(resolved.descriptor().name, "v2ray-plugin");
    assert_eq!(resolved.descriptor().binary_name, "ex-ray");
}

#[skuld::test]
fn resolve_finds_every_bundled_plugin_next_to_the_bridge() {
    for name in hole_common::plugin::known_plugin_names() {
        let install = FakeInstall::new();
        let binary = hole_common::plugin::lookup(name).unwrap().binary_name;
        let plugin_file = install.add_sibling(binary);

        let resolved = install.resolve(name).unwrap();

        assert_eq!(resolved.path(), std::fs::canonicalize(&plugin_file).unwrap(), "{name}");
        assert_eq!(resolved.descriptor().name, name, "{name}");
        assert!(resolved.path().is_absolute(), "{name}");
    }
}

#[skuld::test]
fn resolve_refuses_an_unbundled_plugin_even_when_a_sibling_of_that_name_exists() {
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
    let err = PluginSource::build_dir(BridgeExe::Unknown)
        .resolve("some-custom-plugin")
        .unwrap_err();
    assert!(matches!(err, PluginResolveError::NotBundled { .. }), "got: {err:?}");
}

#[skuld::test]
fn resolve_a_bundled_plugin_missing_next_to_the_bridge_is_a_typed_error_not_a_bare_name() {
    let install = FakeInstall::new();

    let err = install.resolve("v2ray-plugin").unwrap_err();

    assert!(
        matches!(&err, PluginResolveError::BinaryMissing { plugin, binary, .. } if plugin == "v2ray-plugin" && *binary == format!("ex-ray{EXE_SUFFIX}")),
        "got: {err:?}"
    );
}

#[skuld::test]
fn resolve_a_directory_named_like_the_binary_is_not_the_plugin() {
    let install = FakeInstall::new();
    std::fs::create_dir(sibling_path(&install.exe, "ex-ray")).unwrap();

    let err = install.resolve("v2ray-plugin").unwrap_err();

    assert!(matches!(err, PluginResolveError::BinaryMissing { .. }), "got: {err:?}");
}

/// Names that could escape the install directory, or that are not names at all,
/// are plain `NotBundled`: the one gate answers for them, with no separate
/// name-format check.
#[skuld::test]
fn resolve_refuses_a_name_that_could_be_a_path_as_not_bundled() {
    let install = FakeInstall::new();
    for name in [
        "/usr/bin/evil",
        r"..\evil",
        "../evil",
        "evil\0",
        "",
        "evil plugin",
        "ex-ray.exe",
    ] {
        let err = install.resolve(name).unwrap_err();
        assert!(
            matches!(&err, PluginResolveError::NotBundled { name: n } if n == name),
            "{name:?}: {err:?}"
        );
    }
}

#[skuld::test]
fn resolve_without_a_bridge_exe_is_a_typed_error_that_carries_the_os_error() {
    let err = PluginSource::build_dir(BridgeExe::Unknown)
        .resolve("galoshes")
        .unwrap_err();
    assert!(
        matches!(&err, PluginResolveError::ExeUnknown { plugin, .. } if plugin == "galoshes"),
        "got: {err:?}"
    );
    let cause = std::error::Error::source(&err).expect("current_exe's error is the source");
    assert_eq!(
        cause.downcast_ref::<std::io::Error>().map(std::io::Error::kind),
        Some(std::io::ErrorKind::NotFound)
    );
    // The user-facing text stays free of the OS error, which may name a path.
    assert_eq!(
        err.to_string(),
        "cannot locate the directory Hole is installed in, so its bundled plugin \"galoshes\" cannot be found"
    );
}

#[skuld::test]
fn the_not_bundled_message_shows_the_configured_name_escaped() {
    let err = PluginResolveError::NotBundled {
        name: "evil\n\u{1b}[31m\"x".into(),
    };

    let shown = err.to_string();

    assert!(!shown.contains('\n') && !shown.contains('\u{1b}'), "got: {shown:?}");
    assert!(shown.contains(r#""evil\n\u{1b}[31m\"x""#), "got: {shown:?}");
}

#[skuld::test]
fn resolve_with_a_relative_bridge_exe_is_a_typed_error() {
    // A relative exe would make the sibling path relative, i.e. cwd-dependent.
    let err = PluginSource::build_dir(BridgeExe::At("hole".into()))
        .resolve("galoshes")
        .unwrap_err();
    assert!(
        matches!(err, PluginResolveError::ExeUnknown { cause: None, .. }),
        "got: {err:?}"
    );
}

#[skuld::test]
fn resolve_with_a_relative_bridge_exe_never_looks_in_the_cwd() {
    // Exists relative to the cwd, with a plugin beside it: canonicalizing would
    // turn the relative exe into a cwd-rooted absolute path and find it.
    let cwd = std::env::current_dir().unwrap();
    let dir = tempfile::tempdir_in(&cwd).unwrap();
    std::fs::write(dir.path().join(format!("hole{EXE_SUFFIX}")), b"fake").unwrap();
    std::fs::write(dir.path().join(format!("galoshes{EXE_SUFFIX}")), b"fake").unwrap();
    let relative_exe = dir.path().strip_prefix(&cwd).unwrap().join(format!("hole{EXE_SUFFIX}"));
    assert!(relative_exe.is_relative() && relative_exe.exists(), "fixture");

    let err = PluginSource::build_dir(BridgeExe::At(relative_exe))
        .resolve("galoshes")
        .unwrap_err();

    assert!(matches!(err, PluginResolveError::ExeUnknown { .. }), "got: {err:?}");
}

#[skuld::test]
fn resolve_logs_when_the_bridge_exe_cannot_be_canonicalized() {
    use crate::test_support::log_capture::VecWriter;
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let dir = tempfile::tempdir().unwrap();
    let exe = dir.path().join("gone").join("hole");
    let cause = std::fs::canonicalize(&exe).unwrap_err().to_string();
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );

    let err = {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        PluginSource::build_dir(BridgeExe::At(exe))
            .resolve("galoshes")
            .unwrap_err()
    };

    assert!(matches!(err, PluginResolveError::BinaryMissing { .. }), "got: {err:?}");
    let log = writer.snapshot_string();
    assert!(
        log.contains(&cause),
        "the canonicalize failure must be logged; got:\n{log}"
    );
}

#[skuld::test]
fn the_not_bundled_message_names_the_plugin_and_lists_the_bundled_ones() {
    let err = PluginResolveError::NotBundled {
        name: "kcptun".to_string(),
    };
    let msg = err.to_string();
    assert!(msg.contains("kcptun"), "{msg}");
    assert!(msg.contains("only its bundled plugins"), "{msg}");
    assert!(
        msg.contains(&format!(
            "Bundled plugins: {}",
            hole_common::plugin::known_plugin_names_joined()
        )),
        "{msg}"
    );
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
