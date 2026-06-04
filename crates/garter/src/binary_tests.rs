use std::net::SocketAddr;

use crate::binary::BinaryPlugin;
use crate::plugin::ChainPlugin;

#[skuld::test]
fn binary_plugin_name_from_path() {
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", None);
    assert_eq!(plugin.name(), "v2ray-plugin");
}

#[skuld::test]
#[cfg(windows)]
fn binary_plugin_name_from_windows_path() {
    let plugin = BinaryPlugin::new(r"C:\plugins\v2ray-plugin.exe", None);
    assert_eq!(plugin.name(), "v2ray-plugin");
}

#[skuld::test]
fn binary_plugin_with_options() {
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("tls;host=example.com"));
    assert_eq!(plugin.name(), "v2ray-plugin");
}

// SIP003 env-var direction tests ======================================================================================

/// In Client mode (no `server` key in options) `BinaryPlugin` maps
/// `local → SS_LOCAL_*` and `remote → SS_REMOTE_*`. This matches v2ray-plugin's
/// client-mode interpretation: bind on SS_LOCAL, dial SS_REMOTE.
#[skuld::test]
fn sip003_env_client_mode_straight_through() {
    let listen: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let dial: SocketAddr = "203.0.113.1:8388".parse().unwrap();
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("tls;host=example.com"));
    let env = plugin.sip003_env(listen, dial);
    assert_eq!(env.ss_local_host, "127.0.0.1");
    assert_eq!(env.ss_local_port, 9001);
    assert_eq!(env.ss_remote_host, "203.0.113.1");
    assert_eq!(env.ss_remote_port, 8388);
}

/// In Server mode (bare `server` key in options) `BinaryPlugin` must SWAP
/// the env vars: `local → SS_REMOTE_*` and `remote → SS_LOCAL_*`. Reason:
/// v2ray-plugin's server-mode `parseEnv` swaps SS_LOCAL/SS_REMOTE
/// semantics again (SS_REMOTE = inbound listener, SS_LOCAL = outbound
/// dial), so a double-swap restores the chain's intended direction.
/// Without this swap the binary listens on `remote` and forwards to
/// `local`, colliding with the previous chain link. See bindreams/hole#396.
#[skuld::test]
fn sip003_env_server_mode_swaps_addresses() {
    let listen: SocketAddr = "[::]:80".parse().unwrap();
    let dial: SocketAddr = "127.0.0.1:45589".parse().unwrap();
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("server;host=example.com"));
    let env = plugin.sip003_env(listen, dial);
    // Swap: BinaryPlugin's `local` (where the chain wants the binary to
    // bind, [::]:80) must reach v2ray-plugin as SS_REMOTE so its
    // server-mode swap interprets it as the listen address.
    assert_eq!(env.ss_remote_host, "::");
    assert_eq!(env.ss_remote_port, 80);
    assert_eq!(env.ss_local_host, "127.0.0.1");
    assert_eq!(env.ss_local_port, 45589);
}

/// `server` keyword is detected by SIP003 key parser, not substring match.
/// `servername=...` is NOT server mode.
#[skuld::test]
fn sip003_env_client_mode_when_options_only_have_servername() {
    let listen: SocketAddr = "127.0.0.1:9001".parse().unwrap();
    let dial: SocketAddr = "203.0.113.1:8388".parse().unwrap();
    let plugin = BinaryPlugin::new("/usr/bin/v2ray-plugin", Some("servername=cdn.example.com"));
    let env = plugin.sip003_env(listen, dial);
    assert_eq!(env.ss_local_host, "127.0.0.1");
    assert_eq!(env.ss_local_port, 9001);
    assert_eq!(env.ss_remote_host, "203.0.113.1");
    assert_eq!(env.ss_remote_port, 8388);
}

// Readiness-mode tests ================================================================================================

#[skuld::test]
fn readiness_mode_defaults_to_probe() {
    let p = crate::BinaryPlugin::new("/nonexistent", None);
    assert_eq!(p.readiness_mode_for_test(), crate::binary::ReadinessMode::Probe);
}

// GOTRACEBACK env test ================================================================================================

#[skuld::test]
fn fixed_env_sets_gotraceback_crash() {
    // The always-injected env pairs include GOTRACEBACK=crash so a Go
    // plugin (ex-ray) dumps full goroutine state to stderr on a native fault
    // (the bridge relays that stderr through tracing). Harmless to Rust
    // plugins, which ignore it. See bindreams/hole#438.
    let pairs = crate::binary::fixed_plugin_env();
    assert!(
        pairs.iter().any(|(k, v)| *k == "GOTRACEBACK" && *v == "crash"),
        "GOTRACEBACK=crash must be injected: {pairs:?}"
    );
}
