//! Process-scoped skuld fixtures wrapping the in-process shadowsocks +
//! v2ray-plugin helpers from [`super::ssserver`] and the HTTP sentinel from
//! [`super::http_target`].
//!
//! ## Why process scope?
//!
//! Each fixture spins up a real `shadowsocks_service::server::Server` and,
//! for the plugin variants, also a v2ray-plugin subprocess. Setup cost
//! dominates wall time. Process scope means each fixture is built at most
//! once per test binary, shared across all tests that request it.
//!
//! ## Runtime ownership
//!
//! Each fixture struct contains a `_runtime: tokio::runtime::Runtime` field.
//! This is **load-bearing**: the spawned server task only runs as long as
//! its runtime is alive. Process-scoped fixtures outlive the per-test
//! tokio runtimes that test bodies create via [`super::rt`], so they need
//! their own runtime to drive the server task. The runtime is dropped
//! when skuld tears down process fixtures at the end of the test binary.
//!
//! ## SsServerHandle
//!
//! All `ssserver_*` fixtures return the same struct shape so test bodies
//! can use them interchangeably with `build_socks_harness` /
//! `build_tun_harness`.

use crate::test_support::certs::TestCerts;
use crate::test_support::http_target::{start_http_target, HttpTarget, TargetBind};
use crate::test_support::port_alloc::allocate_ephemeral_port;
use crate::test_support::ssserver::{
    locate_built_v2ray_plugin, start_real_ss_server, start_real_ss_server_with_plugin_quic,
    start_real_ss_server_with_plugin_ws, start_real_ss_server_with_plugin_ws_tls, TEST_METHOD, TEST_METHOD_STR,
    TEST_PASSWORD,
};
use std::net::SocketAddr;

/// Common shape for every `ssserver_*` fixture. Owns the tokio runtime that
/// the server task runs on; dropping the struct shuts down the runtime.
pub(crate) struct SsServerHandle {
    pub addr: SocketAddr,
    pub method: &'static str,
    pub password: String,
    pub plugin: Option<String>,
    pub plugin_opts: Option<String>,
    _runtime: tokio::runtime::Runtime,
}

/// Verify the cargo-built v2ray-plugin binary exists and return its path.
/// Panics with a clear remediation message — per CLAUDE.md, tests must fail
/// loudly on missing dependencies.
fn require_v2ray_plugin() -> String {
    let path = locate_built_v2ray_plugin();
    if !path.is_file() {
        panic!("v2ray-plugin not built at {path:?} — run 'cargo build --workspace' before 'cargo test'",);
    }
    path.to_str().expect("plugin path is valid utf-8").to_string()
}

#[skuld::fixture(scope = process)]
fn test_certs() -> Result<TestCerts, String> {
    Ok(crate::test_support::certs::generate_test_certs())
}

/// Plain shadowsocks server, no plugin.
#[skuld::fixture(scope = process)]
fn ssserver_none() -> Result<SsServerHandle, String> {
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let (addr, _handle) = runtime.block_on(start_real_ss_server(TEST_METHOD, TEST_PASSWORD));
    Ok(SsServerHandle {
        addr,
        method: TEST_METHOD_STR,
        password: TEST_PASSWORD.to_string(),
        plugin: None,
        plugin_opts: None,
        _runtime: runtime,
    })
}

/// Shadowsocks server fronted by v2ray-plugin (websocket, no TLS).
#[skuld::fixture(scope = process)]
fn ssserver_ws() -> Result<SsServerHandle, String> {
    let plugin_path = require_v2ray_plugin();
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let addr = runtime.block_on(async {
        let public_port = allocate_ephemeral_port().await;
        let (addr, _handle) =
            start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, public_port, &plugin_path).await;
        addr
    });
    Ok(SsServerHandle {
        addr,
        method: TEST_METHOD_STR,
        password: TEST_PASSWORD.to_string(),
        plugin: Some("v2ray-plugin".to_string()),
        plugin_opts: Some("host=cloudfront.com;path=/".to_string()),
        _runtime: runtime,
    })
}

/// Shadowsocks server fronted by v2ray-plugin (websocket + TLS).
#[skuld::fixture(scope = process)]
fn ssserver_ws_tls(#[fixture(test_certs)] certs: &TestCerts) -> Result<SsServerHandle, String> {
    let plugin_path = require_v2ray_plugin();
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let plugin_opts = format!(
        "host=cloudfront.com;path=/;tls;cert={};key={}",
        certs.cert_path.display(),
        certs.key_path.display()
    );
    let addr = runtime.block_on(async {
        let public_port = allocate_ephemeral_port().await;
        let (addr, _handle) =
            start_real_ss_server_with_plugin_ws_tls(TEST_METHOD, TEST_PASSWORD, public_port, &plugin_path, certs).await;
        addr
    });
    Ok(SsServerHandle {
        addr,
        method: TEST_METHOD_STR,
        password: TEST_PASSWORD.to_string(),
        plugin: Some("v2ray-plugin".to_string()),
        plugin_opts: Some(plugin_opts),
        _runtime: runtime,
    })
}

/// Shadowsocks server fronted by v2ray-plugin (QUIC transport). QUIC
/// auto-enables TLS inside v2ray-plugin so the cert+key pair is required.
#[skuld::fixture(scope = process)]
fn ssserver_quic(#[fixture(test_certs)] certs: &TestCerts) -> Result<SsServerHandle, String> {
    let plugin_path = require_v2ray_plugin();
    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    let plugin_opts = format!(
        "host=cloudfront.com;mode=quic;cert={};key={}",
        certs.cert_path.display(),
        certs.key_path.display()
    );
    let addr = runtime.block_on(async {
        let public_port = allocate_ephemeral_port().await;
        let (addr, _handle) =
            start_real_ss_server_with_plugin_quic(TEST_METHOD, TEST_PASSWORD, public_port, &plugin_path, certs).await;
        addr
    });
    Ok(SsServerHandle {
        addr,
        method: TEST_METHOD_STR,
        password: TEST_PASSWORD.to_string(),
        plugin: Some("v2ray-plugin".to_string()),
        plugin_opts: Some(plugin_opts),
        _runtime: runtime,
    })
}

/// HTTP target bound to the host's primary non-loopback IPv4 (so TUN tests
/// see the traffic).
#[skuld::fixture(scope = process)]
fn http_target_ipv4() -> Result<HttpTarget, String> {
    Ok(start_http_target(TargetBind::Ipv4Primary))
}

/// HTTP target bound to `[::1]` for the IPv6 axis test.
#[skuld::fixture(scope = process)]
fn http_target_ipv6() -> Result<HttpTarget, String> {
    Ok(start_http_target(TargetBind::Ipv6Loopback))
}
