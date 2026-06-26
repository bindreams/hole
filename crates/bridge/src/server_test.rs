//! One-shot shadowsocks client test runner.
//!
//! Completely isolated from `ProxyManager` / `ProxyState`. Each call
//! optionally spawns a transient SIP003 plugin sidecar (e.g.
//! v2ray-plugin/ex-ray), opens a single TCP relay through
//! the configured shadowsocks server to a public-internet sentinel, and
//! reports a granular per-phase outcome. Concurrent calls are safe — each
//! gets its own plugin process and its own [`ProxyClientStream`].

use crate::proxy::resolve_plugin_path_inner;
use hole_common::config::ServerEntry;
use hole_common::protocol::{ServerTestOutcome, LATENCY_VALIDATED_ON_CONNECT};
use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::ProxyClientStream;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::debug;

const HEAD_REQUEST: &[u8] = b"HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";

/// Tunable parameters. Production code constructs [`TestConfig::production`].
/// Tests construct a custom one with shorter timeouts and dynamic sentinels.
#[derive(Clone)]
pub struct TestConfig {
    pub preflight_timeout: Duration,
    pub ss_connect_timeout: Duration,
    pub sentinel_read_timeout: Duration,
    /// Two sentinel `host:port` strings (the second is the fallback).
    pub sentinels: [String; 2],
    /// Optional override for the plugin path. `None` → use
    /// [`resolve_plugin_path_inner`]. Tests use this to point at a specific
    /// on-disk plugin binary (the xtask-built `ex-ray`, or a provisioned
    /// upstream v2ray-plugin) without depending on `PATH`.
    pub plugin_path_override: Option<String>,
    /// User's resolver config for the private-DoH server bootstrap.
    pub dns: hole_common::config::DnsConfig,
    /// Test-only DoH querier override. When present, `run_server_test` resolves
    /// via `resolve_via_doh_with` instead of the production `resolve_via_doh`,
    /// so a test can drive the full preflight path with no OS resolver or
    /// network.
    #[cfg(test)]
    pub bootstrap_querier: Option<std::sync::Arc<dyn crate::dns::bootstrap::DohQuerier>>,
}

impl std::fmt::Debug for TestConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestConfig")
            .field("preflight_timeout", &self.preflight_timeout)
            .field("ss_connect_timeout", &self.ss_connect_timeout)
            .field("sentinel_read_timeout", &self.sentinel_read_timeout)
            .field("sentinels", &self.sentinels)
            .field("plugin_path_override", &self.plugin_path_override)
            .field("dns", &self.dns)
            .finish_non_exhaustive()
    }
}

impl TestConfig {
    pub fn production() -> Self {
        Self {
            preflight_timeout: Duration::from_secs(2),
            ss_connect_timeout: Duration::from_secs(5),
            sentinel_read_timeout: Duration::from_secs(5),
            sentinels: ["1.1.1.1:80".to_string(), "1.0.0.1:80".to_string()],
            plugin_path_override: None,
            dns: hole_common::config::DnsConfig::default(),
            #[cfg(test)]
            bootstrap_querier: None,
        }
    }
}

/// Run a one-shot test against the given server entry.
///
/// Walks three phases:
///
/// 1. Pre-flight DNS + raw TCP probe to detect "the server endpoint is plainly
///    unreachable" without spending the cost of a plugin spawn.
/// 2. Optional v2ray-plugin (or any SIP003 plugin) spawn. The
///    [`Plugin`] guard's `Drop` impl tears down the child process on every
///    exit path, including panics.
/// 3. A real shadowsocks tunnel via [`ProxyClientStream::connect`], with a
///    `HEAD /` request sent through to a public sentinel and the response
///    inspected. Two sentinels are tried in series; both must time out for the
///    "server cannot reach internet" diagnosis.
pub async fn run_server_test(entry: &ServerEntry, cfg: &TestConfig) -> ServerTestOutcome {
    let started = Instant::now();

    // Resolve the server hostname over PRIVATE DoH (never the OS resolver),
    // mirroring `start_inner`. Fail-closed unless `dns.allow_insecure_bootstrap`
    // → on failure return the existing `DnsFailed` outcome (host logged here,
    // not surfaced). Preflight connects to the raw resolved IP; only the plugin
    // handoff uses the bracket-safe `handoff_host` string.
    let resolved = {
        #[cfg(test)]
        {
            match &cfg.bootstrap_querier {
                Some(q) => crate::dns::bootstrap::resolve_via_doh_with(&entry.server, &cfg.dns, q.clone()).await,
                None => crate::dns::bootstrap::resolve_via_doh(&entry.server, &cfg.dns).await,
            }
        }
        #[cfg(not(test))]
        {
            crate::dns::bootstrap::resolve_via_doh(&entry.server, &cfg.dns).await
        }
    };
    let server_ip = match resolved {
        Ok(ip) => ip,
        Err(e) => {
            tracing::warn!(host = %entry.server, error = %e, "server_test: DoH bootstrap failed");
            return ServerTestOutcome::DnsFailed;
        }
    };
    let server_host = crate::dns::bootstrap::handoff_host(server_ip);

    // Phase 1: pre-flight DNS + TCP probe. Skipped for a QUIC server: its
    // public endpoint is UDP-only, so a raw TCP connect can't validate it (it
    // would always surface as a false TcpRefused/TcpTimeout). The full tunnel
    // handshake below still produces a correct diagnosis for an unreachable
    // QUIC server. See bindreams/hole#421.
    if server_endpoint_is_udp(entry) {
        debug!("server_test: skipping TCP preflight for UDP (quic) server endpoint");
    } else if let Err(out) = preflight(SocketAddr::new(server_ip, entry.server_port), cfg.preflight_timeout).await {
        return out;
    }

    let mut svr_cfg = match build_server_config(entry, server_ip) {
        Ok(c) => c,
        Err(detail) => return ServerTestOutcome::InternalError { detail },
    };

    // Phase 2: spawn plugin if configured. The guard's Drop kills the child.
    let _plugin_guard = match maybe_start_plugin(entry, &mut svr_cfg, &server_host, cfg).await {
        Ok(p) => p,
        Err(out) => return out,
    };

    // Phase 3: try each sentinel until one returns bytes or both fail.
    //
    // Diagnosis for v1 AEAD ciphers (the dominant deployment): on AEAD
    // decryption failure the rust SS server silently drains the client
    // forever (anti-probing `ignore_until_end`), so a HANDSHAKE FAILURE
    // produces a CLIENT TIMEOUT, not a clean EOF; whereas a successful
    // handshake with a failed upstream connect closes our tunnel side
    // cleanly, producing EOF. Hence: Timeout → most likely wrong creds;
    // EOF → most likely upstream failure. Two sentinels are tried in
    // series so a transient hiccup doesn't poison the diagnosis; the first
    // definitive timeout breaks early.
    //
    // AEAD-2022 caveat: 2022 ciphers close immediately on bad creds (RST
    // via SO_LINGER 0), producing EOF — misdiagnosed as
    // `ServerCannotReachInternet`. The v1 path is the priority.
    let context: SharedContext = Context::new_shared(ServerType::Local);
    let mut handshake_timeout_observed = false;
    for sentinel in &cfg.sentinels {
        match try_sentinel(Arc::clone(&context), &svr_cfg, sentinel, cfg).await {
            SentinelOutcome::Ok => {
                let raw = started.elapsed().as_millis();
                let latency_ms = u64::try_from(raw).unwrap_or(u64::MAX).max(1);
                debug_assert_ne!(latency_ms, LATENCY_VALIDATED_ON_CONNECT);
                return ServerTestOutcome::Reachable { latency_ms };
            }
            SentinelOutcome::Timeout => {
                handshake_timeout_observed = true;
                break;
            }
            SentinelOutcome::Mismatch { detail } => {
                return ServerTestOutcome::SentinelMismatch { detail };
            }
            SentinelOutcome::HandshakeClosed => continue,
            SentinelOutcome::Internal(detail) => {
                return ServerTestOutcome::InternalError { detail };
            }
        }
    }

    let tunnel_outcome = if handshake_timeout_observed {
        ServerTestOutcome::TunnelHandshakeFailed
    } else {
        ServerTestOutcome::ServerCannotReachInternet
    };

    reclassify_blocked(
        tunnel_outcome,
        // The DoH-resolved IP, never the proxy domain: the reachability probe
        // must not OS-resolve the hostname (that would reopen the DNS leak).
        &server_ip.to_string(),
        entry.server_port,
        entry.plugin.as_deref(),
        entry.plugin_opts.as_deref(),
        // One-shot probe; no caller-side cancel exists in run_server_test.
        &{
            #[allow(clippy::disallowed_methods)] // See clippy.toml: one-shot CancellationToken::new.
            CancellationToken::new()
        },
    )
    .await
}

// Helpers -------------------------------------------------------------------------------------------------------------

/// Per-sentinel result, internal to this module.
enum SentinelOutcome {
    Ok,
    HandshakeClosed,
    Mismatch { detail: String },
    Timeout,
    Internal(String),
}

/// If the tunnel test ended in a failure a network block can masquerade as,
/// probe the server out-of-band and upgrade to [`ServerTestOutcome::NetworkBlocked`]
/// when the probe confirms the network reset or dropped the connection. Every
/// other outcome passes through unchanged, so `PluginStartFailed`, `Reachable`,
/// etc. are preserved and a reachable server can never be falsely blocked.
async fn reclassify_blocked(
    tunnel_outcome: ServerTestOutcome,
    host: &str,
    port: u16,
    plugin: Option<&str>,
    plugin_opts: Option<&str>,
    cancel: &CancellationToken,
) -> ServerTestOutcome {
    match tunnel_outcome {
        ServerTestOutcome::TunnelHandshakeFailed | ServerTestOutcome::ServerCannotReachInternet => {
            if crate::reachability::probe_server_reachability(host, port, plugin, plugin_opts, cancel).await
                == crate::reachability::ReachabilityVerdict::Blocked
            {
                ServerTestOutcome::NetworkBlocked
            } else {
                tunnel_outcome
            }
        }
        other => other,
    }
}

/// True if the server's public endpoint is reached over UDP rather than TCP,
/// i.e. the configured plugin negotiates a QUIC transport (`mode=quic`). The
/// raw TCP preflight probe is meaningless for such an endpoint — there is no
/// TCP listener to connect to — so [`run_server_test`] skips it and lets the
/// full tunnel handshake produce the diagnosis. Covers a direct
/// v2ray-plugin/ex-ray QUIC server AND a galoshes server (which passes
/// `mode=quic` through to its embedded ex-ray). Shares the reachability probe's
/// transport classifier, so the two agree on what a QUIC endpoint is. See
/// bindreams/hole#421.
fn server_endpoint_is_udp(entry: &ServerEntry) -> bool {
    matches!(
        crate::reachability::classify_transport(entry.plugin.as_deref(), entry.plugin_opts.as_deref(), &entry.server),
        crate::reachability::ProbeTransport::Quic { .. }
    )
}

/// Raw-TCP-connect to the DoH-resolved `addr`. Returns `Err(outcome)` with a
/// granular reason on failure, or `Ok(())` on a successful connect (the stream
/// is dropped immediately — only the connect matters). DNS is already done by
/// the bootstrap resolver, so this connects to the raw IP (no name lookup,
/// no bracket parsing).
async fn preflight(addr: SocketAddr, timeout_dur: Duration) -> Result<(), ServerTestOutcome> {
    match timeout(timeout_dur, TcpStream::connect(addr)).await {
        Err(_) => Err(ServerTestOutcome::TcpTimeout),
        Ok(Err(e)) if e.kind() == ErrorKind::ConnectionRefused => Err(ServerTestOutcome::TcpRefused),
        Ok(Err(_)) => Err(ServerTestOutcome::TcpTimeout),
        Ok(Ok(_)) => Ok(()),
    }
}

/// Build a [`ServerConfig`] from a [`ServerEntry`], dialing the DoH-resolved
/// `server_ip` (not the hostname) so the bare-SS connect never OS-resolves the
/// proxy domain. The plugin (if any) is **not** set here — that happens in
/// [`maybe_start_plugin`], which overrides the address to the plugin's local
/// port after the plugin has bound it.
fn build_server_config(entry: &ServerEntry, server_ip: IpAddr) -> Result<ServerConfig, String> {
    let cipher: CipherKind = entry
        .method
        .parse()
        .map_err(|_| format!("unsupported cipher: {}", entry.method))?;
    ServerConfig::new(
        ServerAddr::SocketAddr(SocketAddr::new(server_ip, entry.server_port)),
        entry.password.clone(),
        cipher,
    )
    .map_err(|e| format!("invalid server config: {e}"))
}

/// If `entry.plugin` is set, spawn it via Garter and override `svr_cfg`'s
/// server address to point at the plugin chain's local port.
///
/// Returns `Ok(None)` if no plugin is configured (plain shadowsocks). Returns
/// the [`PluginChain`] guard otherwise — its [`Drop`] cancels the chain
/// (SIP003u graceful shutdown).
async fn maybe_start_plugin(
    entry: &ServerEntry,
    svr_cfg: &mut ServerConfig,
    server_host: &str,
    cfg: &TestConfig,
) -> Result<Option<crate::proxy::plugin::PluginChain>, ServerTestOutcome> {
    let Some(plugin_name) = entry.plugin.as_ref() else {
        return Ok(None);
    };

    let plugin_path = cfg
        .plugin_path_override
        .clone()
        .unwrap_or_else(|| resolve_plugin_path_inner(plugin_name, std::env::current_exe().ok()));

    // Hand the chain the DoH-resolved bracket-safe host (not the entry's
    // unresolved hostname), so garter recombines a valid `host:port`.
    // `build_server_config` always emits a `SocketAddr`, so the port is
    // guaranteed present here.
    let server_port = match svr_cfg.addr() {
        ServerAddr::SocketAddr(sa) => sa.port(),
        ServerAddr::DomainName(_host, port) => {
            debug_assert!(false, "build_server_config always emits SocketAddr, got DomainName");
            *port
        }
    };

    // `None` for state_dir: test-server probes are one-shot and die with
    // the bridge; no crash recovery tracking needed.
    // `diagnostic_tap = false`: one-shot probe; the user is connecting
    // for a quick test, not a debugging session. Per-conn tap metrics
    // would add noise without value here.
    // server_test is a one-shot probe with no caller-side cancel; pass a
    // never-signalled token so the chain runs to its natural conclusion.
    #[allow(clippy::disallowed_methods)]
    // One-shot CLI probe: no caller-side cancel exists. See clippy.toml CancellationToken::new rule.
    let chain_cancel = CancellationToken::new();
    // ech-doh = the first configured resolver's DoH URL, matching the bootstrap
    // path; empty `dns.servers` ⇒ no ech-doh ⇒ ECH off.
    let ech_doh = cfg.dns.servers.first().map(|ip| hole_common::doh_url(*ip));
    let chain = crate::proxy::plugin::start_plugin_chain(
        plugin_name,
        &plugin_path,
        entry.plugin_opts.as_deref(),
        server_host,
        server_port,
        None,
        None,
        false,
        &chain_cancel,
        ech_doh.as_deref(),
    )
    .await
    .map_err(|e| ServerTestOutcome::PluginStartFailed { detail: e.to_string() })?;

    // Override the server address to point at the plugin's local port.
    let local = chain.local_addr();
    *svr_cfg = ServerConfig::new(
        ServerAddr::SocketAddr(local),
        svr_cfg.password().to_owned(),
        svr_cfg.method(),
    )
    .map_err(|e| ServerTestOutcome::PluginStartFailed {
        detail: format!("failed to rebuild server config: {e}"),
    })?;

    debug!("server_test plugin bound at {local}");
    Ok(Some(chain))
}

/// Open a single shadowsocks tunnel through `svr_cfg` to `sentinel_str`,
/// write a `HEAD /` request, and inspect the first read.
async fn try_sentinel(
    ctx: SharedContext,
    svr_cfg: &ServerConfig,
    sentinel_str: &str,
    cfg: &TestConfig,
) -> SentinelOutcome {
    let sentinel: SocketAddr = match sentinel_str.parse() {
        Ok(a) => a,
        Err(e) => {
            return SentinelOutcome::Internal(format!("invalid sentinel {sentinel_str}: {e}"));
        }
    };
    let target = Address::SocketAddress(sentinel);

    let connect_fut = ProxyClientStream::connect(ctx, svr_cfg, target);
    let mut stream = match timeout(cfg.ss_connect_timeout, connect_fut).await {
        Err(_) => return SentinelOutcome::Internal("ss connect timed out".into()),
        Ok(Err(e)) => return SentinelOutcome::Internal(e.to_string()),
        Ok(Ok(s)) => s,
    };

    // Write the HEAD request. A write error here is not interesting on its
    // own — fall through to the read phase, which will surface the failure
    // as either HandshakeClosed (EOF) or Timeout.
    let _ = stream.write_all(HEAD_REQUEST).await;

    let mut buf = [0u8; 64];
    match timeout(cfg.sentinel_read_timeout, stream.read(&mut buf)).await {
        Err(_) => SentinelOutcome::Timeout,
        Ok(Err(_)) => SentinelOutcome::HandshakeClosed,
        Ok(Ok(0)) => SentinelOutcome::HandshakeClosed,
        Ok(Ok(n)) if buf[..n].starts_with(b"HTTP") => SentinelOutcome::Ok,
        Ok(Ok(n)) => {
            let detail = hex::encode(&buf[..n.min(32)]);
            SentinelOutcome::Mismatch { detail }
        }
    }
}

// `server_test_tests` test Hole's own `run_server_test` connectivity tester.
// They run on every Hole platform (Win+mac): the non-plugin cases are
// platform-agnostic, and the one plugin case uses BARE ex-ray server mode (no
// yamux, so no #197 — proven by the interop suite passing on Win+mac). #200
// (Windows DistHarness flakiness) is closed and does not apply to these
// in-process tests. Previously Linux-only-gated, so they ran on no CI job. See #435.
#[cfg(test)]
#[path = "server_test_tests.rs"]
mod server_test_tests;

// `server_endpoint_is_udp` is a pure function with no I/O, so unlike
// `server_test_tests` (which does connectivity I/O) its tests carry no platform
// caveat — they must run everywhere (the QUIC interop tests that depend on the
// preflight skip run on Windows too).
#[cfg(test)]
#[path = "server_test_preflight_tests.rs"]
mod server_test_preflight_tests;
