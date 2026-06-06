//! Client-side roundtrip driver: a garter client chain → `ProxyClientStream`
//! → fake sentinel. Replaces the suites' former dependency on `hole-bridge`'s
//! `server_test::run_server_test`, keeping the plugin tests decoupled from the
//! VPN bridge. Transport-agnostic: the client plugin's local listener is
//! always TCP loopback regardless of the client↔server transport
//! (WS/WS-TLS/QUIC live between the plugin processes).
//!
//! This crate sits outside the bridge's cooperative-cancel chain, so the lone
//! `CancellationToken::new` below carries a sanctioned per-call-site allow
//! (hole's `clippy.toml` `CancellationToken::new` rule).

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use shadowsocks::config::{ServerAddr, ServerConfig, ServerType};
use shadowsocks::context::{Context, SharedContext};
use shadowsocks::crypto::CipherKind;
use shadowsocks::relay::socks5::Address;
use shadowsocks::ProxyClientStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

const HEAD_REQUEST: &[u8] = b"HEAD / HTTP/1.0\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n";

/// Outcome of a single client roundtrip.
#[derive(Debug)]
pub enum Roundtrip {
    /// `HEAD /` traversed client-plugin → server-plugin → ss-server → sentinel
    /// and an `HTTP`-prefixed reply came all the way back.
    Reachable { latency_ms: u64 },
    /// The client chain failed to start (plugin spawn / readiness error).
    ChainFailed(String),
    /// The tunnel connect/read failed, timed out, or returned non-HTTP bytes.
    NotReachable(String),
}

/// Tunable timeouts. Every budget here is a failure-to-human bound for a wedged
/// *subprocess* (CLAUDE.md sync-exception class 2), NOT intra-process
/// synchronization — so each must be generous enough to never fire on a
/// legitimate-but-slow operation, only on a genuine hang.
///
/// The defaults are deliberately large because the data path crosses a plugin
/// chain that extracts and execs a freshly-built `ex-ray` on first run. With
/// **galoshes** on both ends, the server and client each extract their own
/// embedded `ex-ray` concurrently, and a cold host scanning those binaries
/// (Windows Defender on a just-built `ex-ray.exe`) can push the first
/// roundtrip past a single-digit-second bound — the observed flake was a
/// "read timed out" at ~5.9 s against a former 5 s `read_timeout`. These bounds
/// are not a timing assumption: on a healthy host the roundtrip completes in
/// milliseconds and the budget is never approached; on a true wedge the test
/// still fails in bounded time. Do NOT tighten them to "make the suite faster"
/// — a tight class-2 bound that flakes on cold-start is exactly the degenerate
/// timing-assumption the invariant forbids.
pub struct RoundtripConfig {
    pub ss_connect_timeout: Duration,
    pub read_timeout: Duration,
    pub ready_timeout: Duration,
}

impl Default for RoundtripConfig {
    fn default() -> Self {
        Self {
            ss_connect_timeout: Duration::from_secs(20),
            read_timeout: Duration::from_secs(20),
            ready_timeout: Duration::from_secs(30),
        }
    }
}

/// Drive one client roundtrip through `client_plugin_path` (started in client
/// mode with `client_opts`) to a `(server_host, server_port)` SS server that is
/// already fronted by a server-mode plugin, tunneling a `HEAD /` to `sentinel`.
///
/// `method`/`password` must match the SS server behind the plugin chain.
#[allow(clippy::too_many_arguments)] // test driver: eight plain inputs read clearer than a params struct here.
pub async fn run_roundtrip(
    client_plugin_path: &str,
    client_opts: Option<&str>,
    server_host: &str,
    server_port: u16,
    method: CipherKind,
    password: &str,
    sentinel: SocketAddr,
    cfg: &RoundtripConfig,
) -> Roundtrip {
    let started = Instant::now();

    // Local port for the client plugin to listen on. garter's allocator
    // absorbs Windows WSAEACCES excluded-range probe races.
    let local = match garter::chain::allocate_ports(1) {
        Ok(mut v) => v.remove(0),
        Err(e) => return Roundtrip::ChainFailed(format!("allocate local port: {e}")),
    };

    // Sanctioned: this crate is outside the bridge cancel chain (clippy.toml
    // `CancellationToken::new` rule); the chain owns this token's whole life.
    #[allow(clippy::disallowed_methods)]
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();
    let plugin = garter::BinaryPlugin::new(client_plugin_path, client_opts);
    let runner = garter::ChainRunner::new()
        .add(Box::new(plugin))
        .cancel_token(cancel.clone())
        .on_ready(ready_tx);

    let env = garter::PluginEnv {
        local_host: local.ip(),
        local_port: local.port(),
        remote_host: server_host.to_string(),
        remote_port: server_port,
        // `ChainRunner::run` ignores this field for a `BinaryPlugin` chain —
        // the child's `SS_PLUGIN_OPTIONS` is set from `BinaryPlugin::new`'s
        // `options` (see garter/src/binary.rs). Setting it here would be dead.
        plugin_options: None,
    };
    let handle = tokio::spawn(async move { runner.run(env).await });

    let listen = match timeout(cfg.ready_timeout, ready_rx).await {
        Ok(Ok(Ok(chain_ready))) => chain_ready.listen,
        Ok(Ok(Err(start_err))) => {
            cancel.cancel();
            let _ = handle.await;
            return Roundtrip::ChainFailed(format!("{start_err:?}"));
        }
        Ok(Err(_recv)) => {
            cancel.cancel();
            let _ = handle.await;
            return Roundtrip::ChainFailed("client plugin exited before becoming ready".into());
        }
        Err(_timeout) => {
            cancel.cancel();
            handle.abort();
            return Roundtrip::ChainFailed("client plugin did not become ready within budget".into());
        }
    };

    let outcome = run_tunnel(listen, method, password, sentinel, cfg, started).await;

    // Graceful chain teardown (SIP003u shutdown), then await the runner task.
    cancel.cancel();
    let _ = handle.await;
    outcome
}

async fn run_tunnel(
    listen: SocketAddr,
    method: CipherKind,
    password: &str,
    sentinel: SocketAddr,
    cfg: &RoundtripConfig,
    started: Instant,
) -> Roundtrip {
    let svr_cfg = match ServerConfig::new(ServerAddr::SocketAddr(listen), password.to_string(), method) {
        Ok(c) => c,
        Err(e) => return Roundtrip::NotReachable(format!("server config: {e}")),
    };
    let ctx: SharedContext = Context::new_shared(ServerType::Local);
    let target = Address::SocketAddress(sentinel);

    let mut stream = match timeout(
        cfg.ss_connect_timeout,
        ProxyClientStream::connect(ctx, &svr_cfg, target),
    )
    .await
    {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Roundtrip::NotReachable(format!("ss connect: {e}")),
        Err(_) => return Roundtrip::NotReachable("ss connect timed out".into()),
    };

    let _ = stream.write_all(HEAD_REQUEST).await;

    let mut buf = [0u8; 64];
    match timeout(cfg.read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(n)) if n > 0 && buf[..n].starts_with(b"HTTP") => {
            let latency_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX).max(1);
            Roundtrip::Reachable { latency_ms }
        }
        Ok(Ok(n)) if n > 0 => Roundtrip::NotReachable(format!("non-HTTP reply: {}", hex::encode(&buf[..n.min(16)]))),
        Ok(Ok(_)) => Roundtrip::NotReachable("EOF before any reply".into()),
        Ok(Err(e)) => Roundtrip::NotReachable(format!("read: {e}")),
        Err(_) => Roundtrip::NotReachable("read timed out".into()),
    }
}
