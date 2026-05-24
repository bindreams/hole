// `ShadowsocksProxy` — production implementation of the `Proxy` /
// `RunningProxy` traits backed by `shadowsocks_service::local::Server`.

use shadowsocks_service::config::Config;
use std::io;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use super::{Proxy, ProxyError, RunningProxy};

/// Production `Proxy` implementation: spawns a `shadowsocks_service::local::Server`
/// task on `start(config)` and returns a [`ShadowsocksRunning`] handle that
/// owns the spawned task for the duration of its lifetime.
///
/// `ShadowsocksProxy` itself is stateless (zero-sized). Keeping it as a named
/// type — rather than a free function or an associated constant — gives
/// [`crate::proxy_manager::ProxyManager`] a generic type parameter `P: Proxy`
/// that can be substituted for a mock in tests.
#[derive(Debug, Default)]
pub struct ShadowsocksProxy;

impl ShadowsocksProxy {
    pub fn new() -> Self {
        Self
    }
}

impl Proxy for ShadowsocksProxy {
    type Running = ShadowsocksRunning;

    async fn start(&self, config: Config) -> Result<Self::Running, ProxyError> {
        debug!("calling shadowsocks_service::local::Server::new");
        let server = shadowsocks_service::local::Server::new(config)
            .await
            .map_err(ProxyError::Runtime)?;
        debug!("shadowsocks_service Server constructed");
        debug!("spawning shadowsocks server.run() task");
        let handle = tokio::spawn(async move {
            // First log inside the spawned task: a gap between
            // "spawning" and "entered" timestamps in the bridge log
            // means the tokio runtime is starved (#200 H1 hypothesis).
            debug!("shadowsocks server task entered");
            let result = server.run().await;
            // server.run() contains an infinite accept loop — it should never
            // return under normal operation. If it does, the SOCKS5 listener
            // is dead and all proxied connections will fail. Log loudly so the
            // bridge log captures the exact error (or the surprising Ok).
            match &result {
                Ok(()) => warn!("shadowsocks server task returned Ok — expected to run forever"),
                Err(e) => error!(error = %e, "shadowsocks server task exited with error"),
            }
            result
        });
        Ok(ShadowsocksRunning { handle: Some(handle) })
    }
}

/// RAII handle on a running shadowsocks tunnel.
///
/// Two cleanup paths, both safe:
///
/// - [`RunningProxy::stop`] — graceful shutdown. Aborts the task and
///   `await`s the handle, surfacing task-internal panics as
///   `ProxyError::Runtime`. Preferred when the caller has an `.await`
///   point (the normal Stop request flow).
/// - `Drop` — cancel-unwind cleanup. Aborts the task best-effort and
///   returns immediately. Used when the value goes out of scope under
///   an error-path `?` (e.g. the #388 forwarder self-test gate inside
///   `start_inner`) or when the surrounding future is cancelled (e.g.
///   the `tokio::select!` in `start_cancellable`), where there is no
///   `.await` point to host a graceful stop.
///
/// Both paths abort the task; the only thing `Drop` loses vs `stop()`
/// is the ability to observe task-internal panics. See bindreams/hole#393
/// for the incident that motivated documenting the dual contract.
pub struct ShadowsocksRunning {
    handle: Option<JoinHandle<io::Result<()>>>,
}

#[cfg(test)]
impl ShadowsocksRunning {
    /// Test-only constructor: wrap a freshly-spawned task so the Drop
    /// contract can be exercised without binding real shadowsocks
    /// listeners. Production code never reaches `ShadowsocksRunning`
    /// except through [`ShadowsocksProxy::start`].
    pub(crate) fn from_handle(handle: JoinHandle<io::Result<()>>) -> Self {
        Self { handle: Some(handle) }
    }
}

impl RunningProxy for ShadowsocksRunning {
    fn is_alive(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    /// Graceful shutdown: aborts the task and awaits its result. Distinguishes
    /// cancellation (expected from `abort()`) from panics (wrapped as
    /// `ProxyError::Runtime`). Strict improvement over the pre-refactor
    /// `let _ = handle.await;` which silently dropped task results.
    async fn stop(mut self) -> Result<(), ProxyError> {
        let Some(h) = self.handle.take() else {
            return Ok(());
        };
        h.abort();
        match h.await {
            Ok(r) => r.map_err(ProxyError::Runtime),
            Err(e) if e.is_cancelled() => Ok(()),
            Err(e) if e.is_panic() => Err(ProxyError::Runtime(io::Error::other(format!(
                "proxy task panicked: {e}"
            )))),
            Err(e) => Err(ProxyError::Runtime(io::Error::other(e))),
        }
    }
}

impl Drop for ShadowsocksRunning {
    fn drop(&mut self) {
        // Cancel-unwind cleanup. `h.abort()` is fire-and-forget — the
        // runtime delivers cancellation to the task on the next poll.
        // No `await` is possible here (Drop is sync), so task-internal
        // panics are not observed; callers who need that signal use
        // `stop().await`. See the type doc and bindreams/hole#393.
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

#[cfg(test)]
#[path = "shadowsocks_tests.rs"]
mod shadowsocks_tests;
