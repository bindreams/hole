// `ShadowsocksProxy` — production implementation of the `Proxy` /
// `RunningProxy` traits backed by `shadowsocks_service::local::Server`.
//
// Each running proxy owns a dedicated tokio runtime (`SsRuntime`): upstream
// tears `Server::run` and its sub-servers down through three nested
// `Drop` -> `abort()` layers with no handle Hole can join, so a runtime-level
// join is what makes `stop()` (and `Drop`) actually release the listener
// sockets before returning. See CONTRIBUTING.md#proxy-shutdown-contract.

use shadowsocks_service::config::Config;
use shadowsocks_service::net::FlowStat;
use std::io;
use std::sync::Arc;
use tokio::task::JoinHandle;
use tracing::{debug, error, warn};

use super::{Proxy, ProxyError, RunningProxy, TrafficTotals};

/// Join `rt`: blocks until every task on it has been dropped, which is what
/// closes the listener sockets. `drop(Runtime)` is legal only off a thread
/// that is not inside a runtime, so this always hops to a scratch thread; on
/// a multi-thread worker, `block_in_place` releases the core first so the
/// join does not starve the ambient runtime. See
/// CONTRIBUTING.md#proxy-shutdown-contract for the full derivation.
fn join_runtime(rt: tokio::runtime::Runtime) {
    let join = move || {
        std::thread::spawn(move || drop(rt))
            .join()
            .expect("the scratch thread only drops a Runtime");
    };
    match tokio::runtime::Handle::try_current() {
        Ok(h) if matches!(h.runtime_flavor(), tokio::runtime::RuntimeFlavor::MultiThread) => {
            tokio::task::block_in_place(join)
        }
        _ => join(),
    }
}

/// Owns the dedicated runtime a single shadowsocks server runs on.
///
/// `worker_threads(4)` is a reduction from the ambient runtime's
/// `available_parallelism()` — unmeasured; see
/// CONTRIBUTING.md#proxy-shutdown-contract for the tradeoff and the
/// falsifier.
struct SsRuntime(Option<tokio::runtime::Runtime>);

impl SsRuntime {
    fn new() -> io::Result<Self> {
        // Re-install the constructing thread's dispatcher on every worker:
        // `set_default_in_current_thread`'s current-thread assertion can't
        // see across this runtime boundary, so without this hand-off the ss
        // task's tracing events would be silently dropped in tests (not in
        // production, which installs a subscriber globally).
        let dispatcher = tracing::dispatcher::get_default(|d| d.clone());
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .thread_name("hole-ss")
            .worker_threads(4)
            .on_thread_start(move || {
                #[allow(
                    clippy::disallowed_methods,
                    reason = "hands the constructing thread's global dispatcher to an SsRuntime worker; not the per-test assertion target #302 guards against, see CONTRIBUTING.md#proxy-shutdown-contract"
                )]
                let guard = tracing::dispatcher::set_default(&dispatcher);
                std::mem::forget(guard); // one guard per worker; the runtime owns the thread's whole life
            })
            .build()?;
        Ok(Self(Some(rt)))
    }

    /// Panics after `take()`. Only `stop()` takes, and it never spawns after.
    fn handle(&self) -> &tokio::runtime::Handle {
        self.0.as_ref().expect("SsRuntime handle used after take()").handle()
    }

    /// `&mut self`, not `self`: `ShadowsocksRunning` has its own `Drop` and
    /// cannot move fields out.
    fn take(&mut self) -> Option<tokio::runtime::Runtime> {
        self.0.take()
    }
}

impl Drop for SsRuntime {
    fn drop(&mut self) {
        // Gives every Drop path (exposed paths 3-6, not just stop()) the
        // same port-release guarantee — see CONTRIBUTING.md#proxy-shutdown-contract.
        if let Some(rt) = self.0.take() {
            join_runtime(rt);
        }
    }
}

/// Production `Proxy` implementation: spawns a `shadowsocks_service::local::Server`
/// task on `start(config)` and returns a [`ShadowsocksRunning`] handle that
/// owns the spawned task for the duration of its lifetime.
///
/// `ShadowsocksProxy` itself is stateless (zero-sized) — per-session state
/// (the dedicated runtime, the spawned task, the traffic counters) lives in
/// the returned [`ShadowsocksRunning`]'s [`SsRuntime`], not here. Keeping it
/// as a named type — rather than a free function or an associated constant —
/// gives [`crate::proxy_manager::ProxyManager`] a generic type parameter
/// `P: Proxy` that can be substituted for a mock in tests.
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
        // Built first and bound to a local: every subsequent early return
        // and future-drop runs `SsRuntime::drop`, which joins it.
        let runtime = SsRuntime::new().map_err(ProxyError::Runtime)?;
        let (tx, rx) = tokio::sync::oneshot::channel::<io::Result<Arc<FlowStat>>>();

        debug!("spawning shadowsocks server.run() task");
        let handle = runtime.handle().spawn(async move {
            // First log inside the spawned task: a gap between the
            // "spawning" and "entered" timestamps in the bridge log
            // means the hole-ss runtime is starved.
            debug!("shadowsocks server task entered");
            debug!("calling shadowsocks_service::local::Server::new");
            // `Server::new` must run on the dedicated runtime, not the
            // caller's — tokio I/O resources are bound to the runtime that
            // created them.
            let server = match shadowsocks_service::local::Server::new(config).await {
                Ok(server) => server,
                Err(e) => {
                    // Expected to fail when `start`'s future was dropped
                    // (the receiver went away) — not an error.
                    let _ = tx.send(Err(e));
                    return Ok(());
                }
            };
            debug!("shadowsocks_service Server constructed");
            // The balancer's ServiceContext is cloned from the same template
            // as every local instance's, so they all share one Arc<FlowStat>
            // (every proxied TCP stream / UDP association increments it).
            // This is the only public handle to the server's traffic counters.
            let flow_stat = server.server_balancer().context().flow_stat();
            let _ = tx.send(Ok(flow_stat));

            // server.run() contains an infinite accept loop — it should never
            // return under normal operation. If it does, the SOCKS5 listener
            // is dead and all proxied connections will fail. Log loudly so the
            // bridge log captures the exact error (or the surprising Ok).
            let result = server.run().await;
            match &result {
                Ok(()) => warn!("shadowsocks server task returned Ok — expected to run forever"),
                Err(e) => error!(error = %e, "shadowsocks server task exited with error"),
            }
            result
        });

        let flow_stat = match rx.await {
            Ok(Ok(flow_stat)) => flow_stat,
            Ok(Err(e)) => return Err(ProxyError::Runtime(e)),
            Err(_) => {
                return Err(ProxyError::Runtime(io::Error::other(
                    "shadowsocks server task ended before reporting its startup result",
                )));
            }
        };

        Ok(ShadowsocksRunning {
            handle: Some(handle),
            flow_stat,
            runtime,
        })
    }
}

/// RAII handle on a running shadowsocks tunnel.
///
/// Both cleanup paths close every socket the proxy bound: each owns an
/// [`SsRuntime`], whose `Drop` joins the dedicated runtime the tunnel runs
/// on — the join is what actually releases the listeners. They differ only
/// in whether the outer task's own exit is observed:
///
/// - [`RunningProxy::stop`] — aborts the task, `await`s it (surfacing
///   task-internal panics as `ProxyError::Runtime`), then joins the runtime.
///   Preferred whenever the caller has an `.await` point.
/// - `Drop` — aborts the task and joins the runtime without observing the
///   task's own exit. Used when there is no `.await` point to host a
///   graceful stop (e.g. an error-path `?` in `start_inner`, or a cancelled
///   `tokio::select!` in `start_cancellable`).
pub struct ShadowsocksRunning {
    handle: Option<JoinHandle<io::Result<()>>>,
    /// Shared with every local instance inside the running `Server` —
    /// SOCKS5/HTTP listeners and UDP associations all increment it.
    flow_stat: Arc<FlowStat>,
    runtime: SsRuntime,
}

#[cfg(test)]
impl ShadowsocksRunning {
    /// Test-only constructor: build a fresh `SsRuntime` and hand its
    /// `Handle` to `spawn`, so the Drop/stop contract can be exercised
    /// without binding real shadowsocks listeners. Production code never
    /// reaches `ShadowsocksRunning` except through
    /// [`ShadowsocksProxy::start`].
    pub(crate) fn from_task<F>(spawn: F) -> Self
    where
        F: FnOnce(&tokio::runtime::Handle) -> JoinHandle<io::Result<()>>,
    {
        let runtime = SsRuntime::new().expect("build SsRuntime for test");
        let handle = spawn(runtime.handle());
        Self {
            handle: Some(handle),
            flow_stat: Arc::new(FlowStat::new()),
            runtime,
        }
    }
}

impl RunningProxy for ShadowsocksRunning {
    fn is_alive(&self) -> bool {
        self.handle.as_ref().is_some_and(|h| !h.is_finished())
    }

    fn traffic_totals(&self) -> TrafficTotals {
        TrafficTotals {
            bytes_in: self.flow_stat.rx(),
            bytes_out: self.flow_stat.tx(),
        }
    }

    /// Graceful shutdown: aborts the task, awaits its result (distinguishing
    /// cancellation from a panic), then joins the dedicated runtime — every
    /// socket the proxy bound is closed before this returns.
    async fn stop(mut self) -> Result<(), ProxyError> {
        let outcome = match self.handle.take() {
            Some(h) => {
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
            None => Ok(()),
        };
        // Classify the task's own exit before shutting the runtime down —
        // shutting down first would collapse every outcome into "cancelled".
        if let Some(rt) = self.runtime.take() {
            join_runtime(rt);
        }
        outcome
    }
}

impl Drop for ShadowsocksRunning {
    fn drop(&mut self) {
        // Aborts the outer task; the `SsRuntime` field's own `Drop` (run
        // automatically once this fn returns) joins the runtime, so this
        // path releases every bound socket exactly like `stop()` does. No
        // `.await` is possible here (Drop is sync), so task-internal panics
        // are not observed; callers who need that signal use `stop().await`.
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

#[cfg(test)]
#[path = "shadowsocks_tests.rs"]
mod shadowsocks_tests;
