// Proxy trait surface + shadowsocks implementation.
//
// # Bridge test-isolation contract
//
// All production I/O that spawns a tunnel or touches shadowsocks runtime
// state in bridge code MUST route through the [`Proxy`] / [`RunningProxy`]
// traits defined here. Helper types whose `Drop` impls shut down a running
// proxy must do so through a `RunningProxy::stop` / `Drop` path on the
// associated running type, not by calling `shadowsocks_service` directly.
//
// The reason is test isolation. [`crate::proxy_manager::ProxyManager`] is
// generic over the `Proxy` trait so unit tests can substitute a mock that
// returns inert running handles. A helper that bypasses the trait cannot
// be intercepted by the mock and will exercise real production code from
// unit tests, with catastrophic consequences for test reliability and CI
// health. See the bindreams/hole#165 incident.
//
// Module layout:
//
// - [`config`] — `ProxyError`, `TUN_DEVICE_NAME`, `TUN_SUBNET`, and the
//   shadowsocks-service config builder. Not conceptually part of the
//   `Proxy` trait but lives in the same module tree because everything
//   proxy-related is funneled through this module.
// - [`shadowsocks`] — `ShadowsocksProxy` / `ShadowsocksRunning`, the
//   production implementation.

use shadowsocks_service::config::Config;

pub mod config;
pub mod shadowsocks;

pub use config::{build_ss_config, udp_proxy_available, ProxyError, TUN_DEVICE_NAME, TUN_SUBNET};
pub use shadowsocks::{ShadowsocksProxy, ShadowsocksRunning};

// Used by `server_test.rs` + `proxy_tests.rs`. Kept crate-private so
// external consumers can't rely on it.
pub(crate) use config::resolve_plugin_path_inner;

// Trait surface =======================================================================================================

/// A proxy tunnel implementation.
///
/// Calling [`start`](Self::start) spawns a fresh running-proxy handle
/// ([`Self::Running`]) per invocation. The factory (`Self`) is persistent
/// across multiple start/stop cycles and holds whatever configuration or
/// test instrumentation is needed; the running handle is single-use and
/// owns the spawned task.
///
/// The trait takes `&self` (not `&mut self`) on `start` so that
/// [`crate::proxy_manager::ProxyManager::start_inner`] can be a cancel-safe
/// future that operates on locally-owned RAII state without ever mutating
/// `ProxyManager`. See [`crate::proxy_manager`] for the cancellation
/// contract.
pub trait Proxy: Send + Sync {
    type Running: RunningProxy + Send;

    /// Spawn a new proxy tunnel from `config`. On success returns an
    /// owned [`Self::Running`] handle whose `Drop` aborts the spawned
    /// task if it is dropped without an explicit `stop().await`.
    fn start(&self, config: Config) -> impl std::future::Future<Output = Result<Self::Running, ProxyError>> + Send;
}

/// Handle on a running proxy tunnel returned from [`Proxy::start`].
///
/// Single-use: [`stop`](Self::stop) consumes `self`. Drop aborts the
/// underlying task best-effort. A type implementing `RunningProxy` MUST
/// also implement `Drop` such that the spawned task is aborted on drop —
/// this is the cancellation-safety primitive that
/// [`crate::proxy_manager::ProxyManager::start_inner`] relies on.
pub trait RunningProxy: Send + Sync {
    /// Cheap, synchronous check: is the underlying task still running?
    fn is_alive(&self) -> bool;

    /// Graceful shutdown: abort the task and await its result so errors
    /// can be reported to the caller. Idempotent with respect to
    /// subsequent `Drop` because `stop` consumes `self`.
    fn stop(self) -> impl std::future::Future<Output = Result<(), ProxyError>> + Send;
}

#[cfg(test)]
#[path = "proxy_tests.rs"]
mod proxy_tests;
