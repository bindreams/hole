// Proxy lifecycle manager — start/stop/reload orchestration.
//
// # Design notes (post-#165)
//
// `ProxyManager` is parameterized over two traits:
// - `P: Proxy`     — the proxy backend (production: `ShadowsocksProxy`).
// - `R: Routing`   — the OS routing provider (production: `SystemRouting`).
//
// Both traits return RAII associated types on success (`P::Running` /
// `R::Installed`) whose Drop impls clean up their respective side effects.
// This is what makes `start_inner` cancel-safe: if the start future is
// dropped mid-flight (for example because a `tokio::select!` cancel branch
// fired), the locally-owned `Running` / `Installed` values are dropped in
// reverse-declaration order — aborting the shadowsocks task and tearing
// down routes without the ProxyManager fields ever being mutated.
//
// A cycle's transient state lives in `Option<RunningState<P, R>>`. When
// `stop()` takes the state, the proxy handle is explicitly
// `stop().await`ed (so errors are reported), then the routes guard drops
// (tearing down). On a successful `start`, the full `RunningState` is
// committed to `self.running` from the synchronous match arm, after the
// `tokio::select!` that races the cancel token has already resolved.
//
// There are deliberately no getters for `proxy` or `routing` — test access
// to mock state happens via `Arc` clones captured before the mock is
// handed to `new`. Re-adding a getter would recreate the encapsulation
// smell the pre-#165 `pub fn backend(&self)` carried.

use crate::proxy::{build_ss_config, Proxy, ProxyError, RunningProxy, ShadowsocksProxy, TUN_DEVICE_NAME};
use crate::routing::{Routing, SystemRouting};
use hole_common::protocol::{ProxyConfig, TunnelMode};
use std::net::IpAddr;
use std::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

// State ===============================================================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyState {
    Stopped,
    Running,
}

// Running state =======================================================================================================

/// Per-cycle state owned only while a proxy is running.
///
/// **Field declaration order is load-bearing.** Dispatcher drops first
/// (closes TUN, cancels handlers), then routes (teardown commands
/// target a live TUN since the dispatcher already closed it), then
/// proxy (releases SS). `None` fields for SocksOnly mode where
/// routing/dispatcher are skipped.
struct RunningState<P: Proxy, R: Routing> {
    /// TCP dispatcher — owns TUN device, smoltcp, fake DNS, handler
    /// tasks. Drops FIRST. `None` in SocksOnly mode and under
    /// `#[cfg(test)]`.
    #[allow(dead_code)]
    dispatcher: Option<crate::dispatcher::Dispatcher>,
    /// Installed routes. Dropped SECOND. `None` in SocksOnly mode.
    #[allow(dead_code)]
    routes: Option<R::Installed>,
    /// Handle on the running proxy. Dropped LAST. Drop aborts
    /// the task (best-effort); supported graceful shutdown is via
    /// `stop().await` from [`ProxyManager::stop`].
    proxy: P::Running,
    server_ip: Option<IpAddr>,
    started_at: Instant,
    /// Whether UDP proxy relay is available (from plugin config).
    udp_proxy_available: bool,
    /// Whether IPv6 bypass is available (from gateway info).
    ipv6_bypass_available: bool,
}

// ProxyManager ========================================================================================================

pub struct ProxyManager<P: Proxy = ShadowsocksProxy, R: Routing = SystemRouting> {
    proxy: P,
    routing: R,
    running: Option<RunningState<P, R>>,
    last_error: Option<String>,
    /// Last successfully-started config. Used by `reload` to detect
    /// filter-only changes (hot-swap path vs full restart).
    active_config: Option<ProxyConfig>,
    /// Whether the server's plugin configuration supports UDP relay.
    udp_proxy_available: bool,
    /// Whether the upstream network has IPv6 connectivity.
    ipv6_bypass_available: bool,
}

impl<P: Proxy, R: Routing> ProxyManager<P, R> {
    pub fn new(proxy: P, routing: R) -> Self {
        Self {
            proxy,
            routing,
            running: None,
            last_error: None,
            active_config: None,
            udp_proxy_available: true,
            ipv6_bypass_available: true,
        }
    }

    pub fn state(&self) -> ProxyState {
        // ProxyState is retained (Stopped/Running) to preserve the IPC
        // `StatusResponse.running` field semantics unchanged for the GUI.
        if self.running.is_some() {
            ProxyState::Running
        } else {
            ProxyState::Stopped
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.running
            .as_ref()
            .map(|r| r.started_at.elapsed().as_secs())
            .unwrap_or(0)
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// Delegation for `handle_diagnostics`: expose the routing provider's
    /// default-gateway query without leaking the provider itself. This is
    /// NOT an encapsulation-breaking getter — it's a single capability
    /// intentionally surfaced for the diagnostics handler so tests can
    /// exercise the mock routing's gateway stub instead of hitting the
    /// host OS.
    pub fn default_gateway(&self) -> Result<crate::gateway::GatewayInfo, ProxyError> {
        self.routing.default_gateway()
    }

    /// Get the list of invalid (dropped) filter rules from the current ruleset.
    pub fn invalid_filters(&self) -> Vec<hole_common::protocol::InvalidFilter> {
        self.running
            .as_ref()
            .and_then(|r| r.dispatcher.as_ref())
            .map(|d| d.invalid_filters())
            .unwrap_or_default()
    }

    /// Whether UDP proxy relay is available with the current config.
    pub fn udp_proxy_available(&self) -> bool {
        self.udp_proxy_available
    }

    /// Whether IPv6 bypass is available on the upstream network.
    pub fn ipv6_bypass_available(&self) -> bool {
        self.ipv6_bypass_available
    }

    /// Non-cancellable convenience wrapper around
    /// [`start_cancellable`](Self::start_cancellable). Equivalent to
    /// passing a fresh, never-signaled `CancellationToken`. Used by
    /// existing callers (tests, `reload`) that don't need cancel
    /// semantics.
    pub async fn start(&mut self, config: &ProxyConfig) -> Result<(), ProxyError> {
        self.start_cancellable(config, CancellationToken::new()).await
    }

    /// Start the proxy with a caller-supplied `CancellationToken`.
    /// Signaling the token at any point during `start_inner` returns
    /// `Err(ProxyError::Cancelled)` and rolls back partial state (via
    /// the RAII guards inside `start_inner`) without mutating `self`.
    ///
    /// Three race scenarios are handled correctly:
    ///
    /// 1. **Cancel before any `start_inner` await.** `tokio::select!`
    ///    with `biased;` polls the cancel branch first, so an
    ///    already-cancelled token returns `Cancelled` without invoking
    ///    `start_inner` at all.
    /// 2. **Cancel mid-flight.** `select!` drops the `start_inner`
    ///    future, which runs every live RAII guard's `Drop` in
    ///    reverse-declaration order — the proxy task is aborted (by
    ///    `P::Running::drop`), routes are torn down (by
    ///    `R::Installed::drop`), and the state file is cleared (by the
    ///    same `R::Installed::drop`).
    /// 3. **Cancel right after `start_inner` returns `Ok(started)`.**
    ///    Commit to `self` happens in this outer function AFTER
    ///    `select!` has already yielded `Ok(started)`, so the late
    ///    cancel cannot race the commit. The started proxy is left
    ///    running; the client sees `Ok(())`. A caller that wanted to
    ///    cancel that late can follow up with an explicit stop.
    pub async fn start_cancellable(
        &mut self,
        config: &ProxyConfig,
        cancel: CancellationToken,
    ) -> Result<(), ProxyError> {
        if self.running.is_some() {
            return Err(ProxyError::AlreadyRunning);
        }

        // Run start_inner in a select! against the cancel token.
        // `start_inner` is a free associated function — it does NOT
        // touch `self`, so dropping the future leaves `self` untouched.
        // All partial state is owned by the locally-constructed RAII
        // types inside start_inner and cleans up on drop.
        let result: Result<RunningState<P, R>, ProxyError> = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ProxyError::Cancelled),
            r = Self::start_inner(&self.proxy, &self.routing, config) => r,
        };

        // Commit (or record the error) in the outer function, so the
        // only path that mutates `self.running = Some(..)` is strictly
        // after the select! has completed successfully.
        match result {
            Ok(state) => {
                let server_ip = state.server_ip;
                self.udp_proxy_available = state.udp_proxy_available;
                self.ipv6_bypass_available = state.ipv6_bypass_available;
                self.running = Some(state);
                self.active_config = Some(config.clone());
                self.last_error = None;
                info!(server_ip = ?server_ip, "proxy started");
                Ok(())
            }
            Err(ProxyError::Cancelled) => {
                // Do NOT set last_error on cancel — the user asked for it.
                info!("proxy start cancelled");
                Err(ProxyError::Cancelled)
            }
            Err(e) => {
                self.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Produce a [`RunningState`] without touching `self`. All partial
    /// state is owned by local RAII values so that dropping this future
    /// at any `.await` point unwinds cleanly:
    ///
    /// 1. `P::Running` — on drop, aborts the spawned proxy task.
    /// 2. `R::Installed` — on drop, tears down routes and clears the
    ///    crash-recovery state file.
    ///
    /// CRITICAL ORDERING: the routing provider is responsible for
    /// persisting the recovery state BEFORE mutating routes. A panic
    /// or SIGKILL between `setup_routes` and `SystemRoutes`
    /// construction would otherwise leak routes with no on-disk record,
    /// defeating crash recovery on next startup. See
    /// [`crate::routing::SystemRouting::install`] for the invariant.
    async fn start_inner(proxy: &P, routing: &R, config: &ProxyConfig) -> Result<RunningState<P, R>, ProxyError> {
        // Build shadowsocks config (SOCKS5 only, no TUN).
        let ss_config = build_ss_config(config)?;

        // SocksOnly mode: skip everything routing-related (wintun preload,
        // DNS resolution, gateway detection, route installation). Just start
        // the proxy tunnel — `build_ss_config` has already omitted the TUN
        // local instance, so `shadowsocks-service::local::Server::new` will
        // only bind the SOCKS5 listener.
        if matches!(config.tunnel_mode, TunnelMode::SocksOnly) {
            let running_proxy = proxy.start(ss_config).await?;
            return Ok(RunningState {
                dispatcher: None,
                routes: None,
                proxy: running_proxy,
                server_ip: None,
                started_at: Instant::now(),
                udp_proxy_available: crate::proxy::udp_proxy_available(config),
                ipv6_bypass_available: false,
            });
        }

        // Full mode: pre-load wintun.dll explicitly so we can give a
        // descriptive error if it's missing. See crates/bridge/src/wintun.rs.
        #[cfg(target_os = "windows")]
        crate::wintun::ensure_loaded()?;

        // Resolve server hostname to IP.
        let server_ip = resolve_server_ip(&config.server.server, config.server.server_port).await?;

        // Query the OS default gateway via the routing provider.
        let gw_info = routing.default_gateway()?;

        // Discover upstream DNS servers BEFORE routes are installed, so
        // queries use the real upstream path (not the TUN).
        let dns_servers = crate::dispatcher::upstream_dns::discover_dns_servers()
            .map_err(|e| ProxyError::Gateway(format!("DNS discovery failed: {e}")))?;

        // Compile filter rules.
        let ruleset = crate::filter::rules::RuleSet::from_user_rules(&config.filters);

        // Start the SS SOCKS5 proxy.
        let running_proxy = proxy.start(ss_config).await?;

        // Start the dispatcher (owns TUN device + smoltcp). Skipped
        // under #[cfg(test)] because creating a TUN requires elevation.
        #[cfg(not(test))]
        let dispatcher = {
            let d = crate::dispatcher::Dispatcher::new(
                config.local_port,
                gw_info.interface_index,
                gw_info.ipv6_available,
                crate::proxy::udp_proxy_available(config),
                ruleset,
                &dns_servers,
            )?;
            Some(d)
        };
        #[cfg(test)]
        let dispatcher: Option<crate::dispatcher::Dispatcher> = {
            let _ = (ruleset, dns_servers); // suppress unused warnings
            None
        };

        // Install the routes — NOW traffic starts flowing to the TUN.
        let routes = routing.install(TUN_DEVICE_NAME, server_ip, gw_info.gateway_ip, &gw_info.interface_name)?;

        Ok(RunningState {
            dispatcher,
            routes: Some(routes),
            proxy: running_proxy,
            server_ip: Some(server_ip),
            started_at: Instant::now(),
            udp_proxy_available: crate::proxy::udp_proxy_available(config),
            ipv6_bypass_available: gw_info.ipv6_available,
        })
    }

    pub async fn stop(&mut self) -> Result<(), ProxyError> {
        let Some(state) = self.running.take() else {
            return Ok(());
        };
        let RunningState {
            dispatcher,
            proxy,
            routes,
            server_ip: _,
            started_at: _,
            udp_proxy_available: _,
            ipv6_bypass_available: _,
        } = state;

        // 1. Shut down dispatcher (closes TUN, cancels all handlers).
        if let Some(mut d) = dispatcher {
            d.shutdown().await;
        }

        // 2. Graceful proxy shutdown (stops SS SOCKS5).
        let res = proxy.stop().await;

        // 3. Routes tear down via RAII Drop.
        drop(routes);

        // Clear any error from a previous failed start. See issue #142.
        self.last_error = None;
        self.active_config = None;
        self.udp_proxy_available = true;
        self.ipv6_bypass_available = true;
        info!("proxy stopped");
        res
    }

    pub async fn reload(&mut self, config: &ProxyConfig) -> Result<(), ProxyError> {
        let Some(ref active) = self.active_config else {
            // Not running: just start.
            return self.start(config).await;
        };

        // Structural equality check (ignoring filters).
        let structural_same = active.server == config.server
            && active.local_port == config.local_port
            && active.tunnel_mode == config.tunnel_mode;

        if structural_same {
            // Fast path: hot-swap filter rules without restart.
            let new_ruleset = crate::filter::rules::RuleSet::from_user_rules(&config.filters);
            if let Some(ref state) = self.running {
                if let Some(ref dispatcher) = state.dispatcher {
                    dispatcher.swap_rules(new_ruleset);
                }
            }
            self.active_config = Some(config.clone());
            info!("filter rules hot-swapped");
            Ok(())
        } else {
            // Slow path: full stop + start.
            self.stop().await?;
            self.start(config).await
        }
    }

    /// Sync health check: detects a proxy task that exited on its own
    /// (e.g. shadowsocks panic or upstream connection failure).
    ///
    /// **Error-discard note**: this function cannot await the dead
    /// handle, so the underlying task's `io::Result` is discarded.
    /// Callers that need the task's error must use `stop().await`
    /// instead. The graceful duplication-fix from pre-#165 is complete
    /// (this is now one line) but the sync-vs-async limitation is
    /// fundamental to Rust — we do not make `check_health` async
    /// because every caller would have to be made async too.
    pub fn check_health(&mut self) {
        if let Some(state) = &self.running {
            if !state.proxy.is_alive() {
                error!("proxy task exited unexpectedly");
                self.last_error = Some("proxy task exited unexpectedly".into());
                self.running = None; // Drop tears down routes + clears state file
                self.active_config = None;
                self.udp_proxy_available = true;
                self.ipv6_bypass_available = true;
            }
        }
    }
}

// DNS resolution ======================================================================================================

async fn resolve_server_ip(host: &str, port: u16) -> Result<IpAddr, ProxyError> {
    // Try parsing as IP address first (return as-is, including IPv6 literals)
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip);
    }

    // DNS lookup — prefer IPv4 to ensure bypass route compatibility with IPv4 gateway
    let addrs: Vec<_> = tokio::net::lookup_host(format!("{host}:{port}"))
        .await
        .map_err(|e| ProxyError::DnsResolution {
            host: host.to_owned(),
            source: e,
        })?
        .collect();

    let addr = addrs
        .iter()
        .find(|a| a.is_ipv4())
        .or_else(|| addrs.first())
        .ok_or_else(|| ProxyError::DnsResolution {
            host: host.to_owned(),
            source: std::io::Error::other("no addresses returned"),
        })?;

    Ok(addr.ip())
}

#[cfg(test)]
#[path = "proxy_manager_tests.rs"]
mod proxy_manager_tests;
