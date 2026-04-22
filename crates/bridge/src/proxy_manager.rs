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

use std::net::IpAddr;
use std::time::Instant;

use dump::{dump, DeriveDump};
use hole_common::protocol::{ProxyConfig, TunnelMode};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::{Routing, SystemRouting};

use crate::proxy::{build_ss_config, Proxy, ProxyError, RunningProxy, ShadowsocksProxy, TUN_DEVICE_NAME};

/// Non-secret diagnostic view of a proxy-start event — suitable for
/// YAML-shaped logging via `dump!`. Deliberately excludes password /
/// PSK fields; `ServerEntry` itself is not `Dump` so it cannot be
/// dropped into a log by mistake.
#[derive(DeriveDump)]
struct ProxyStartedDiag<'a> {
    server_ip: Option<IpAddr>,
    server_host: &'a str,
    server_port: u16,
    local_port: u16,
    tunnel_mode: &'a str,
    udp_proxy_available: bool,
    ipv6_bypass_available: bool,
}

// State ===============================================================================================================

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ProxyState {
    Stopped,
    Running,
}

// Running state =======================================================================================================

/// Per-cycle state owned only while a proxy is running.
///
/// **Field declaration order is load-bearing.** DNS drops first (restores
/// the user's OS DNS while routes + dispatcher + SS are still live so any
/// in-flight OS DNS queries egress the restored path), then dispatcher
/// (closes TUN, cancels handlers), then plugin chain (graceful stop via
/// SIGTERM/CTRL_BREAK), then routes (teardown commands), then proxy
/// (releases SS). `None` fields for SocksOnly mode where
/// routing/dispatcher/DNS are skipped, or when no plugin is configured.
struct RunningState<P: Proxy, R: Routing> {
    /// DNS interception: system-DNS apply + LocalDnsServer. Drops FIRST
    /// so the user's prior resolvers are restored before anything else
    /// tears down. `None` when DNS forwarder is disabled or in SocksOnly
    /// mode.
    #[allow(dead_code)]
    dns: Option<RunningDns>,
    /// TCP dispatcher — owns TUN device, smoltcp, and per-connection
    /// handler tasks. Drops SECOND. `None` in SocksOnly mode and under
    /// `#[cfg(test)]`.
    #[allow(dead_code)]
    dispatcher: Option<crate::dispatcher::Dispatcher>,
    /// Garter-managed plugin chain. Drops SECOND (cancel token triggers
    /// SIP003u graceful shutdown). `None` when no plugin is configured.
    #[allow(dead_code)]
    plugin_chain: Option<crate::proxy::plugin::PluginChain>,
    /// Installed routes. Dropped THIRD. `None` in SocksOnly mode.
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

/// DNS interception state held for the proxy's lifetime. Drop restores
/// system DNS (via `system::restore_all`) and clears `bridge-dns.json`,
/// then drops `local_dns_server` (aborts its tasks, releasing the
/// loopback port). Drop is synchronous because all underlying OS
/// commands block; this matches the existing `SystemRoutes::drop`
/// convention.
struct RunningDns {
    applied_prior: Vec<crate::dns_state::DnsPriorAdapter>,
    /// State directory for the `bridge-dns.json` persisted file. `None`
    /// when the caller didn't configure one (dev harness without a
    /// state dir — a case the existing plugin / routes paths also
    /// tolerate).
    state_dir: Option<std::path::PathBuf>,
    /// Held to keep the loopback `<ip>:53` bound and to keep the
    /// forwarder tasks running. Dropped after system DNS is restored.
    _local_dns_server: crate::dns::server::LocalDnsServer,
}

impl Drop for RunningDns {
    fn drop(&mut self) {
        let errors = crate::dns::system::restore_all(&self.applied_prior);
        if !errors.is_empty() {
            warn!(
                count = errors.len(),
                "RunningDns::drop: some adapters failed to restore"
            );
        }
        if let Some(dir) = &self.state_dir {
            if let Err(e) = crate::dns_state::clear(dir) {
                warn!(error = %e, "RunningDns::drop: failed to clear bridge-dns.json");
            }
        }
    }
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
    /// State directory for plugin PID crash recovery. `None` in tests
    /// that don't need crash recovery tracking.
    state_dir: Option<std::path::PathBuf>,
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
            state_dir: None,
        }
    }

    /// Set the state directory for plugin PID crash recovery.
    pub fn with_state_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.state_dir = Some(dir);
        self
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
    pub fn default_gateway(&self) -> Result<GatewayInfo, ProxyError> {
        self.routing.default_gateway().map_err(Into::into)
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
        debug!(
            local_port = config.local_port,
            tunnel_mode = ?config.tunnel_mode,
            plugin = ?config.server.plugin,
            server_host = %config.server.server,
            server_port = config.server.server_port,
            "ProxyManager::start_cancellable entered"
        );
        if self.running.is_some() {
            return Err(ProxyError::AlreadyRunning);
        }

        // Run start_inner in a select! against the cancel token.
        // `start_inner` is a free associated function — it does NOT
        // touch `self`, so dropping the future leaves `self` untouched.
        // All partial state is owned by the locally-constructed RAII
        // types inside start_inner and cleans up on drop.
        debug!("awaiting start_inner");
        let result: Result<RunningState<P, R>, ProxyError> = tokio::select! {
            biased;
            _ = cancel.cancelled() => Err(ProxyError::Cancelled),
            r = Self::start_inner(&self.proxy, &self.routing, config, self.state_dir.as_deref()) => r,
        };

        // Commit (or record the error) in the outer function, so the
        // only path that mutates `self.running = Some(..)` is strictly
        // after the select! has completed successfully.
        match result {
            Ok(state) => {
                let server_ip = state.server_ip;
                self.udp_proxy_available = state.udp_proxy_available;
                self.ipv6_bypass_available = state.ipv6_bypass_available;
                let udp_proxy_available = self.udp_proxy_available;
                let ipv6_bypass_available = self.ipv6_bypass_available;
                self.running = Some(state);
                self.active_config = Some(config.clone());
                self.last_error = None;
                let diag = ProxyStartedDiag {
                    server_ip,
                    server_host: &config.server.server,
                    server_port: config.server.server_port,
                    local_port: config.local_port,
                    tunnel_mode: tunnel_mode_label(&config.tunnel_mode),
                    udp_proxy_available,
                    ipv6_bypass_available,
                };
                info!(started = %dump!(&diag), "proxy started");
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
    /// [`tun_engine::routing::SystemRouting::install`] for the invariant.
    async fn start_inner(
        proxy: &P,
        routing: &R,
        config: &ProxyConfig,
        state_dir: Option<&std::path::Path>,
    ) -> Result<RunningState<P, R>, ProxyError> {
        debug!("start_inner entered");
        // Start plugin chain via Garter if a plugin is configured.
        let plugin_chain = if let Some(ref plugin_name) = config.server.plugin {
            let plugin_path = crate::proxy::config::resolve_plugin_path(plugin_name);
            let chain = crate::proxy::plugin::start_plugin_chain(
                plugin_name,
                &plugin_path,
                config.server.plugin_opts.as_deref(),
                &config.server.server,
                config.server.server_port,
                state_dir,
            )
            .await?;
            Some(chain)
        } else {
            None
        };

        // Build shadowsocks config. When a plugin chain is running,
        // point ss-service at the chain's local port.
        let plugin_local = plugin_chain.as_ref().map(|c| c.local_addr());
        let ss_config = build_ss_config(config, plugin_local)?;

        // SocksOnly mode: skip everything routing-related (wintun preload,
        // DNS resolution, gateway detection, route installation). Just start
        // the proxy tunnel — `build_ss_config` has already omitted the TUN
        // local instance, so `shadowsocks-service::local::Server::new` will
        // only bind the SOCKS5 listener.
        if matches!(config.tunnel_mode, TunnelMode::SocksOnly) {
            debug!(local_count = ss_config.local.len(), "calling proxy.start");
            let running_proxy = proxy.start(ss_config).await?;
            debug!("proxy.start returned Ok");

            // In-bridge SOCKS5 loopback self-test (#200 H2 vs H3 disambiguation).
            // When the test harness sets `HOLE_BRIDGE_SELF_TEST`, spawn a task
            // that connects to our own SOCKS5 port from inside the bridge.
            // Compare with the test process's external connect outcome:
            //   self-OK + ext-OK            → no bug
            //   self-OK + ext-WSAETIMEDOUT  → cross-process loopback broken (H2)
            //   self-WSAETIMEDOUT           → listener broken (H1/H3)
            //   self-ECONNREFUSED           → listener never opened (H3)
            // No pre-sleep: Server::new().await has already done bind+listen
            // so the kernel queues SYNs into the backlog regardless of whether
            // user-space accept() has been called. Any failure IS the signal.
            if std::env::var_os("HOLE_BRIDGE_SELF_TEST").is_some() {
                let port = config.local_port;
                tokio::spawn(async move {
                    let addr: std::net::SocketAddr = ([127, 0, 0, 1], port).into();
                    let started = std::time::Instant::now();
                    match tokio::time::timeout(std::time::Duration::from_secs(5), tokio::net::TcpStream::connect(addr))
                        .await
                    {
                        Ok(Ok(_stream)) => info!(
                            port,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "in-bridge self-test connect OK"
                        ),
                        Ok(Err(e)) => error!(
                            port,
                            error = %e,
                            os_code = ?e.raw_os_error(),
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "in-bridge self-test connect failed"
                        ),
                        Err(_) => error!(port, "in-bridge self-test connect timed out after 5s"),
                    }
                });
            }

            return Ok(RunningState {
                dns: None,
                dispatcher: None,
                plugin_chain,
                routes: None,
                proxy: running_proxy,
                server_ip: None,
                started_at: Instant::now(),
                udp_proxy_available: crate::proxy::plugin_supports_udp(config),
                ipv6_bypass_available: false,
            });
        }

        // Full mode: pre-load wintun.dll explicitly so we can give a
        // descriptive error if it's missing. See tun_engine::device::wintun.
        #[cfg(target_os = "windows")]
        tun_engine::device::wintun::ensure_loaded()?;

        // Resolve server hostname to IP.
        let server_ip = resolve_server_ip(&config.server.server, config.server.server_port).await?;

        // Query the OS default gateway via the routing provider.
        let gw_info = routing.default_gateway()?;

        // Compile filter rules.
        let ruleset = crate::filter::rules::RuleSet::from_user_rules(&config.filters);

        // Start the SS SOCKS5 proxy.
        let running_proxy = proxy.start(ss_config).await?;

        // DNS forwarder wiring. Must happen BEFORE Dispatcher::new so the
        // LocalDnsEndpoint can be passed in as a constructor argument —
        // HoleRouter has no mutable registration API. We wire the
        // forwarder's upstream through the just-started SS SOCKS5
        // listener (Socks5Connector) so user filter rules that Block the
        // resolver IP cannot strand our own queries. See `dns/mod.rs`.
        let (local_dns_server, local_dns_endpoint) =
            build_local_dns(&config.dns, config.local_port, gw_info.ipv6_available).await;

        // Start the dispatcher (owns TUN device + smoltcp). Skipped
        // under #[cfg(test)] because creating a TUN requires elevation.
        #[cfg(not(test))]
        let dispatcher = {
            let d = crate::dispatcher::Dispatcher::new(
                config.local_port,
                gw_info.interface_index,
                gw_info.ipv6_available,
                config.server.plugin.clone(),
                crate::proxy::plugin_supports_udp(config),
                ruleset,
                local_dns_endpoint,
            )?;
            Some(d)
        };
        #[cfg(test)]
        let dispatcher: Option<crate::dispatcher::Dispatcher> = {
            let _ = ruleset; // suppress unused warning
            let _ = local_dns_endpoint;
            None
        };

        // Install the routes — NOW traffic starts flowing to the TUN.
        let routes = routing.install(TUN_DEVICE_NAME, server_ip, gw_info.gateway_ip, &gw_info.interface_name)?;

        // Apply system DNS AFTER routes install so the OS "best-route to
        // DNS server" lookup resolves through the TUN (its DNS setting is
        // our loopback IP). Persist the prior state to `bridge-dns.json`
        // BEFORE mutating so a mid-apply crash leaves a recoverable file.
        let dns_state = if let Some(srv) = local_dns_server.as_ref() {
            apply_dns_settings(srv, &gw_info.interface_name, state_dir).await
        } else {
            None
        };

        let dns = local_dns_server.zip(dns_state).map(|(srv, applied)| RunningDns {
            applied_prior: applied,
            state_dir: state_dir.map(std::path::Path::to_path_buf),
            _local_dns_server: srv,
        });

        Ok(RunningState {
            dns,
            dispatcher,
            plugin_chain,
            routes: Some(routes),
            proxy: running_proxy,
            server_ip: Some(server_ip),
            started_at: Instant::now(),
            udp_proxy_available: crate::proxy::plugin_supports_udp(config),
            ipv6_bypass_available: gw_info.ipv6_available,
        })
    }

    pub async fn stop(&mut self) -> Result<(), ProxyError> {
        let Some(state) = self.running.take() else {
            return Ok(());
        };
        let RunningState {
            dns,
            dispatcher,
            plugin_chain,
            proxy,
            routes,
            server_ip: _,
            started_at: _,
            udp_proxy_available: _,
            ipv6_bypass_available: _,
        } = state;

        // 0. Restore system DNS FIRST (while routes + SS are still live
        // so any in-flight OS queries egress via the restored resolver).
        drop(dns);

        // 1. Shut down dispatcher (closes TUN, cancels all handlers).
        if let Some(mut d) = dispatcher {
            d.shutdown().await;
        }

        // 2. Stop plugin chain: kill tracked PIDs explicitly, then drop
        // (which cancels the chain and clears the state file).
        if let Some(ref chain) = plugin_chain {
            chain.kill_tracked();
        }
        drop(plugin_chain);

        // 3. Graceful proxy shutdown (stops SS SOCKS5).
        let res = proxy.stop().await;

        // 4. Routes tear down via RAII Drop.
        drop(routes);

        // Snapshot WFP + NDIS post-teardown. Emits warn when wintun-
        // related references remain in either layer. Cheap and
        // log-visible on user machines so bug reports carry the verdict
        // without needing debug mode. Bridge owns the diagnostics
        // module; tun-engine's SystemRoutes::drop can't call these.
        #[cfg(target_os = "windows")]
        {
            crate::diagnostics::wfp::log_snapshot("post-teardown");
            crate::diagnostics::ndis::log_snapshot("post-teardown");
        }

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

        // Structural equality check (ignoring filters). Any field that
        // changes which listeners are bound — or where they bind — must
        // appear here; otherwise toggling e.g. `proxy_http` on a running
        // bridge would take the hot-swap fast path and silently leave
        // the HTTP listener unbound. DnsConfig is included for the same
        // reason — a DnsConfig edit must force a full stop + start so
        // the LocalDnsServer rebinds with the new transport/servers.
        let structural_same = active.server == config.server
            && active.local_port == config.local_port
            && active.tunnel_mode == config.tunnel_mode
            && active.dns == config.dns
            && active.proxy_socks5 == config.proxy_socks5
            && active.proxy_http == config.proxy_http
            && active.local_port_http == config.local_port_http;

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

/// Stable human-readable label for a `TunnelMode` — used by
/// `ProxyStartedDiag` so the dump output doesn't vary with Debug
/// formatting changes.
fn tunnel_mode_label(mode: &TunnelMode) -> &'static str {
    match mode {
        TunnelMode::Full => "full",
        TunnelMode::SocksOnly => "socks_only",
    }
}

#[cfg(test)]
#[path = "proxy_manager_tests.rs"]
mod proxy_manager_tests;

// E2E test skip policy in CI:
//
// - **macOS**: the entire module is skipped. The galoshes test set
//   reliably hits #197 (internal port race in shadowsocks-service's
//   `PluginConfig`). The non-galoshes tests work but the coverage
//   uplift from running them in isolation on macOS wasn't judged worth
//   the module-level complexity — re-enable the module when #197 has
//   a custom server-side launcher.
//
// - **Windows**: the module runs, but the *galoshes* tests inside are
//   individually `#[cfg(not(target_os = "windows"))]`-gated because the
//   same #197 race fires here too. Everything else (the `ssserver_none`
//   + cipher roundtrips that were the #200 canonical repro) runs and
//   stays green. The `#[cfg]` gating lives in
//   `proxy_manager_e2e_tests.rs` next to each affected test so the
//   skip reason is co-located with the test.
//
// - **Linux**: the module runs fully. Linux CI is the only platform
//   where the full galoshes matrix is exercised.
//
// See #200 (H7 TCPIP investigation, now dormant with `diagnostics::etw`
// permanently on) and #197 (galoshes bind race, still open).
#[cfg(all(test, not(target_os = "macos")))]
#[path = "proxy_manager_e2e_tests.rs"]
mod proxy_manager_e2e_tests;

#[cfg(all(test, not(target_os = "macos")))]
#[path = "proxy_manager_listener_e2e_tests.rs"]
mod proxy_manager_listener_e2e_tests;

// DNS wiring helpers ==================================================================================================

/// Build the local DNS server + endpoint, if the config enables it. The
/// forwarder's upstream runs via [`crate::dns::socks5_connector::Socks5Connector`]
/// targeting the just-started SS SOCKS5 listener, so user filter rules
/// cannot strand our own queries.
async fn build_local_dns(
    dns_cfg: &hole_common::config::DnsConfig,
    local_ss_port: u16,
    ipv6_bypass_available: bool,
) -> (
    Option<crate::dns::server::LocalDnsServer>,
    Option<crate::endpoint::LocalDnsEndpoint>,
) {
    if !dns_cfg.enabled {
        return (None, None);
    }

    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use std::sync::Arc;

    let socks_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), local_ss_port);
    let connector = Arc::new(crate::dns::socks5_connector::Socks5Connector::new(socks_addr))
        as Arc<dyn crate::dns::connector::UpstreamConnector>;
    let forwarder = Arc::new(crate::dns::forwarder::DnsForwarder::new(
        dns_cfg.clone(),
        connector,
        ipv6_bypass_available,
    ));

    let server = match crate::dns::server::LocalDnsServer::bind_ladder(Arc::clone(&forwarder)).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "LocalDnsServer::bind_ladder failed; DNS forwarder disabled for this session");
            return (None, None);
        }
    };
    info!(addr = %server.addr(), "LocalDnsServer bound");

    let endpoint = if dns_cfg.intercept_udp53 {
        Some(crate::endpoint::LocalDnsEndpoint::new(Arc::clone(&forwarder)))
    } else {
        None
    };

    (Some(server), endpoint)
}

/// Capture prior system DNS for the adapters we're about to override,
/// persist the `bridge-dns.json` recovery file, then apply the loopback
/// IP. Returns the captured prior state on success, which
/// [`RunningDns::drop`] will later replay.
///
/// Async because the underlying platform functions shell out to
/// `netsh` / `networksetup` via `std::process::Command`. Keeping the
/// body sync today (see `dns::system::windows`) blocks a tokio worker
/// thread for the full duration, which #247 observed stalling the
/// `start_inner` path by ~10s. The `async fn` signature is a
/// Phase-1 no-behavior-change prerequisite for a Phase-4 swap to
/// `tokio::process::Command`.
///
/// Instrumented with an `info_span!("apply_dns_settings")` entered via
/// `.instrument()`. The happy-path exit logs
/// `info!(elapsed_ms = ..., "apply_dns_settings done")` so Phase-2
/// observation of #247 sees the total at INFO without needing to raise
/// the log level — per-sub-call `elapsed_ms` lines live at DEBUG inside
/// `dns::system::windows`.
async fn apply_dns_settings(
    server: &crate::dns::server::LocalDnsServer,
    upstream_iface: &str,
    state_dir: Option<&std::path::Path>,
) -> Option<Vec<crate::dns_state::DnsPriorAdapter>> {
    use tracing::Instrument;
    let span = tracing::info_span!("apply_dns_settings", upstream_iface = %upstream_iface);
    async { apply_dns_settings_body(server, upstream_iface, state_dir) }
        .instrument(span)
        .await
}

fn apply_dns_settings_body(
    server: &crate::dns::server::LocalDnsServer,
    upstream_iface: &str,
    state_dir: Option<&std::path::Path>,
) -> Option<Vec<crate::dns_state::DnsPriorAdapter>> {
    let started = Instant::now();
    #[cfg(any(target_os = "windows", target_os = "macos"))]
    let result = {
        use crate::dns::system;
        use crate::dns_state::{self, DnsState, SCHEMA_VERSION};
        use crate::proxy::TUN_DEVICE_NAME;

        let aliases: Vec<String> = vec![TUN_DEVICE_NAME.into(), upstream_iface.to_string()];
        let prior = match system::capture_adapters(&aliases) {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "system DNS capture failed; skipping apply");
                return None;
            }
        };

        // Persist BEFORE mutating so a mid-apply crash has a recoverable
        // file. Matches the `tun_engine::routing::SystemRouting::install`
        // precondition.
        if let Some(dir) = state_dir {
            let state = DnsState {
                version: SCHEMA_VERSION,
                chosen_loopback: server.addr(),
                adapters: prior.clone(),
            };
            if let Err(e) = dns_state::save(dir, &state) {
                warn!(error = %e, "dns_state::save failed; continuing without crash-recovery file");
            }
        }

        if let Err(e) = system::apply_loopback(&aliases, server.addr().ip()) {
            warn!(error = %e, "system DNS apply failed; DNS forwarder unreachable by OS clients");
            return None;
        }

        Some(prior)
    };
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    let result: Option<Vec<crate::dns_state::DnsPriorAdapter>> = {
        let _ = (server, upstream_iface, state_dir);
        None
    };

    info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "apply_dns_settings done"
    );
    result
}
