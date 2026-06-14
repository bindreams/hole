// Proxy lifecycle manager — start/stop/reload orchestration.
//
// # Design notes
//
// `ProxyManager` is parameterized over two traits:
// - `P: Proxy`     — the proxy backend (production: `ShadowsocksProxy`).
// - `R: Routing`   — the OS routing provider (production: `SystemRouting`).
//
// Both traits return RAII associated types on success (`P::Running` /
// `R::Installed`) whose Drop impls clean up their respective side effects.
// RAII unwind covers the Err-return path of `start_inner` — if any phase
// returns Err, locally-owned guards drop in reverse-declaration order,
// aborting the shadowsocks task and tearing down routes without the
// ProxyManager fields ever being mutated.
//
// **Cancellation is cooperative.** A `CancellationToken` is threaded
// *into* `start_inner` and every long-running phase observes it
// cooperatively. Future-drop cancellation (an outer `tokio::select!`)
// can't preempt a phase that needs async cleanup (DNS apply) — once a
// sync FFI is on a tokio worker the future can't be preempted. RAII Drop
// is retained as the catastrophic / panic teardown safety net only.
//
// A cycle's transient state lives in `Option<RunningState<P, R>>`. When
// `stop()` takes the state, the proxy handle is explicitly
// `stop().await`ed (so errors are reported), then the routes guard drops
// (tearing down). On a successful `start`, the full `RunningState` is
// committed to `self.running` strictly after `start_inner` returns
// `Ok(state)`; the cooperative-cancel path returns `Err(Cancelled)`
// before reaching the commit.
//
// There are deliberately no getters for `proxy` or `routing` — test access
// to mock state happens via `Arc` clones captured before the mock is
// handed to `new`. A getter would recreate an encapsulation smell.

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;
use util::port_alloc;

use dump::{dump, DeriveDump};
use hole_common::protocol::{ProxyConfig, TunnelMode};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::{Routing, SystemRouting};

use crate::dns::system::{Dns, DnsApplied, DnsError, SystemDns};
use crate::proxy::{
    build_ss_config, Proxy, ProxyError, RunningProxy, ShadowsocksProxy, TrafficTotals, TUN_DEVICE_NAME,
};

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

/// Derive whether `Proxy`-routed UDP flows can be carried through the
/// tunnel, from a live plugin chain's sitrep-reported transports.
///
/// - `Some(transports)` — a plugin chain is running; UDP is available iff
///   the end-to-end transport intersection it reported includes
///   [`garter::Transports::UDP`].
/// - `None` — no plugin chain; the raw SOCKS5 path always carries UDP, so
///   UDP is available.
///
/// Takes `Option<Transports>` rather than `Option<&PluginChain>` so it is
/// trivially unit-testable without standing up a real chain (which owns a
/// `JoinHandle` + `CancellationToken`).
fn udp_available_from_chain(transports: Option<garter::Transports>) -> bool {
    match transports {
        Some(t) => t.contains(garter::Transports::UDP),
        None => true,
    }
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
/// **Tear-down order is load-bearing.** `ProxyManager::stop` runs the
/// shutdown sequence in this order:
/// 1. `dns_applied.shutdown().await` — restores OS DNS while routes +
///    dispatcher + SS are still live so any in-flight OS DNS queries
///    egress the restored path.
/// 2. `dispatcher.shutdown().await` — closes TUN, cancels handlers.
/// 3. `plugin_chain` drop — graceful stop via SIGTERM/CTRL_BREAK.
/// 4. `proxy.stop().await` — releases SS task.
/// 5. `routes` drop — RAII teardown.
///
/// `None` fields for SocksOnly mode where routing / dispatcher / DNS are
/// skipped, or when no plugin is configured.
struct RunningState<P: Proxy, R: Routing, D: Dns> {
    /// DNS interception guard: holds the captured prior DNS state.
    /// `stop()` awaits [`DnsApplied::shutdown`] on this BEFORE dropping
    /// anything else so the OS sees its restored resolvers while routes
    /// are still live. `None` when DNS forwarder is disabled or in
    /// SocksOnly mode.
    #[allow(dead_code)]
    dns: Option<D::Applied>,
    /// TCP dispatcher — owns TUN device, smoltcp, and per-connection
    /// handler tasks. `None` in SocksOnly mode and under `#[cfg(test)]`.
    #[allow(dead_code)]
    dispatcher: Option<crate::dispatcher::Dispatcher>,
    /// Garter-managed plugin chain; drop triggers SIP003u graceful
    /// shutdown via the cancel token. `None` when no plugin is configured.
    #[allow(dead_code)]
    plugin_chain: Option<crate::proxy::plugin::PluginChain>,
    /// Installed routes. `None` in SocksOnly mode.
    #[allow(dead_code)]
    routes: Option<R::Installed>,
    /// Handle on the running proxy. Drop aborts the task (best-effort);
    /// supported graceful shutdown is via `stop().await` from
    /// [`ProxyManager::stop`].
    proxy: P::Running,
    server_ip: Option<IpAddr>,
    started_at: Instant,
    /// Whether UDP proxy relay is available (from plugin config).
    udp_proxy_available: bool,
    /// Whether IPv6 bypass is available (from gateway info).
    ipv6_bypass_available: bool,
    /// Rate window for [`ProxyManager::sample_traffic`]. `None` until the
    /// first sample after start. Lives here so it structurally cannot
    /// survive a stop/start cycle — the counters it derives deltas from
    /// reset with the `Server`.
    traffic_window: Option<TrafficWindow>,
}

/// Previous [`ProxyManager::sample_traffic`] observation.
///
/// `sampled_at` is a `tokio::time::Instant` (not std) so speed tests can
/// drive the window deterministically with `tokio::time::pause`/`advance`
/// instead of sleeping; outside a paused runtime it is the same monotonic
/// clock.
struct TrafficWindow {
    sampled_at: tokio::time::Instant,
    totals: TrafficTotals,
    speed_in_bps: u64,
    speed_out_bps: u64,
}

/// One traffic sample: cumulative totals plus speeds over the window
/// since the previous sample.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct TrafficMetrics {
    pub totals: TrafficTotals,
    pub speed_in_bps: u64,
    pub speed_out_bps: u64,
}

// ProxyManager ========================================================================================================

pub struct ProxyManager<P: Proxy = ShadowsocksProxy, R: Routing = SystemRouting, D: Dns = SystemDns> {
    proxy: P,
    routing: R,
    dns: D,
    running: Option<RunningState<P, R, D>>,
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

impl<P: Proxy, R: Routing> ProxyManager<P, R, SystemDns> {
    pub fn new(proxy: P, routing: R) -> Self {
        Self::new_with_dns(proxy, routing, SystemDns::default())
    }
}

impl<P: Proxy, R: Routing, D: Dns> ProxyManager<P, R, D> {
    /// Construct a [`ProxyManager`] with an explicit [`Dns`] provider.
    /// Used by Layer-1 unit tests to substitute `MockDns` so cancel /
    /// shutdown propagation through `start_inner` can be observed
    /// without touching the OS resolver. Production code uses
    /// [`Self::new`].
    pub fn new_with_dns(proxy: P, routing: R, dns: D) -> Self {
        Self {
            proxy,
            routing,
            dns,
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

    /// Test seam: shift `started_at` backwards by `by`. Lets uptime
    /// tests assert "after N seconds elapsed" without sleeping or
    /// injecting a clock abstraction. No-op if not currently running.
    /// See bindreams/hole#383.
    #[cfg(test)]
    pub fn shift_started_at_for_test(&mut self, by: std::time::Duration) {
        if let Some(r) = self.running.as_mut() {
            r.started_at = r
                .started_at
                .checked_sub(by)
                .expect("shift_started_at_for_test: arithmetic underflow");
        }
    }

    /// Sample cumulative tunnel-traffic totals and compute speeds over
    /// the window since the previous sample. Each call advances the
    /// window — the IPC metrics poll is the sampling event. `None` when
    /// stopped; the first sample after a start reports 0 bps.
    pub fn sample_traffic(&mut self) -> Option<TrafficMetrics> {
        let running = self.running.as_mut()?;
        let totals = running.proxy.traffic_totals();
        let now = tokio::time::Instant::now();
        let (speed_in_bps, speed_out_bps) = match &running.traffic_window {
            None => (0, 0),
            Some(w) => {
                let elapsed = now.duration_since(w.sampled_at);
                if elapsed.is_zero() {
                    // Same-instant resample: nothing to divide by. Reuse
                    // the previous speeds and keep the window so the next
                    // real sample still has a usable base.
                    return Some(TrafficMetrics {
                        totals,
                        speed_in_bps: w.speed_in_bps,
                        speed_out_bps: w.speed_out_bps,
                    });
                }
                // Counters are monotonic within one RunningState: same
                // handle, fetch_add only, and the window dies with the state.
                debug_assert!(
                    totals.bytes_in >= w.totals.bytes_in && totals.bytes_out >= w.totals.bytes_out,
                    "traffic counters must be monotonic within a running session"
                );
                (
                    speed_bps(totals.bytes_in - w.totals.bytes_in, elapsed),
                    speed_bps(totals.bytes_out - w.totals.bytes_out, elapsed),
                )
            }
        };
        running.traffic_window = Some(TrafficWindow {
            sampled_at: now,
            totals,
            speed_in_bps,
            speed_out_bps,
        });
        Some(TrafficMetrics {
            totals,
            speed_in_bps,
            speed_out_bps,
        })
    }

    /// Test seam: rewind the traffic window's `sampled_at` by `by`, making
    /// the next sample's `elapsed > 0` a structural guarantee instead of a
    /// bet on clock granularity. Callers rewind by a tiny duration (1ms) —
    /// large rewinds can underflow past the `Instant` epoch (system boot).
    /// No-op when not running or before the first sample.
    #[cfg(test)]
    pub fn shift_traffic_window_for_test(&mut self, by: std::time::Duration) {
        if let Some(w) = self.running.as_mut().and_then(|r| r.traffic_window.as_mut()) {
            w.sampled_at = w
                .sampled_at
                .checked_sub(by)
                .expect("shift_traffic_window_for_test: rewound past the Instant epoch");
        }
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
        #[allow(clippy::disallowed_methods)]
        // Non-cancellable shim: callers explicitly opt out of cancel semantics. See clippy.toml CancellationToken::new rule.
        let token = CancellationToken::new();
        self.start_cancellable(config, token).await
    }

    /// Start the proxy with a caller-supplied `CancellationToken`.
    /// Signaling the token at any point during `start_inner` returns
    /// `Err(ProxyError::Cancelled)` and rolls back partial state (via
    /// the RAII guards inside `start_inner`) without mutating `self`.
    ///
    /// **Cooperative cancellation.** The token is threaded *into*
    /// `start_inner` and every long-running phase observes it
    /// cooperatively — see the `start_inner` doc and the per-phase
    /// cancel-aware wrappers. (Future-drop cancellation — racing
    /// `start_inner` against the token in an outer `tokio::select!` —
    /// cannot preempt a phase whose inner future never yields, e.g. a
    /// sync FFI on a tokio worker.)
    ///
    /// Three race scenarios are handled correctly:
    ///
    /// 1. **Cancel before `start_inner` starts.** The first phase's
    ///    `cancel.is_cancelled()` check fires immediately and returns
    ///    `Cancelled` without doing any work.
    /// 2. **Cancel mid-flight.** Each phase's cancel-aware wrapper
    ///    returns `Cancelled` cooperatively; locally-owned RAII guards
    ///    drop in reverse-declaration order as the function unwinds.
    /// 3. **Cancel right after `start_inner` returns `Ok(started)`.**
    ///    Commit to `self` happens after `start_inner` yields, so the
    ///    late cancel cannot race the commit. The started proxy is left
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

        // `start_inner` is a free associated function — it does NOT
        // touch `self`, so any cancel-driven unwind leaves `self`
        // untouched. All partial state is owned by the locally-
        // constructed RAII types inside start_inner and cleans up on
        // drop. The cancel token is threaded *into* start_inner instead
        // of being raced against it (#397); this prevents the
        // "uncancellable sync phase" foot-gun where a future that
        // doesn't yield blocks the outer select! from observing cancel.
        debug!("awaiting start_inner");
        let result: Result<RunningState<P, R, D>, ProxyError> = Self::start_inner(
            &self.proxy,
            &self.routing,
            &self.dns,
            config,
            self.state_dir.as_deref(),
            cancel,
        )
        .await;

        // Commit (or record the error) in the outer function, so the
        // only path that mutates `self.running = Some(..)` is strictly
        // after start_inner has completed successfully.
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

    /// Produce a [`RunningState`] without touching `self`.
    ///
    /// **Cooperative cancellation.** Each long-running phase
    /// observes the supplied `cancel` token and returns
    /// `Err(ProxyError::Cancelled)` cooperatively. Earlier RAII guards
    /// drop in reverse-declaration order when the function returns Err,
    /// tearing down anything that was constructed before the cancel
    /// observation:
    ///
    /// 1. `PluginChain` — on drop, cancels its garter token and clears
    ///    the plugin state file.
    /// 2. `P::Running` — on drop, aborts the spawned proxy task.
    /// 3. `R::Installed` — on drop, tears down routes and clears the
    ///    crash-recovery state file.
    ///
    /// Per-phase cancellation strategy:
    /// - **Phase 1 (plugin chain)**: the bridge cancel is threaded into
    ///   `start_plugin_chain`, which derives child tokens for each
    ///   attempt and races readiness against cancel.
    /// - **Phase 2 (proxy.start)**: `tokio::select!` around
    ///   `proxy.start(ss_config)`. Drop-on-cancel is sound — Proxy
    ///   implementations own no async cleanup obligations on an
    ///   in-flight start.
    /// - **Phase 3 (build_local_dns)**: builds the in-TUN endpoint +
    ///   forwarder synchronously; the outer `tokio::select!` against
    ///   cancel re-emits Cancelled canonically.
    /// - **Phase 4 (forwarder self-test)**: cooperative — the token is
    ///   threaded into `run_forwarder_self_test` which checks it
    ///   between retry attempts and races the per-attempt forward.
    /// - **Phases 5–6 (Dispatcher::new, routing.install)**: sync; cancel
    ///   observed at phase boundary only (`if cancel.is_cancelled()`).
    ///   These calls are millisecond-scale; mid-call preemption isn't
    ///   needed.
    /// - **Phase 7 (dns.apply)**: cooperative — the token is threaded
    ///   into [`Dns::apply`], which observes cancel between per-adapter
    ///   FFIs. A cancel arriving mid-apply triggers an inline-restore
    ///   of any partially-applied adapters before `DnsError::Cancelled`
    ///   propagates back as `ProxyError::Cancelled`. The
    ///   `SystemDnsApplied` guard is returned only on the `Ok` path,
    ///   so the `DebugDropBomb` is never armed during an Err unwind.
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
        dns: &D,
        config: &ProxyConfig,
        state_dir: Option<&std::path::Path>,
        cancel: CancellationToken,
    ) -> Result<RunningState<P, R, D>, ProxyError> {
        debug!("start_inner entered");
        // Pre-flight: short-circuit a pre-cancelled token before any work.
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        // Phase 1: start plugin chain via Garter if a plugin is configured.
        // `start_plugin_chain` threads `cancel` through to its readiness
        // wait + bind_ephemeral retries.
        let plugin_chain = if let Some(ref plugin_name) = config.server.plugin {
            let plugin_path = crate::proxy::config::resolve_plugin_path(plugin_name);
            let chain = crate::proxy::plugin::start_plugin_chain(
                plugin_name,
                &plugin_path,
                config.server.plugin_opts.as_deref(),
                &config.server.server,
                config.server.server_port,
                state_dir,
                config.diagnostic_plugin_tap,
                &cancel,
            )
            .await?;
            Some(chain)
        } else {
            None
        };

        // Cancel observed between phases — required because a
        // pre-cancelled token can slip past `start_plugin_chain` when
        // there is no plugin configured (the `if let` branch above is
        // skipped entirely).
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }

        // UDP availability: when a plugin chain is running, use the
        // transports it reported via sitrep; with no plugin the raw SOCKS5
        // path carries UDP, so default to available. Computed once here (in
        // scope for both the SocksOnly and Full branches below) so all
        // three start sites read the same live value.
        let udp_proxy_available = udp_available_from_chain(plugin_chain.as_ref().map(|c| c.transports()));

        // Build shadowsocks config. When a plugin chain is running,
        // point ss-service at the chain's local port.
        //
        // Pure-VPN starts (Full mode, no user-facing listeners, #459)
        // cannot build the config yet — the internal SOCKS5 port is
        // allocated by bind_ephemeral in phase 2 — so run the same
        // typed validation now to keep rejects fast and typed, before
        // any Full-mode preamble work.
        let plugin_local = plugin_chain.as_ref().map(|c| c.local_addr());
        let pure_vpn = matches!(config.tunnel_mode, TunnelMode::Full) && !config.proxy_socks5;
        let ss_config = if pure_vpn {
            crate::proxy::validate_proxy_config(config)?;
            None
        } else {
            Some(build_ss_config(config, plugin_local, None)?)
        };

        // SocksOnly mode: skip everything routing-related (wintun preload,
        // DNS resolution, gateway detection, route installation). Just start
        // the proxy tunnel — `build_ss_config` has already omitted the TUN
        // local instance, so `shadowsocks-service::local::Server::new` will
        // only bind the SOCKS5 listener.
        if matches!(config.tunnel_mode, TunnelMode::SocksOnly) {
            let ss_config = ss_config.expect("SocksOnly start always has a prebuilt ss_config");
            debug!(local_count = ss_config.local.len(), "calling proxy.start");
            // Phase 2 (SocksOnly): race proxy.start against cancel.
            let running_proxy = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(ProxyError::Cancelled),
                r = proxy.start(ss_config) => r?,
            };
            debug!("proxy.start returned Ok");

            // Harness-only (HOLE_BRIDGE_SELF_TEST): connect to our own SOCKS5
            // port from inside the bridge to distinguish a broken cross-process
            // loopback from a broken/never-opened listener. Compare with the
            // test process's external connect outcome:
            //   self-OK + ext-OK            → no bug
            //   self-OK + ext-WSAETIMEDOUT  → cross-process loopback broken
            //   self-WSAETIMEDOUT           → listener broken
            //   self-ECONNREFUSED           → listener never opened
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
                udp_proxy_available,
                ipv6_bypass_available: false,
                traffic_window: None,
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

        // CRITICAL ORDERING:
        //
        //   0. (above) plugin_chain spawn  — plugin subprocess is alive
        //      from this point. NOT a system-state mutation (the chain
        //      Drop SIGTERMs it on unwind) but the user sees the
        //      plugin process briefly.
        //   1. proxy.start  — binds local SS listener
        //   2. build_local_dns  — builds the in-TUN LocalDnsEndpoint +
        //      forwarder (Err on degenerate dns.enabled + empty servers)
        //   3. GATE: run_forwarder_self_test  — Err here means the plugin
        //      chain cannot reach upstream. RAII unwind drops
        //      running_proxy + plugin_chain locally. NO system state
        //      (routes / system DNS / TUN adapter) is mutated.
        //   4. Dispatcher::new  — only NOW does LocalDnsEndpoint become
        //      reachable through the cascade
        //   5. routing.install  — TUN routes go live; OS DNS to the
        //      advertised resolver IPs starts routing into the TUN
        //   6. Dns::apply  — OS adapter DNS pointed at the resolver IPs
        //
        // Reordering steps 3..=6 re-introduces a dead-tunnel DNS hijack
        // with the GUI reporting "Running". The
        // start_blocks_on_forwarder_self_test_failure test catches the
        // most likely regression (asserting routing.install was NOT
        // called when the gate fails).

        // Phase 2 (Full mode): start the SS SOCKS5 proxy, racing the
        // start future against cancel. Drop on Running aborts the SS
        // task on cancel via P::Running::drop.
        //
        // The TUN data plane rides the user-facing SOCKS5 listener when
        // it is enabled. On a pure-VPN start (no user-facing listeners,
        // #459) the internal SOCKS5 instance binds an ephemeral loopback
        // port instead, so nothing is bound on the user-configured
        // ports. TCP+UDP: the SOCKS5 instance is always TcpAndUdp.
        let (socks5_port, running_proxy) = if let Some(ss_config) = ss_config {
            let running = tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(ProxyError::Cancelled),
                r = proxy.start(ss_config) => r?,
            };
            (config.local_port, running)
        } else {
            let bind = port_alloc::bind_ephemeral(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                port_alloc::Protocols::TCP | port_alloc::Protocols::UDP,
                |port| async move {
                    let ss_config =
                        build_ss_config(config, plugin_local, Some(port)).map_err(proxy_start_err_to_io_err)?;
                    proxy.start(ss_config).await.map_err(proxy_start_err_to_io_err)
                },
            );
            tokio::select! {
                biased;
                _ = cancel.cancelled() => return Err(ProxyError::Cancelled),
                r = bind => match r {
                    Ok((port, running)) => (port, running),
                    Err(_) if cancel.is_cancelled() => return Err(ProxyError::Cancelled),
                    Err(e) => return Err(ProxyError::Runtime(e)),
                },
            }
        };

        // Phase 3: build the in-TUN DNS endpoint + forwarder. Err on the
        // degenerate `dns.enabled && servers.is_empty()` config. Returns the
        // forwarder Arc so the gate can drive it without re-plumbing. The
        // outer `tokio::select!` re-emits Cancelled canonically.
        let (local_dns_endpoint, forwarder) = tokio::select! {
            biased;
            _ = cancel.cancelled() => return Err(ProxyError::Cancelled),
            r = build_local_dns(&config.dns, socks5_port, gw_info.ipv6_available, cancel.clone()) => r?,
        };

        // Phase 4: blocking forwarder self-test gate. Runs synchronously
        // BEFORE Dispatcher::new / routing.install / Dns::apply.
        // On Err, the locally-owned `running_proxy` Drop aborts the SS
        // task and `plugin_chain` (further up the stack) Drop SIGTERMs
        // the chain. System state is untouched. `run_forwarder_self_test`
        // observes cancel cooperatively between retry attempts and races
        // each per-attempt forward against it (#397).
        if let Some(fwd) = forwarder.as_ref() {
            let started = std::time::Instant::now();
            let outcome = run_forwarder_self_test(
                std::sync::Arc::clone(fwd),
                config.dns.servers.clone(),
                config.diagnostic_plugin_tap,
                cancel.clone(),
            )
            .await;
            outcome.into_result(started.elapsed().as_millis() as u64)?;
        }

        // Phase 5: cancel checkpoint before Dispatcher::new (sync, cannot
        // be preempted mid-call once entered).
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        // Start the dispatcher (owns TUN device + smoltcp). Skipped
        // under #[cfg(test)] because creating a TUN requires elevation.
        #[cfg(not(test))]
        let dispatcher = {
            let d = crate::dispatcher::Dispatcher::new(
                socks5_port,
                gw_info.interface_index,
                gw_info.ipv6_available,
                config.server.plugin.clone(),
                udp_proxy_available,
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

        // Phase 6: cancel checkpoint before routing.install (sync; mid-
        // call preemption isn't structurally possible — netsh/route
        // shell-outs are uninterruptible from our process).
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        // Install the routes — NOW traffic starts flowing to the TUN.
        let routes = routing.install(TUN_DEVICE_NAME, server_ip, gw_info.gateway_ip, &gw_info.interface_name)?;

        // Phase 7: apply system DNS AFTER routes install so the OS
        // "best-route to DNS server" lookup resolves through the TUN.
        // We advertise the configured upstream resolver IPs — OS UDP/53 to
        // them routes into hole-tun and is intercepted by the in-TUN
        // LocalDnsEndpoint; OS TCP/53 falls through the proxy cascade to the
        // real resolver over the tunnel. (No loopback :53 server.)
        // Pass the FULL list, not a v4 filter: `set_servers` advertises both
        // the v4 and v6 families from their own entries (an unconfigured
        // family is left untouched), so a mixed or v6 resolver list is carried
        // end-to-end on both platforms. Persist + apply are cancel-aware inside
        // `Dns::apply`. Non-cancel Io failures → warn! + None.
        let dns_applied = if forwarder.is_some() {
            let advertise_ips: Vec<IpAddr> = config.dns.servers.clone();
            // Capture runs on upstream only; the TUN was created by
            // `routing.install` above so its prior is definitionally
            // "defaults". Apply runs on both so the OS's best-route-to-DNS
            // lookup lands on a TUN-routed resolver IP.
            let capture_aliases = vec![gw_info.interface_name.clone()];
            let apply_aliases = vec![TUN_DEVICE_NAME.into(), gw_info.interface_name.clone()];
            match dns
                .apply(
                    advertise_ips,
                    capture_aliases,
                    apply_aliases,
                    state_dir.map(std::path::Path::to_path_buf),
                    cancel.clone(),
                )
                .await
            {
                Ok(a) => Some(a),
                Err(DnsError::Cancelled) => return Err(ProxyError::Cancelled),
                Err(DnsError::Io(e)) => {
                    warn!(error = %e, "system DNS apply failed; in-tunnel DNS unreachable by OS clients");
                    None
                }
            }
        } else {
            None
        };

        Ok(RunningState {
            dns: dns_applied,
            dispatcher,
            plugin_chain,
            routes: Some(routes),
            proxy: running_proxy,
            server_ip: Some(server_ip),
            started_at: Instant::now(),
            udp_proxy_available,
            ipv6_bypass_available: gw_info.ipv6_available,
            traffic_window: None,
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
            traffic_window: _,
        } = state;

        // 0. Restore system DNS FIRST (while routes + SS are still live
        // so any in-flight OS queries egress via the restored resolver).
        // Async shutdown — defuses the `DebugDropBomb` in `SystemDnsApplied`
        // before the field drops. Skipping the await would panic in debug
        // builds (catching missed-shutdown bugs at first test run).
        if let Some(mut d) = dns {
            d.shutdown().await;
        }

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
        // reason — a DnsConfig edit must force a full stop + start so the
        // DnsForwarder + in-TUN LocalDnsEndpoint are rebuilt with the new
        // transport/servers and the OS is re-advertised the new resolver IPs.
        let structural_same = active.server == config.server
            && active.local_port == config.local_port
            && active.tunnel_mode == config.tunnel_mode
            && active.dns == config.dns
            && active.proxy_socks5 == config.proxy_socks5
            && active.proxy_http == config.proxy_http
            && active.local_port_http == config.local_port_http
            // #388: toggling diagnostic_plugin_tap wraps/unwraps the
            // plugin chain in TapPlugin, which is fixed at chain
            // construction. Hot-swap can't rebuild the chain — force
            // full stop + start so the new tap state takes effect.
            && active.diagnostic_plugin_tap == config.diagnostic_plugin_tap;

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
    /// instead. Not made async because every caller would then have to
    /// be made async too.
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

// Pure-VPN ephemeral bind =============================================================================================

/// Map errors from a pure-VPN ephemeral bind attempt into `io::Error`
/// for [`port_alloc::bind_ephemeral`]'s retry classification.
/// `Runtime` unwraps to its `io::Error` so a genuine listener bind race
/// (`AddrInUse` from shadowsocks-service's in-process bind) is
/// classified by `is_bind_race` and retried on a fresh port; every
/// other variant is deterministic for a given config (validation,
/// cipher, plugin name) and becomes a non-retryable
/// `io::Error::other`. The IPC layer surfaces `ProxyError` to clients
/// as a message string, so wrapping the round-trip in
/// `ProxyError::Runtime` preserves the user-visible text.
fn proxy_start_err_to_io_err(e: ProxyError) -> std::io::Error {
    match e {
        ProxyError::Runtime(io) => io,
        other => std::io::Error::other(other.to_string()),
    }
}

// Traffic rate ========================================================================================================

/// `bytes` over `elapsed` as bits per second. u128 intermediate so the
/// multiply cannot overflow; saturates at u64::MAX.
fn speed_bps(bytes: u64, elapsed: std::time::Duration) -> u64 {
    let bits = bytes as u128 * 8 * 1_000_000_000;
    let nanos = elapsed.as_nanos().max(1);
    u64::try_from(bits / nanos).unwrap_or(u64::MAX)
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

// E2E test platform policy:
//
// - **Non-galoshes** DistHarness e2e (`e2e_none`, lifecycle, cipher, and the
//   listener-selection tests) run on every Hole platform (Win+mac).
// - **galoshes-fronted** tests front a galoshes *server* via the garter
//   `ChainRunner` launcher (`plugin_e2e::ssserver`). They are all `#[ignore]`d:
//   galoshes plugin data delivery is flaky on CI — the roundtrips truncate
//   intermittently across every transport (#518; the bridge itself is correct).
//   They compile on their real platforms (WS on Win+mac, WS-TLS and QUIC on
//   macOS only for the Windows custom-cert limit, the full-tunnel test on the
//   Windows TUN lane) and run again once #518 is fixed. galoshes transport
//   coverage proper lives in the `plugin-e2e` crate.
#[cfg(test)]
#[path = "proxy_manager_e2e_tests.rs"]
mod proxy_manager_e2e_tests;

#[cfg(test)]
#[path = "proxy_manager_listener_e2e_tests.rs"]
mod proxy_manager_listener_e2e_tests;

// DNS wiring helpers ==================================================================================================

/// Build the in-TUN DNS endpoint + forwarder, if the config enables it. The
/// forwarder's upstream runs via [`crate::dns::socks5_connector::Socks5Connector`]
/// targeting the just-started SS SOCKS5 listener, so user filter rules
/// cannot strand our own queries.
///
/// Returns the `forwarder` Arc alongside the endpoint so the blocking
/// self-test gate in `start_inner` can call `forwarder.forward(...)` without
/// re-plumbing.
///
/// Rejects the `dns.enabled && servers.is_empty()` config combination with
/// `ForwarderSelfTestFailed { reason: "no DNS servers configured" }` because
/// that combination would otherwise produce a degenerate runtime (TUN routes
/// go live but the forwarder has nothing to forward to).
async fn build_local_dns(
    dns_cfg: &hole_common::config::DnsConfig,
    local_ss_port: u16,
    ipv6_bypass_available: bool,
    _cancel: CancellationToken,
) -> Result<
    (
        Option<crate::endpoint::LocalDnsEndpoint>,
        Option<std::sync::Arc<crate::dns::forwarder::DnsForwarder>>,
    ),
    ProxyError,
> {
    if !dns_cfg.enabled {
        return Ok((None, None));
    }
    if dns_cfg.servers.is_empty() {
        // Hard error: the only sensible recovery is to disable the forwarder.
        // A live TUN with no upstream would strand every in-tunnel UDP/53
        // flow at the LocalDnsEndpoint with nothing to forward to.
        return Err(ProxyError::ForwarderSelfTestFailed {
            reason: "no DNS servers configured".into(),
            attempts: 0,
            elapsed_ms: 0,
        });
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

    // The in-TUN endpoint is the sole OS DNS path: OS DNS now routes
    // into hole-tun and is intercepted here, not via a loopback :53 server.
    // It is built whenever DNS is enabled, independent of `intercept_udp53`
    // (legacy flag — the in-TUN forwarder is now the mechanism).
    let endpoint = crate::endpoint::LocalDnsEndpoint::new(Arc::clone(&forwarder));

    Ok((Some(endpoint), Some(forwarder)))
}

/// Hint logged on self-test failure when the plugin tap IS enabled.
/// Tells the reader where the per-connection diagnostic lines are.
pub(crate) const TAP_ENABLED_HINT: &str =
    "DNS self-test failed with plugin tap enabled; check 'plugin tap: closed' lines above for per-connection bytes_to_plugin / bytes_from_plugin / ttfb_ms / close_kind";

/// Hint logged on self-test failure when the plugin tap is NOT enabled.
/// Tells the reader how to capture richer diagnostics next time.
pub(crate) const TAP_DISABLED_HINT: &str =
    "DNS self-test failed; to capture per-connection plugin diagnostics on next reproduction, set diagnostic_plugin_tap=true in AppConfig and restart the bridge";

/// Run the forwarder self-test inline against its first configured server.
/// Returns `SelfTestOutcome::Ok` when any well-formed non-SERVFAIL reply
/// comes back within the 3×1500ms / 5s budget, else `Failed`. Also writes
/// the canonical `"forwarder self-test ok"` / `"forwarder self-test failed"`
/// log line at `info!`. On failure, additionally emits a `warn!`
/// correlation breadcrumb pointing the reader to the plugin tap
/// (depending on whether it was enabled this run — see
/// `TAP_ENABLED_HINT` / `TAP_DISABLED_HINT`).
///
/// A blocking gate: called from `start_inner` BEFORE `Dispatcher::new` /
/// `routing.install` / `Dns::apply`. A failure short-circuits the start;
/// the locally-owned `running_proxy` + `plugin_chain` RAII guards unwind
/// without ever hijacking system DNS into a dead tunnel.
async fn run_forwarder_self_test(
    forwarder: std::sync::Arc<crate::dns::forwarder::DnsForwarder>,
    servers: Vec<std::net::IpAddr>,
    diagnostic_tap_enabled: bool,
    cancel: CancellationToken,
) -> SelfTestOutcome {
    const PER_ATTEMPT: std::time::Duration = std::time::Duration::from_millis(1500);
    const OUTER_BUDGET: std::time::Duration = std::time::Duration::from_secs(5);
    const ATTEMPTS: u32 = 3;

    let Some(&first_server) = servers.first() else {
        info!("forwarder self-test skipped: no servers configured");
        return SelfTestOutcome::Ok { attempts: 0 };
    };

    let query = sample_self_test_query();
    let started = std::time::Instant::now();
    let outcome = tokio::time::timeout(OUTER_BUDGET, async {
        let mut last_err: Option<String> = None;
        for attempt in 1..=ATTEMPTS {
            // Cooperative cancel check between retry attempts (#397).
            if cancel.is_cancelled() {
                return SelfTestOutcome::Cancelled;
            }
            // Future-drop on `forwarder.forward(&query)` IS acceptable
            // here — the single exception to the cooperative cancellation
            // contract in this module (#397). The `DnsForwarder`'s only
            // in-flight resource is a TCP/UDP socket that closes on Drop
            // (sync, trivial); there is no async cleanup to await.
            let result = tokio::select! {
                biased;
                _ = cancel.cancelled() => return SelfTestOutcome::Cancelled,
                r = tokio::time::timeout(PER_ATTEMPT, forwarder.forward(&query)) => r,
            };
            match result {
                Ok(reply) => {
                    if is_dns_reply_ok(&reply) {
                        return SelfTestOutcome::Ok { attempts: attempt };
                    }
                    last_err = Some(format!("SERVFAIL reply on attempt {attempt}"));
                }
                Err(_) => last_err = Some(format!("attempt {attempt} timed out after {PER_ATTEMPT:?}")),
            }
        }
        SelfTestOutcome::Failed {
            attempts: ATTEMPTS,
            reason: last_err.unwrap_or_else(|| "unknown".into()),
        }
    })
    .await
    .unwrap_or(SelfTestOutcome::Failed {
        attempts: ATTEMPTS,
        reason: format!("outer timeout after {OUTER_BUDGET:?}"),
    });

    let elapsed_ms = started.elapsed().as_millis() as u64;
    match &outcome {
        SelfTestOutcome::Ok { attempts } => {
            info!(%first_server, attempts, elapsed_ms, "forwarder self-test ok");
        }
        SelfTestOutcome::Failed { attempts, reason } => {
            info!(%first_server, attempts, elapsed_ms, reason, "forwarder self-test failed");
            // #388 correlation breadcrumb: tells the reader either
            // where the tap data lives, or how to enable it for next
            // reproduction. The actual error surfaces through
            // ProxyError::ForwarderSelfTestFailed → IPC response →
            // GUI; no error! log needed.
            if diagnostic_tap_enabled {
                warn!("{TAP_ENABLED_HINT}");
            } else {
                warn!("{TAP_DISABLED_HINT}");
            }
        }
        SelfTestOutcome::Cancelled => {
            info!(%first_server, elapsed_ms, "forwarder self-test cancelled");
        }
    }
    outcome
}

#[derive(Debug)]
enum SelfTestOutcome {
    Ok {
        attempts: u32,
    },
    Failed {
        attempts: u32,
        reason: String,
    },
    /// The bridge cancel token fired before the self-test could complete
    /// or fail definitively (#397). Maps to `ProxyError::Cancelled` via
    /// `into_result`; not a diagnostic failure (the user asked for it).
    Cancelled,
}

impl SelfTestOutcome {
    /// Convert outcome to a Result for use as a start-time gate.
    /// `Ok(attempts)` carries the attempt count taken to succeed (0 when
    /// skipped because no servers configured — only reachable via the
    /// `dns.enabled = false` branch in `build_local_dns`).
    fn into_result(self, elapsed_ms: u64) -> Result<u32, ProxyError> {
        match self {
            Self::Ok { attempts } => Ok(attempts),
            Self::Failed { attempts, reason } => Err(ProxyError::ForwarderSelfTestFailed {
                reason,
                attempts,
                elapsed_ms,
            }),
            Self::Cancelled => Err(ProxyError::Cancelled),
        }
    }
}

/// Treat "any well-formed DNS reply that isn't SERVFAIL" as success.
/// The reply header is 12 bytes; RCODE lives in the low nibble of byte 3
/// (RFC 1035 §4.1.1). RCODE 2 = SERVFAIL (upstream failed explicitly);
/// all other RCODEs (NoError, NXDOMAIN, REFUSED) mean the path works.
fn is_dns_reply_ok(reply: &[u8]) -> bool {
    reply.len() >= 12 && (reply[3] & 0x0F) != 2
}

/// Build a minimal wire-format DNS query: `example.com A`. Used by
/// [`run_forwarder_self_test`] — hardcoded hostname is acceptable
/// because the forwarder self-test is an internal probe, never a user-
/// visible config. NXDOMAIN on this name still proves the path works.
fn sample_self_test_query() -> Vec<u8> {
    let mut q = Vec::with_capacity(32);
    q.extend_from_slice(&0x0001_u16.to_be_bytes()); // id
    q.extend_from_slice(&[0x01, 0x00]); // flags: RD=1
    q.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    q.push(7);
    q.extend_from_slice(b"example");
    q.push(3);
    q.extend_from_slice(b"com");
    q.push(0);
    q.extend_from_slice(&[0x00, 0x01]); // QTYPE=A
    q.extend_from_slice(&[0x00, 0x01]); // QCLASS=IN
    q
}
