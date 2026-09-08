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
// A cycle's transient state lives in `self.posture`, one of `Idle` /
// `PendingStart` / `Session(RunningState<P, R>)` — see the `Posture` section
// below. When `stop()` takes the state, the proxy handle is explicitly
// `stop().await`ed (so errors are reported), then the routes guard drops
// (tearing down). On a successful `start`, the full `RunningState` is
// committed via `Posture::commit_session` strictly after `start_inner`
// returns `Ok(state)`; the cooperative-cancel path returns `Err(Cancelled)`
// before reaching the commit.
//
// There are deliberately no getters for `proxy` or `routing` — test access
// to mock state happens via `Arc` clones captured before the mock is
// handed to `new`. A getter would recreate an encapsulation smell.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Instant;
use util::port_alloc;

use dump::{dump, DeriveDump};
use hole_common::logging::redact_arm::{ip_family, ip_scope, server_kind, token_for};
use hole_common::protocol::{ProxyConfig, TunnelMode};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use tun_engine::gateway::GatewayInfo;
use tun_engine::routing::failclosed::lockdown_state::{self, Intent};
use tun_engine::routing::{CoverGuard, CoverPresence, RoutesInstalled, Routing, SystemRouting};

use crate::reconciler::{teardown_cover_disposition, transient_cover_disposition, CoverDisposition};
use crate::target::{self, target_after, SessionEvent, Target};

use crate::dns::self_test::{
    build_local_dns, implicates_plugin_transport, report_plugin_output, run_forwarder_self_test, self_test_error_for,
    SelfTestOutcome,
};
use crate::dns::system::{Dns, DnsApplied, DnsError, SystemDns};
use crate::proxy::{build_ss_config, Proxy, ProxyError, RunningProxy, ShadowsocksProxy, TrafficTotals};
// `WINDOWS_TUN_ALIAS` only stands in for a real `TunIdentity` on the
// `#[cfg(test)]` synthetic path below — the production path threads the
// identity `Engine::build`/`Dispatcher::identity()` actually opened. Names no
// OS object either way, so borrowing the Windows-only alias constant here
// (rather than a fresh literal) is inert on every platform this test code
// compiles for.
#[cfg(test)]
use crate::proxy::config::WINDOWS_TUN_ALIAS;

/// Non-secret diagnostic view of a proxy-start event — suitable for
/// YAML-shaped logging via `dump!`.
///
/// There is no field an address can occupy. `server` is the entry's opaque
/// token; the shape questions this repo's actual diagnoses turned on (#248,
/// #541, #655, #770, #694) are answered by `server_kind` / `server_family` /
/// `server_scope` instead. `server_family` and `server_scope` are `None`
/// only where no address was resolved.
#[derive(DeriveDump)]
struct ProxyStartedDiag<'a> {
    server: String,
    server_kind: &'static str,
    server_family: Option<&'static str>,
    server_scope: Option<&'static str>,
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

/// Whether an out-of-band reachability probe must be suppressed because
/// Hole's OWN fail-closed cover — not network censorship — would explain a
/// blocked egress. A cover from ANY source suppresses it: a MEASURED standing
/// cover (`cover`, an OS probe — `Indeterminate`/`Unreachable` fold in with
/// `Live`/`Recorded`, since an uncertain probe must never wave the probe
/// through), this attempt's own held transient cover
/// (`transient_pending` — `Posture::PendingStart`), or a standing cover this
/// attempt is ABOUT to install (`standing_expected`, decided before
/// `routing.install` runs it).
fn suppresses_reachability_probe(cover: CoverPresence, transient_pending: bool, standing_expected: bool) -> bool {
    cover.is_present() || transient_pending || standing_expected
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
/// **Tear-down order is load-bearing.** `ProxyManager::stop_with` runs the
/// shutdown sequence in this order:
/// 1. `dns_applied.shutdown().await` — restores OS DNS while routes +
///    dispatcher + SS are still live so any in-flight OS DNS queries
///    egress the restored path.
/// 2. `dispatcher.shutdown().await` — closes TUN, cancels handlers.
/// 3. `plugin_chain` drop — graceful stop via SIGTERM/CTRL_BREAK.
/// 4. `proxy.stop().await` — releases SS task.
/// 5. `routes` drop — RAII teardown.
/// 6. `lockdown` — its fate comes from `cover_step(intent, presence, target)`,
///    not from why the session ended: `Release` drops it (disengage; opens
///    the host), `Hold`/`Engage` disarms it (the persistent filters survive).
///    Last so the persistent filters outlive routes by Drop order.
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
    /// Standing lockdown cover, engaged only when intent is on. `None` when
    /// lockdown is off — then behavior is byte-identical to today. Whether a
    /// cover is engaged is now a MEASURED fact
    /// ([`ProxyManager::cover_presence`], an OS probe) — no site may derive
    /// it from this field's presence; a structural guard in
    /// `proxy_manager_tests.rs` catches a source that tries. `stop_with`
    /// still CONSUMES this field to decide the cover's fate at teardown: a
    /// `UserStop` disengages it and a `Cutover` disarms it (the persistent
    /// filters survive), both after routes tear down (its Drop is the
    /// catastrophic safety net).
    lockdown: Option<R::Cover>,
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

/// The one reason an out-of-band death is reported to the GUI. A `&'static str`
/// so the status/toast surface is path-free by construction (#470): unlike the
/// operation-error `last_error`, which can carry a filesystem path or hostname
/// from a failed start, this can never embed PII.
pub const DEATH_REASON: &str = "proxy task exited unexpectedly";

pub struct ProxyManager<P: Proxy = ShadowsocksProxy, R: Routing = SystemRouting, D: Dns = SystemDns> {
    proxy: P,
    /// Shared, not owned outright: `IpcState` holds a clone of this SAME
    /// `Arc` beside the proxy mutex so the unblock escape
    /// (`ipc::handle_unblock`) can read cover presence and release covers
    /// WITHOUT taking `state.proxy.lock()` — the escape must work even while
    /// a teardown wedges that lock. See [`Self::routing_handle`].
    routing: Arc<R>,
    dns: D,
    /// See the `Posture` section below. The pending-start case holds the
    /// single transient fail-closed cover, engaged when a covered
    /// (auto-connect) start failed: the host stays blocked, not leaked,
    /// while no session is running. The live guard is held here (its `Drop`
    /// still runs) — released on a user stop/cancel or the next successful
    /// start. The transient cover is a global singleton, so a retry reuses
    /// this guard rather than engaging a second. It carries the server
    /// identity it permits so a same-server retry reuses the resolved IP
    /// instead of re-resolving under the cover (which it would block).
    posture: Posture<P, R, D>,
    last_error: Option<String>,
    /// The out-of-band death reason surfaced to the GUI status/toast, distinct
    /// from `last_error` (which keeps the rich, possibly-PII operation detail
    /// for diagnostics and the click-path start-error surface). Set only by
    /// `check_health`; cleared on every start attempt and on stop (#470).
    death_reason: Option<&'static str>,
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
    /// uid/gid to chown persisted state files to. Set by an elevated
    /// user-scoped run so the real user owns the files; `None` (the
    /// default, and the `--service` daemon) leaves ownership as-is.
    state_owner: Option<(u32, u32)>,
    /// "Startup recovery found a standing cover live this run" — see
    /// [`Self::set_standing_cover_adopted`] for the full contract.
    ///
    /// The LIVE-COVER half only. The armed half — "the user wants the kill
    /// switch" — is `bridge-lockdown.json`, written by `promote_adopted_claim`
    /// once a start honours this claim with a real `install_lockdown`. Holding
    /// both facts here is what let a plain disconnect disarm the switch.
    adopted_standing_cover: bool,
    /// Set (lock-free) by `handle_unblock` via [`Self::cover_invalidation_handle`]
    /// when it releases every OS-level cover from outside this manager's own
    /// lock (R7: the escape must work even while a wedged teardown holds
    /// `state.proxy.lock()`). `start_cancellable` consumes it — see the swap
    /// at its top — the same way `turn_lockdown_off` drops a held transient
    /// guard directly via `posture.take_pending()`, just reachable without
    /// `&mut self`.
    cover_invalidated: Arc<std::sync::atomic::AtomicBool>,
    /// Test-only DoH querier override. Set by `set_bootstrap_querier_for_test`;
    /// when present, `start_cancellable` resolves via `resolve_via_doh_with`
    /// instead of the production `resolve_via_doh`.
    #[cfg(test)]
    bootstrap_querier: Option<std::sync::Arc<dyn crate::dns::bootstrap::DohQuerier>>,
    /// The `ech-doh` URL the most recent start derived. Test-only: the
    /// derivation is otherwise observable only through the plugin it spawns.
    #[cfg(test)]
    last_ech_doh: Option<String>,
}

/// A held block-until-connected cover plus the server identity it permits —
/// the payload of `Posture::PendingStart`.
/// `resolver_permit` is what was ACTUALLY passed to `install_failclosed_cover`
/// at the engage that produced `cover` — ground truth for what the LIVE OS
/// cover permits, frozen until the next fresh engage. A covered retry against
/// the same `host` reuses `server_ip` and never re-engages the cover UNLESS
/// this attempt's freshly re-derived permit now differs from `resolver_permit`
/// (e.g. the user added a plugin since the first attempt) — that drift makes
/// the held cover stale, and `start_cancellable` releases it so the engage
/// block re-engages fresh with the corrected permit.
struct BlockedStart<C> {
    cover: C,
    host: String,
    server_ip: IpAddr,
    /// Which resolver answered when this cover's IP was resolved. A covered
    /// retry never re-resolves, so it reuses this — revalidated against the
    /// retry's own config, so an edited resolver set is never overridden.
    pin: crate::dns::ech::PinSource,
    /// Distinct from `pin`: `pin` is revalidated every retry, this field is
    /// not — it describes the live OS cover, not the current config. See the
    /// struct doc for what it means.
    resolver_permit: Option<IpAddr>,
}

// Posture =============================================================================================================

/// Who owns `ProxyManager`'s per-cycle state right now: nobody, a pending
/// covered start, or a live session. Collapses what were two independently
/// mutable `Option` fields (`running`, `blocked`) into one, so a session and
/// a pending start both holding covers stops being representable.
enum Posture<P: Proxy, R: Routing, D: Dns> {
    Idle,
    PendingStart(BlockedStart<R::Cover>),
    // Boxed: `RunningState` (283+ bytes, dwarfing `PendingStart`'s ~75) would
    // otherwise size every `Posture` — including the common `Idle` case — to
    // its largest variant.
    Session(Box<RunningState<P, R, D>>),
}

impl<P: Proxy, R: Routing, D: Dns> Posture<P, R, D> {
    fn session(&self) -> Option<&RunningState<P, R, D>> {
        match self {
            Posture::Session(s) => Some(s.as_ref()),
            _ => None,
        }
    }

    fn session_mut(&mut self) -> Option<&mut RunningState<P, R, D>> {
        match self {
            Posture::Session(s) => Some(s.as_mut()),
            _ => None,
        }
    }

    fn pending(&self) -> Option<&BlockedStart<R::Cover>> {
        match self {
            Posture::PendingStart(b) => Some(b),
            _ => None,
        }
    }

    /// Take the pending-start payload, leaving `Idle`. `None`, and the
    /// posture left untouched, on any other variant — in particular this
    /// must not disturb a live session.
    fn take_pending(&mut self) -> Option<BlockedStart<R::Cover>> {
        if !matches!(self, Posture::PendingStart(_)) {
            return None;
        }
        match std::mem::replace(self, Posture::Idle) {
            Posture::PendingStart(b) => Some(b),
            _ => unreachable!("just matched PendingStart above"),
        }
    }

    /// Contract: the posture is `Idle`. Provers: `start_cancellable`'s
    /// `AlreadyRunning` guard rules out `Session`; the caller's own
    /// `self.posture.pending().is_none()` check, immediately before this
    /// call, rules out an existing `PendingStart`.
    fn hold_pending(&mut self, held: BlockedStart<R::Cover>) {
        debug_assert!(
            matches!(self, Posture::Idle),
            "hold_pending: posture must be Idle — AlreadyRunning already ruled out a session, \
             and the caller's own pending().is_none() check ruled out an existing pending start"
        );
        *self = Posture::PendingStart(held);
    }

    /// Contract: the posture is `Idle`. Provers: `start_cancellable`'s
    /// `AlreadyRunning` guard rules out `Session`; the caller's own
    /// `take_pending()` call, immediately before this call, rules out a
    /// `PendingStart`.
    fn commit_session(&mut self, session: RunningState<P, R, D>) {
        debug_assert!(
            matches!(self, Posture::Idle),
            "commit_session: posture must be Idle — AlreadyRunning already ruled out a session, \
             and the caller's own take_pending() call ruled out a pending start"
        );
        *self = Posture::Session(Box::new(session));
    }
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
            routing: Arc::new(routing),
            dns,
            posture: Posture::Idle,
            last_error: None,
            death_reason: None,
            active_config: None,
            udp_proxy_available: true,
            ipv6_bypass_available: true,
            state_dir: None,
            state_owner: None,
            adopted_standing_cover: false,
            cover_invalidated: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            #[cfg(test)]
            bootstrap_querier: None,
            #[cfg(test)]
            last_ech_doh: None,
        }
    }

    /// Test seam: override the DoH bootstrap querier so `start_inner` resolves
    /// the server hostname via `resolve_via_doh_with` (no OS resolver, no
    /// network).
    #[cfg(test)]
    pub fn set_bootstrap_querier_for_test(&mut self, q: std::sync::Arc<dyn crate::dns::bootstrap::DohQuerier>) {
        self.bootstrap_querier = Some(q);
    }

    /// Clone of the shared routing handle. `bind_with_dirs`/`bind` derive
    /// `IpcState::routing` from this — a `Mutex`-free clone taken once at
    /// bind time, uncontended since the `ProxyManager` is freshly
    /// constructed there — so the unblock escape can act on routing without
    /// taking `state.proxy.lock()`.
    pub fn routing_handle(&self) -> Arc<R> {
        Arc::clone(&self.routing)
    }

    /// Clone of the lock-free cover-invalidation signal. `bind_with_dirs`
    /// derives `IpcState::cover_invalidated` from this, the same way it
    /// derives `routing` from [`Self::routing_handle`] — taken once at bind
    /// time, uncontended. `handle_unblock` sets it after releasing every
    /// OS-level cover; [`Self::start_cancellable`] consumes it.
    pub fn cover_invalidation_handle(&self) -> Arc<std::sync::atomic::AtomicBool> {
        Arc::clone(&self.cover_invalidated)
    }

    /// Set the state directory for plugin PID crash recovery.
    pub fn with_state_dir(mut self, dir: std::path::PathBuf) -> Self {
        self.state_dir = Some(dir);
        self
    }

    /// Set the owner (uid/gid) that persisted state files are chowned to.
    pub fn with_state_owner(mut self, owner: Option<(u32, u32)>) -> Self {
        self.state_owner = owner;
        self
    }

    /// The owner every persisted-state write must carry. Read by
    /// `crate::route_recovery` so crash recovery's intent repair chowns what it
    /// creates the same way the manager's own writes do.
    pub fn state_owner(&self) -> Option<(u32, u32)> {
        self.state_owner
    }

    pub fn state(&self) -> ProxyState {
        // ProxyState is retained (Stopped/Running) to preserve the IPC
        // `StatusResponse.running` field semantics unchanged for the GUI.
        if self.posture.session().is_some() {
            ProxyState::Running
        } else {
            ProxyState::Stopped
        }
    }

    pub fn uptime_secs(&self) -> u64 {
        self.posture
            .session()
            .map(|r| r.started_at.elapsed().as_secs())
            .unwrap_or(0)
    }

    /// Test seam: shift `started_at` backwards by `by`. Lets uptime
    /// tests assert "after N seconds elapsed" without sleeping or
    /// injecting a clock abstraction. No-op if not currently running.
    /// See bindreams/hole#383.
    #[cfg(test)]
    pub fn shift_started_at_for_test(&mut self, by: std::time::Duration) {
        if let Some(r) = self.posture.session_mut() {
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
        let running = self.posture.session_mut()?;
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
        if let Some(w) = self.posture.session_mut().and_then(|r| r.traffic_window.as_mut()) {
            w.sampled_at = w
                .sampled_at
                .checked_sub(by)
                .expect("shift_traffic_window_for_test: rewound past the Instant epoch");
        }
    }

    pub fn last_error(&self) -> Option<&str> {
        self.last_error.as_deref()
    }

    /// The out-of-band death reason for the GUI status/toast (path-free by
    /// type), or None if the proxy did not die unexpectedly (#470).
    pub fn death_reason(&self) -> Option<&'static str> {
        self.death_reason
    }

    /// Delegation for `handle_diagnostics`: expose the routing provider's
    /// destination-independent default-route query without leaking the
    /// provider itself. This is NOT an encapsulation-breaking getter — it's
    /// a single capability intentionally surfaced for the diagnostics
    /// handler so tests can exercise the mock routing's gateway stub instead
    /// of hitting the host OS.
    ///
    /// `Routing::default_route`, not `default_gateway`: diagnostics runs
    /// with no session, so there is no `server_ip` a server-scoped probe
    /// could even be given (see `Routing::default_gateway`'s doc).
    pub fn default_route(&self) -> Result<GatewayInfo, ProxyError> {
        self.routing.default_route().map_err(Into::into)
    }

    /// Get the list of invalid (dropped) filter rules from the current ruleset.
    pub fn invalid_filters(&self) -> Vec<hole_common::protocol::InvalidFilter> {
        self.posture
            .session()
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

    /// What the OS says about a standing lockdown cover on the host right
    /// now — an OS probe (`Routing::lockdown_cover_presence`), not a
    /// recollection of what this process engaged. Distinct from the
    /// persisted intent (`lockdown_enabled`). Replaces the old
    /// `lockdown_active() -> bool`, which answered the *host* question with
    /// a *process-ownership* answer — structurally `false` whenever nothing
    /// is running even while an adopted cover blocks every packet
    /// (bindreams/hole#825).
    pub fn cover_presence(&self) -> CoverPresence {
        self.routing.lockdown_cover_presence()
    }

    /// Whether a covered start failed and left the host fail-closed (blocked, not
    /// leaked) while not running — the GUI's distinct blocked state. This is
    /// the one sanctioned exception that still reads `Posture`: it answers a
    /// TRANSIENT, tunnel-surface question (`Posture::PendingStart`, a fact
    /// about THIS attempt's own held cover) that the standing-cover probe
    /// does not measure at all.
    pub fn blocked_until_connected(&self) -> bool {
        matches!(self.posture, Posture::PendingStart(_))
    }

    #[cfg(test)]
    pub(crate) fn last_ech_doh(&self) -> Option<&str> {
        self.last_ech_doh.as_deref()
    }

    /// Record or clear the claim "a standing cover is live this run and this
    /// process has not released it".
    ///
    /// Set from startup recovery's `Adopt`, gated additionally on a MEASURED
    /// `CoverPresence::Live` (see `crate::route_recovery`) — `Adopt` alone also
    /// covers `Recorded`/`Indeterminate`, which the OS did not confirm.
    ///
    /// Cleared at four sites. Three release the cover and clear only on
    /// CONFIRMED success — never on the guard's own `Drop`, which can only warn
    /// on failure, not report it: `turn_lockdown_off`'s idle arm, a `UserStop`
    /// teardown, and `check_health` tearing down a dead session, each after its
    /// own `release_all_covers` call returns `Ok`. The fourth,
    /// `turn_lockdown_off`'s mid-session arm, releases nothing — the session's
    /// own cover is untouched, `stop_with` alone decides its fate — and clears
    /// only because the user's newly-persisted explicit off must not keep
    /// being overridden by a stale claim. A `Cutover` stop deliberately leaves
    /// it set — it does not open the host.
    pub fn set_standing_cover_adopted(&mut self, adopted: bool) {
        self.adopted_standing_cover = adopted;
    }

    /// The raw claim, so a test can tell the live-cover half from the armed
    /// half `bridge-lockdown.json` carries. Both public reads fold the two
    /// together.
    #[cfg(test)]
    pub(crate) fn standing_cover_adopted(&self) -> bool {
        self.adopted_standing_cover
    }

    /// **Status reply + tray escape.** Whether the kill switch should read as
    /// armed: the intent's `reads_armed` fold, OR this run adopted a standing
    /// cover it has not released.
    ///
    /// The `|| adopted` disjunct is what keeps the Unblock item on the menu
    /// when the intent file is gone and the repair write itself failed — the
    /// escape must not depend on the file this change made stickier.
    ///
    /// An explicit recorded `Off` wins over the claim outright: the claim is
    /// only ever cleared by in-process paths, so an out-of-process writer
    /// (`hole bridge unlock`, on the bridge's own state_dir) can record `Off`
    /// while the claim from a still-running bridge's earlier recovery stays
    /// set. Without this, that unlock is invisible to the tray and the next
    /// connect re-engages the cover it just escaped.
    pub fn lockdown_enabled(&self) -> bool {
        let Some(intent) = self.state_dir.as_deref().map(lockdown_state::load_intent) else {
            return self.adopted_standing_cover;
        };
        !matches!(intent, lockdown_state::Intent::Off) && (self.adopted_standing_cover || intent.reads_armed())
    }

    /// **Connect path + update-consent gate.** Whether a standing cover holds,
    /// or is about to hold, the host: the intent's `installs_standing_cover`
    /// fold, OR this run adopted one.
    ///
    /// Differs from [`Self::lockdown_enabled`] on exactly one input — an
    /// `Unreadable` intent with no adopted cover — where it answers *no*, so
    /// the covered start engages the transient block-until-connected cover
    /// instead of skipping it for a standing cover that only arrives after
    /// `routing.install`, and `consent_gate` truthfully reports that no
    /// standing cover holds the update gap.
    ///
    /// The `|| adopted` disjunct is load-bearing on the connect path: an
    /// adopted cover is inert, so it still names the PREVIOUS run's TUN and
    /// server IP. A connect that did not re-engage would bring up a new TUN the
    /// live cover blocks — connected, with no traffic.
    ///
    /// An explicit recorded `Off` wins over the claim outright — see
    /// [`Self::lockdown_enabled`]'s doc for why: without it, the next connect
    /// after an out-of-process `hole bridge unlock` re-installs the cover the
    /// user just escaped.
    pub fn standing_cover_expected(&self) -> bool {
        let Some(intent) = self.state_dir.as_deref().map(lockdown_state::load_intent) else {
            return self.adopted_standing_cover;
        };
        !matches!(intent, lockdown_state::Intent::Off)
            && (self.adopted_standing_cover || intent.installs_standing_cover())
    }

    /// Last-writer-wins absolute set of the lockdown intent. Persists to
    /// `bridge-lockdown.json`. ERRORS when there is no state_dir: the bridge
    /// cannot honor a kill switch it cannot persist (a silent `Ok(())` would be
    /// a fail-open footgun — the GUI would believe lockdown is armed when
    /// nothing was written).
    pub fn set_lockdown_intent(&self, enabled: bool) -> Result<(), ProxyError> {
        let dir = self.state_dir.as_deref().ok_or_else(|| {
            ProxyError::Runtime(std::io::Error::other(
                "cannot set lockdown intent: bridge has no state_dir to persist it",
            ))
        })?;
        lockdown_state::set_enabled(dir, enabled, self.state_owner)
            .map_err(|e| ProxyError::Runtime(std::io::Error::other(format!("lockdown persist: {e}"))))
    }

    /// Turn the kill-switch intent off, releasing the cover unless
    /// `cover_step` has CONFIRMED there is nothing to release. Reads no
    /// session posture directly — Q4 ("unblock IS unticking") means a live
    /// session's cover is released too when the persisted target is `Off`
    /// and presence is not confirmed `Absent`; `cover_step`'s own
    /// `Target::Off` arm is what decides that, uniformly, whether or not a
    /// session is running.
    ///
    /// A target the bridge cannot even read, or a presence probe that
    /// cannot even reach the OS (`Target::Unreadable` / `CoverPresence::
    /// Unreachable`), is not evidence the host is clean — `cover_step`
    /// holds on both because it has no authority to decide either way, but
    /// this is an EXPLICIT user disarm, not a steady-state reconcile: an
    /// escape-offering site must resolve an unknown toward releasing, never
    /// toward "nothing to do" (see `crates/common/api/openapi.yaml`'s
    /// `CoverPresence` doc). `release_all_covers` is documented unconditional
    /// and idempotent, so calling it on a false positive costs nothing.
    ///
    /// Release-then-persist ordering is load-bearing: the tray offers this
    /// escape while the intent is on, so flipping the intent off after a
    /// FAILED release would delete the user's only retry affordance while
    /// the host is still held closed. The intent moves only after the clear
    /// confirms (or after this decided no clear was owed).
    pub fn turn_lockdown_off(&mut self) -> Result<(), ProxyError> {
        // Drop any held transient guard's in-process authority first. Not a
        // condition — a no-op when nothing is pending — it exists so no live
        // guard outlives the OS objects `release_all_covers` is about to
        // delete out from under it.
        self.posture.take_pending();

        // Unconditional: `release_all_covers` is documented idempotent, so
        // gating it on a presence probe is a check-then-act guard on an
        // operation that needs none — and at an explicit disarm a stale
        // `Absent` is the one wrong answer that matters. This is also what
        // removes the discrepancy between this site's bespoke `must_release`
        // and `handle_unblock`'s: neither computes a rule any more.
        self.routing.release_all_covers()?;
        // The clear confirmed, so the host is open: an adopted cover no
        // longer holds it. Dropping this claim is what stops the tray
        // from rendering `Lockdown: On` over an open host for the life
        // of the process.
        self.set_standing_cover_adopted(false);

        // Only now move the intent. Either the covers are already gone and
        // the host is open, or `cover_step` said none needed releasing; a
        // persist failure here means only the SETTING did not save, which
        // the caller must be able to say distinctly from a failed release.
        self.set_lockdown_intent(false)
            .map_err(|_| ProxyError::LockdownIntentNotPersisted)
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
        self.start_cancellable(config, false, token).await
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
        covered: bool,
        cancel: CancellationToken,
    ) -> Result<(), ProxyError> {
        debug!(
            local_port = config.local_port,
            tunnel_mode = ?config.tunnel_mode,
            plugin = ?config.server.plugin,
            server = %token_for(&config.server.id),
            server_kind = server_kind(config.server.server.expose()),
            server_port = config.server.server_port,
            "ProxyManager::start_cancellable entered"
        );
        if self.posture.session().is_some() {
            return Err(ProxyError::AlreadyRunning);
        }

        // A lock-free `handle_unblock` may have released every OS-level
        // cover while this manager wasn't holding the lock. Any
        // `PendingStart` we're still carrying is now a zombie: the OS
        // objects it claims to hold are already gone. Drop it before the
        // reuse checks below (`repair_fallback`, the `pending().is_none()`
        // gate) can trust it — `take_pending()` is a no-op when nothing is
        // pending, and the dropped guard's own Drop is idempotent against
        // an already-cleared cover on both platforms, so this is safe
        // whether or not anything was actually held. `swap` both reads and
        // clears in one step, so this consumes the signal exactly once.
        if self.cover_invalidated.swap(false, std::sync::atomic::Ordering::SeqCst) {
            self.posture.take_pending();
        }

        // A (re)start supersedes any prior out-of-band death — clear the death
        // reason regardless of this attempt's outcome.
        self.death_reason = None;

        #[cfg(test)]
        let bootstrap_querier = self.bootstrap_querier.clone();
        #[cfg(not(test))]
        let bootstrap_querier: Option<std::sync::Arc<dyn crate::dns::bootstrap::DohQuerier>> = None;

        // A DIFFERENT server's hostname needs a FRESH DoH resolution — not
        // guaranteed to land on the resolver already baked into the held cover
        // (see `BlockedStart`'s doc) — so a start for a different server must
        // release the held cover BEFORE resolving.
        let stale = self
            .posture
            .pending()
            .is_some_and(|b| b.host != config.server.server.expose());
        if stale {
            debug_assert!(self.posture.pending().is_some(), "stale implies a held cover");
            self.posture.take_pending();
            warn!("start for a different server while blocked: releasing the held cover before re-resolving");
        }

        // Resolve the server IP over private DoH. A same-server retry under the
        // held cover reuses the cached IP and pin.
        let (server_ip, pin) = match self
            .posture
            .pending()
            .filter(|b| b.host == config.server.server.expose())
        {
            Some(b) => (b.server_ip, crate::dns::ech::revalidate(b.pin, &config.dns.servers)),
            None => match Self::resolve_server_ip(config, &bootstrap_querier, &cancel).await {
                Ok(b) => (b.server_ip, b.via),
                Err(e) => {
                    if !matches!(e, ProxyError::Cancelled) {
                        self.last_error = Some(e.to_string());
                        // A covered start that can't resolve has no IP to permit, so no
                        // cover can engage: the block-until-connected intent falls open
                        // here — logged so the gap is visible, not silent.
                        if covered {
                            warn!(error = %e, "covered start could not resolve the server; host NOT blocked (no IP to permit)");
                        }
                    }
                    return Err(e);
                }
            },
        };

        // At the JOIN, not on `resolve_server_ip`'s success path: the
        // held-cover reuse branch above takes `b.server_ip` and resolves
        // nothing. Arming only the resolve path would be correct today
        // solely because `BlockedStart` is in-memory and the registry is
        // grow-only — an undocumented invariant one refactor from false.
        hole_common::logging::redact_arm::arm_resolved_ip(&config.server.id, server_ip);

        // `ech_doh` (what ex-ray is TOLD to fetch) and `ech_resolver_permit`
        // (what THIS ATTEMPT would permit it to reach) both read the same
        // plugin-presence + pin inputs — computed ONCE here so the two cannot
        // drift apart under a future edit to either gate. Only a plugin chain
        // carries an ECH lookup, so a plugin-less start derives nothing.
        let plugin_pin: Option<crate::dns::ech::PinSource> = config.server.plugin.is_some().then_some(pin);

        // Every pin outcome reaches ex-ray as one URL, so the reason is named
        // here or it is unrecoverable from the log. An "unpinned ECH lookup"
        // line for a plugin-less start would name an exposure that does not
        // exist, hence `plugin_pin` gating this too.
        let ech_doh = plugin_pin.and_then(|p| {
            let derived = crate::dns::ech::ech_doh_url(&config.dns, p);
            debug!(ech_doh = ?derived, ?p, "ech-doh source");
            if matches!(p, crate::dns::ech::PinSource::ResolverDeselected) {
                warn!("covered retry: the cached DoH resolver is no longer configured; the ECH lookup is unpinned");
            }
            derived
        });
        #[cfg(test)]
        {
            self.last_ech_doh = ech_doh.as_ref().map(|e| e.url.clone());
        }

        // `ech_doh` is Hole's CANDIDATE — what it would tell ex-ray, before
        // `inject_plugin_directives` runs. That injection only rewrites
        // `ech-doh` for the v2ray-family plugin names, and even then an
        // operator's own `ech-doh` already in `plugin_opts` can win
        // first-wins over Hole's (see `effective_ech_doh`'s doc). The cover
        // must be gated on whether Hole's candidate is the EFFECTIVE value
        // ex-ray actually dials — not on `ech_doh.is_some()` alone — or a
        // non-ECH-capable plugin, or an operator's own override, would widen
        // the cover for a fetch that provably does not use it. The residual
        // warning below also reads `effective_ech_doh` directly, to name an
        // operator-won address the cover cannot permit either.
        let effective_ech_doh = crate::proxy::plugin::effective_ech_doh(
            config.server.plugin.as_deref().unwrap_or_default(),
            config.server.plugin_opts.as_deref(),
            ech_doh.as_ref(),
        );
        let ech_effective = matches!(effective_ech_doh, crate::proxy::plugin::EffectiveEchDoh::Holes);

        // `ech_doh.resolver`, read directly — not re-derived from `pin` — is
        // the exact address the ECH-config fetch will dial (see `EchDoh`'s
        // doc for why permitting it costs no new trust regardless of
        // `PinSource`). Gated on `ech_effective`, not `ech_doh.is_some()`: a
        // non-ECH-capable plugin or an operator's own override never widens
        // the cover for a fetch that provably won't use Hole's address.
        let ech_resolver_permit = ech_effective.then_some(ech_doh.as_ref()).flatten().map(|e| e.resolver);
        debug!(
            ?ech_resolver_permit,
            ?pin,
            ech_effective,
            "failclosed cover resolver permit"
        );

        // Engage the block-until-connected cover for a covered start UNLESS a
        // standing cover is expected: that cohort installs the lockdown cover
        // at routing.install, and engaging the transient cover too would (on macOS)
        // clobber the singular pf ruleset. A corrupt or absent lockdown-state
        // file resolves to NOT STANDING — the fail-SAFE direction (we engage,
        // blocking not leaking).
        let lockdown_on = self.standing_cover_expected();

        // A held cover's resolver_permit is fixed at engage time; re-engage
        // whenever this attempt's fresh derivation DIFFERS from what the
        // held cover already has — a narrowing to `None` (e.g. the plugin
        // was removed, or `effective_ech_doh` no longer resolves to
        // `Holes`) drifts too: leaving a wider-than-needed permit live is a
        // real widening of the kill switch (the resolver permit carries no
        // App-ID/process scoping on either platform, so it is available to
        // every process on the host, not just the plugin chain), not a
        // correction with no benefit. `repair_fallback` captures what's
        // being given up: `Some((old_permit, original_pin))` means a good
        // cover existed a moment ago, so a failed fresh engage below
        // restores it instead of leaving the host uncovered. `original_pin`
        // is `pin` BEFORE this attempt's own `revalidate` — see the repair
        // arms below for why it, not the local `pin` variable, is what gets
        // stored back.
        //
        // A retry whose desired permit still matches a value a PRIOR repair
        // already proved unreachable is not treated specially — it repairs
        // again like any other drift. The corrected engage's own failure
        // could be transient (a momentary OS-level condition), not a
        // lasting property of the value, so there is no principled way to
        // tell "will fail again" from "would now succeed" without trying;
        // skipping on a heuristic (e.g. a fixed number of retries) would
        // just delay a correction that could have landed this attempt. Each
        // attempt's release-to-reengage window is bounded to this one
        // (user-paced) retry either way — see the restore fallback below.
        let repair_fallback: Option<(Option<IpAddr>, crate::dns::ech::PinSource)> = if covered && !lockdown_on {
            self.posture
                .pending()
                .filter(|b| b.host == config.server.server.expose() && b.resolver_permit != ech_resolver_permit)
                .map(|b| (b.resolver_permit, b.pin))
        } else {
            None
        };
        if repair_fallback.is_some() {
            self.posture.take_pending();
            warn!(
                "covered retry: this attempt's resolver permit differs from the held cover's; \
                 releasing it so a fresh engage can correct it — egress is briefly OPEN until \
                 the corrected (or, on failure, the restored) cover re-engages below"
            );
        }

        if covered && !lockdown_on {
            // The transient cover is a global singleton — never construct a second
            // over the same objects. An engage failure proceeds UNCOVERED (aborting
            // would leave the user unconnected AND unprotected), surfaced via last_error
            // — UNLESS this was a repair (`repair_fallback` is `Some`), in which case
            // the host was ALREADY covered a moment ago and a compensating re-engage
            // of the OLD permit is attempted first: correcting a permit now takes
            // BOTH the corrected AND the restore engage failing to lose the cover
            // (the `Err(e2)` arm below), not one — never impossible, just
            // narrowed from the ordinary single-engage failure case. On that
            // double failure this attempt proceeds open, same as the
            // non-repair case; the NEXT retry finds the posture holds no
            // pending start and re-engages fresh from scratch.
            if self.posture.pending().is_none() {
                // A repair's corrected engage still carries forward the
                // ORIGINAL cover's `pin`, not this attempt's locally
                // revalidated `pin`: `pin` (the struct field) records when
                // the SERVER IP was resolved, a fact independent of which
                // ECH resolver this attempt's permit needs — `revalidate`
                // only ever downgrades (`Answered` -> `ResolverDeselected`),
                // so persisting an already-downgraded value here would make
                // that loss permanent, unrecoverable even once the original
                // resolver returns to `dns.servers`. A fresh (non-repair)
                // engage has no prior cover to preserve, so `pin` (fresh
                // from resolve, or a first same-host reuse) is correct as-is.
                let engaged_pin = repair_fallback.map_or(pin, |(_, original_pin)| original_pin);
                match self.routing.install_failclosed_cover(server_ip, ech_resolver_permit) {
                    Ok(cover) => {
                        self.posture.hold_pending(BlockedStart {
                            cover,
                            host: config.server.server.expose().to_string(),
                            server_ip,
                            pin: engaged_pin,
                            resolver_permit: ech_resolver_permit,
                        });
                    }
                    Err(e) => {
                        if let Some((old_permit, original_pin)) = repair_fallback {
                            match self.routing.install_failclosed_cover(server_ip, old_permit) {
                                Ok(cover) => {
                                    self.posture.hold_pending(BlockedStart {
                                        cover,
                                        host: config.server.server.expose().to_string(),
                                        server_ip,
                                        pin: original_pin,
                                        resolver_permit: old_permit,
                                    });
                                    // The restored permit is stale either way, but which
                                    // direction it's stale in depends on whether the fetch
                                    // this attempt needs an ECH resolver at all: widening
                                    // repairs (`Holes`) restore something narrower than
                                    // needed, so the fetch may stall; narrowing repairs
                                    // (`None`/`Operators`, no fetch this cover permits
                                    // anyway) instead restore something WIDER than needed —
                                    // a live kill-switch permit for an address nothing
                                    // dials, not a stall risk.
                                    if matches!(effective_ech_doh, crate::proxy::plugin::EffectiveEchDoh::Holes) {
                                        warn!(
                                            error = %e,
                                            "failed to engage the corrected fail-closed cover; restored the \
                                             PREVIOUS permit instead of leaving the host open — ex-ray's ECH \
                                             fetch may still stall against the now-stale permit"
                                        );
                                    } else {
                                        warn!(
                                            error = %e,
                                            ?old_permit,
                                            "failed to engage the corrected fail-closed cover; restored the \
                                             PREVIOUS permit instead of leaving the host open — the fail-closed \
                                             cover still permits a resolver address this attempt no longer needs"
                                        );
                                    }
                                    self.last_error = Some(e.to_string());
                                }
                                Err(e2) => {
                                    warn!(
                                        error = %e,
                                        restore_error = %e2,
                                        "failed to engage BOTH the corrected and the previous fail-closed \
                                         cover; host NOT blocked, proceeding open"
                                    );
                                    self.last_error = Some(e.to_string());
                                }
                            }
                        } else {
                            warn!(error = %e, "failed to engage fail-closed cover on covered start; host NOT blocked, proceeding open");
                            self.last_error = Some(e.to_string());
                        }
                    }
                }
            }
        } else if covered {
            // Covered retry after the user enabled lockdown mid-blocked-state:
            // release the held cover. This opens egress until the standing lockdown
            // cover engages at routing.install — a brief, disclosed open window.
            if self.posture.take_pending().is_some() {
                warn!(
                    "covered retry with lockdown newly enabled: releasing the held cover; the host is briefly \
                     uncovered until the standing lockdown cover engages at connect"
                );
            }
        } else if self.posture.take_pending().is_some() {
            // Manual (uncovered) connect or reload-while-blocked: fail-open by
            // design. Releasing the held cover opens egress — logged so the fail-open
            // has a visible disposition, never a silent drop.
            warn!("uncovered start while blocked: releasing the held cover (host fail-open by design)");
        }
        // Whether THIS attempt still holds a transient cover after the
        // release/reuse decisions above — read once here so `start_inner`
        // (which can never observe `Posture::Session`, only `Idle`/
        // `PendingStart`) gets an explicit bool instead of recomputing it
        // from session state.
        let transient_pending = self.posture.pending().is_some();

        // Disclosed residual (see CONTRIBUTING.md's "Transient cutover
        // cover" section) gated on `effective_ech_doh`, the value that will
        // ACTUALLY reach ex-ray: `Holes` still stalls only if a repair's
        // restore left the LIVE held permit different from what this
        // attempt needs (`live_permit != ech_resolver_permit`); `Operators(url)`
        // always stalls, since the cover never permits an operator-chosen
        // address; `None` never stalls (no fetch is attempted) but a
        // repair's restore can still leave the LIVE permit WIDER than this
        // attempt needs — the opposite residual direction, a kill-switch
        // widening rather than a stall risk.
        if let Some(live_permit) = self.posture.pending().map(|b| b.resolver_permit) {
            match &effective_ech_doh {
                crate::proxy::plugin::EffectiveEchDoh::None => {
                    if live_permit.is_some() {
                        warn!(
                            ?pin,
                            ?live_permit,
                            "covered start: the fail-closed cover still permits a resolver address this \
                             attempt does not need (a repair's restore left it stale); the kill switch is \
                             wider than the current config requires"
                        );
                    }
                }
                crate::proxy::plugin::EffectiveEchDoh::Holes => {
                    if live_permit != ech_resolver_permit {
                        warn!(
                            ?pin,
                            ech_doh_url = ?ech_doh.as_ref().map(|e| &e.url),
                            ?live_permit,
                            ?ech_resolver_permit,
                            "covered start: the ECH-config fetch will dial a resolver the fail-closed cover \
                             does not permit (a repair's restore left it stale); it may stall to ex-ray's \
                             client timeout"
                        );
                    }
                }
                crate::proxy::plugin::EffectiveEchDoh::Operators(url) => {
                    warn!(
                        operator_ech_doh = %url,
                        "covered start: the plugin's own ech-doh overrides Hole's and dials a resolver the \
                         fail-closed cover does not permit; it may stall to ex-ray's client timeout"
                    );
                }
            }
        }

        debug!("awaiting start_inner");
        let result: Result<RunningState<P, R, D>, ProxyError> = Self::start_inner(
            &self.proxy,
            &self.routing,
            &self.dns,
            config,
            server_ip,
            ech_doh,
            transient_pending,
            lockdown_on,
            self.state_dir.as_deref(),
            self.state_owner,
            cancel,
        )
        .await;

        // Commit (or record the error) in the outer function, so the
        // only path that commits a session via `Posture::commit_session` is
        // strictly after start_inner has completed successfully.
        match result {
            Ok(state) => {
                // Tunnel is up: release the block-until-connected cover (drop →
                // disengage; already None when lockdown subsumed it — the standing
                // lockdown cover holds instead).
                drop(self.posture.take_pending());
                let server_ip = state.server_ip;
                self.udp_proxy_available = state.udp_proxy_available;
                self.ipv6_bypass_available = state.ipv6_bypass_available;
                let udp_proxy_available = self.udp_proxy_available;
                let ipv6_bypass_available = self.ipv6_bypass_available;
                self.posture.commit_session(state);
                self.active_config = Some(config.clone());
                self.last_error = None;
                let diag = ProxyStartedDiag {
                    server: token_for(&config.server.id),
                    server_kind: server_kind(config.server.server.expose()),
                    server_family: server_ip.map(ip_family),
                    server_scope: server_ip.map(ip_scope),
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
                // User asked to cancel: release the cover (same trust as a user
                // disconnect). Do NOT set last_error on cancel.
                drop(self.posture.take_pending());
                info!("proxy start cancelled");
                Err(ProxyError::Cancelled)
            }
            Err(e) => {
                // Covered start failed: RETAIN the held cover (the posture keeps
                // it as `PendingStart`, so its Drop does NOT run) — the host stays
                // blocked, not leaked, until a later successful start, a user
                // stop/cancel, or a bridge restart. A retry reuses this single held
                // guard and its resolved IP.
                self.last_error = Some(e.to_string());
                Err(e)
            }
        }
    }

    /// Resolve the proxy server's hostname to an IP over PRIVATE DoH using the
    /// configured `dns.servers` — never the OS resolver — for EVERY start,
    /// independent of `dns.enabled`. Fail-closed unless `dns.allow_insecure_bootstrap`.
    /// The hostname stays the SNI name; only the route + plugin handoff use the IP.
    /// Host logged here, not in the error, so the PII-free toast omits it.
    async fn resolve_server_ip(
        config: &ProxyConfig,
        bootstrap_querier: &Option<std::sync::Arc<dyn crate::dns::bootstrap::DohQuerier>>,
        cancel: &CancellationToken,
    ) -> Result<crate::dns::bootstrap::Bootstrapped, ProxyError> {
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        let res = match bootstrap_querier {
            Some(q) => {
                crate::dns::bootstrap::resolve_via_doh_with(config.server.server.expose(), &config.dns, q.clone()).await
            }
            None => crate::dns::bootstrap::resolve_via_doh(config.server.server.expose(), &config.dns).await,
        };
        Ok(res.inspect_err(|e| {
            warn!(
                server = %token_for(&config.server.id),
                server_kind = server_kind(config.server.server.expose()),
                error = %e,
                "DoH bootstrap resolution failed"
            )
        })?)
    }

    /// Produce a [`RunningState`] without touching `self`.
    ///
    /// **Cooperative cancellation.** Each long-running phase
    /// observes the supplied `cancel` token and returns
    /// `Err(ProxyError::Cancelled)` cooperatively. Earlier RAII guards
    /// drop in reverse-declaration order when the function returns Err,
    /// tearing down anything that was constructed before the cancel
    /// observation (listed in declaration order — later items drop first):
    ///
    /// 1. `PluginChain` — on drop, cancels its garter token and clears
    ///    the plugin state file.
    /// 2. `P::Running` — on drop, aborts the spawned proxy task.
    /// 3. `R::Installed` — on drop, tears down routes and clears the
    ///    crash-recovery state file.
    /// 4. `Option<R::Cover>` (lockdown) — declared last, so it drops first,
    ///    before `R::Installed`; disengages the standing cover (only `Some`
    ///    when intent is on and engage already succeeded). On the fail-FATAL
    ///    engage `?` it is never constructed, so only `R::Installed` tears down.
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
    ///   threaded into `run_forwarder_self_test`, which races its one walk
    ///   against cancel in a `biased` `select!` (cancel checked first on
    ///   every poll) and drops the in-flight walk on cancel rather than
    ///   waiting for it.
    /// - **Phase 5 (Dispatcher::new)**: cooperative — the token is threaded
    ///   in, and the device build runs on `spawn_blocking` raced against it
    ///   in a `biased` `select!`. It is no longer millisecond-scale: the
    ///   build waits for the TUN interface's IPv6 half to appear, and on a
    ///   covered start a Cancel the phase could not observe would extend the
    ///   window during which the host is fail-closed. On cancel the blocking
    ///   task finishes and drops its own `Device`; nothing is
    ///   future-drop-cancelled.
    /// - **Phase 6 (routing.install)**: sync; cancel observed at the phase
    ///   boundary only (`if cancel.is_cancelled()`). Mid-call preemption
    ///   isn't structurally possible — the netsh/route shell-outs are
    ///   uninterruptible from our process.
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
    // DI params (the proxy/routing/dns seams + config + cancel + the owner and
    // test-querier seams); bundling into a struct adds more noise than the warning.
    #[allow(clippy::too_many_arguments)]
    async fn start_inner(
        proxy: &P,
        routing: &R,
        dns: &D,
        config: &ProxyConfig,
        server_ip: IpAddr,
        ech_doh: Option<crate::dns::ech::EchDoh>,
        // Whether THIS attempt still holds a transient (block-until-connected)
        // cover, snapshotted by the caller before this call — `start_inner`
        // can only ever be reached with `Posture::Idle` or `PendingStart`
        // (never `Session`), so this bool is the whole of what the outer
        // posture can tell phase 4's reachability-probe gate below.
        transient_pending: bool,
        // `ProxyManager::standing_cover_expected`, derived ONCE by the caller
        // (which also used it to decide whether to engage the transient cover),
        // so this start cannot answer the question two ways.
        standing_cover_expected: bool,
        state_dir: Option<&std::path::Path>,
        owner: Option<(u32, u32)>,
        cancel: CancellationToken,
    ) -> Result<RunningState<P, R, D>, ProxyError> {
        debug!("start_inner entered");
        // Pre-flight: short-circuit a pre-cancelled token before any work.
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }

        // `server_ip` is resolved by the caller (`start_cancellable`) via private
        // DoH BEFORE this fn, so the fail-closed cover can be owned in the outer
        // scope — un-leakable by construction: `start_inner`'s many `?` exits
        // cannot drop a cover they never hold.
        let server_host = crate::dns::bootstrap::handoff_host(server_ip);

        // Phase 1: start plugin chain via Garter if a plugin is configured.
        // `start_plugin_chain` threads `cancel` through to its readiness
        // wait + bind_ephemeral retries.
        let plugin_chain = if let Some(ref plugin_name) = config.server.plugin {
            let plugin_path = crate::proxy::config::resolve_plugin_path(plugin_name);
            let chain = crate::proxy::plugin::start_plugin_chain(
                plugin_name,
                &plugin_path,
                config.server.plugin_opts.as_deref(),
                &server_host,
                config.server.server_port,
                state_dir,
                owner,
                config.diagnostic_plugin_tap,
                &cancel,
                ech_doh.as_ref(),
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
            Some(build_ss_config(config, plugin_local, server_ip, None)?)
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
                lockdown: None,
                proxy: running_proxy,
                server_ip: Some(server_ip),
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

        // Query the OS default gateway via the routing provider.
        let gw_info = routing.default_gateway(server_ip)?;

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
                    let ss_config = build_ss_config(config, plugin_local, server_ip, Some(port))
                        .map_err(proxy_start_err_to_io_err)?;
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
        // observes cancel cooperatively: its one walk races cancel in a
        // biased `select!`, checked before every poll of the walk (#397).
        if let Some(fwd) = forwarder.as_ref() {
            // Race an out-of-band reachability probe against the self-test so it
            // adds NO latency. Skip it under an active fail-closed cover — this
            // start's engaged transient cover, a pre-existing/adopted standing
            // one THIS PROCESS never released (measured, not recalled from
            // session state — a standing cover from a crashed prior run is
            // `Idle` here but still live on the host), or one this bridge is
            // ABOUT to install (`standing_cover_expected`, since routing.install
            // for the standing cover runs after this gate) — because Hole's
            // OWN cover would classify the probe's egress as blocked and
            // mis-report it as censorship; keep the original self-test reason
            // instead.
            let cover = routing.lockdown_cover_presence();
            let cover_active = suppresses_reachability_probe(cover, transient_pending, standing_cover_expected);
            let probe = (!cover_active).then(|| {
                // The DoH-resolved IP, never the proxy domain: the reachability
                // probe must not OS-resolve the hostname (that would reopen the
                // DNS leak this feature closes).
                let host = server_ip.to_string();
                let token = token_for(&config.server.id);
                let port = config.server.server_port;
                let plugin = config.server.plugin.clone();
                let opts = config.server.plugin_opts.clone();
                let pc = cancel.child_token();
                // Hold a clone to wind the probe down cooperatively on the paths
                // that don't await its verdict.
                let stop = pc.clone();
                let handle = tokio::spawn(async move {
                    crate::reachability::probe_server_reachability(
                        &host,
                        port,
                        &token,
                        plugin.as_deref(),
                        opts.as_deref(),
                        &pc,
                    )
                    .await
                });
                (handle, stop)
            });

            let outcome = run_forwarder_self_test(
                std::sync::Arc::clone(fwd),
                config.dns.servers.clone(),
                config.diagnostic_plugin_tap,
                cancel.clone(),
            )
            .await;
            match outcome {
                // Self-test passed: cancel the probe token.
                SelfTestOutcome::Ok { .. } => {
                    if let Some((_, stop)) = probe {
                        stop.cancel();
                    }
                }
                // The user asked for the cancel; stop the probe and propagate.
                SelfTestOutcome::Cancelled => {
                    if let Some((_, stop)) = probe {
                        stop.cancel();
                    }
                    return Err(ProxyError::Cancelled);
                }
                // The forwarder failed: await the concurrent probe's verdict and
                // reclassify the error. It ran in parallel, so the wait is at most
                // the probe's remaining budget, not its full duration on top.
                // `elapsed_ms` rides in the outcome, measured by the self-test
                // itself, so the duration in the user's sentence can never grow
                // to include this wait.
                SelfTestOutcome::Failed {
                    attempts,
                    elapsed_ms,
                    reason,
                } => {
                    let verdict = match probe {
                        Some((handle, _stop)) => match handle.await {
                            Ok(v) => Some(v),
                            // The probe's verdict outranks the self-test's own
                            // reading, so losing it degrades the report — WARN,
                            // or the downgrade is invisible at the default level.
                            Err(e) => {
                                warn!(%e, "reachability probe task did not complete; its verdict is unavailable");
                                None
                            }
                        },
                        None => None,
                    };
                    // A cancel that fired during the gate makes the probe return
                    // Inconclusive; surface it as Cancelled, not a server toast.
                    if cancel.is_cancelled() {
                        return Err(ProxyError::Cancelled);
                    }
                    // Checked against the pre-verdict `reason` AND `verdict`
                    // directly (not against the FINAL `ProxyError`): once
                    // `InconclusiveTransport` and `Other` both collapse into
                    // `ForwarderSelfTestFailed`, that value alone can no
                    // longer tell them apart — see `implicates_plugin_transport`'s doc.
                    if implicates_plugin_transport(&reason, verdict) {
                        report_plugin_output(plugin_chain.as_ref().map(|c| &**c.log()));
                    }
                    return Err(self_test_error_for(verdict, attempts, elapsed_ms, reason));
                }
            }
        }

        // Phase 5: cancel checkpoint before Dispatcher::new, which then
        // observes the token cooperatively while the device is built.
        if cancel.is_cancelled() {
            return Err(ProxyError::Cancelled);
        }
        // Start the dispatcher (owns TUN device + smoltcp). Skipped
        // under #[cfg(test)] because creating a TUN requires elevation.
        #[cfg(not(test))]
        let mut dispatcher = match crate::dispatcher::Dispatcher::new(
            socks5_port,
            gw_info.interface_index,
            gw_info.ipv6_available,
            config.server.plugin.clone(),
            udp_proxy_available,
            ruleset,
            local_dns_endpoint,
            &cancel,
        )
        .await?
        {
            Some(d) => Some(d),
            None => return Err(ProxyError::Cancelled),
        };
        #[cfg(test)]
        let mut dispatcher: Option<crate::dispatcher::Dispatcher> = {
            let _ = ruleset; // suppress unused warning
            let _ = local_dns_endpoint;
            None
        };

        // The identity of the TUN device this start opened — the LUID and
        // alias of the concrete OS object, never a name lookup. Threaded to
        // `Dns::apply` below.
        //
        // Under `#[cfg(test)]` the dispatcher is stubbed out (creating a
        // real TUN needs elevation), so no `hole-tun` exists on a clean
        // machine — a synthetic identity stands in instead. This is what
        // makes Phase 7 reachable and observable from a unit test on any
        // machine, not just one with a leftover `hole-tun`. The
        // alternative — resolving the alias via a raw OS call here instead
        // of threading the identity through — would be wrong on both
        // safety grounds (a name lookup can resolve to someone else's
        // adapter) and testability grounds (nothing to substitute in a
        // unit test).
        #[cfg(not(test))]
        let tun_identity = dispatcher
            .as_ref()
            .expect("dispatcher is always Some on the production (#[cfg(not(test))]) path")
            .identity()
            .clone();
        #[cfg(test)]
        let tun_identity = tun_engine::TunIdentity::synthetic(0xFEED, WINDOWS_TUN_ALIAS);

        // The TUN's IPv6 verdict, read here because `Engine::build` has
        // already consumed the device by now. `Ipv6StackAbsent` is the second
        // operand of the route-install fatality rule: the IPv6 route adds are
        // non-fatal when the upstream has no IPv6 OR the TUN interface has no
        // IPv6 half.
        let tun_ipv6 = dispatcher.as_ref().and_then(|d| d.ipv6_assigned());

        // Phase 6: cancel checkpoint before routing.install (sync; mid-
        // call preemption isn't structurally possible — netsh/route
        // shell-outs are uninterruptible from our process).
        if cancel.is_cancelled() {
            if let Some(mut d) = dispatcher.take() {
                d.shutdown().await;
            }
            return Err(ProxyError::Cancelled);
        }
        // Install the routes — NOW traffic starts flowing to the TUN.
        let routes = match routing.install(&tun_identity, server_ip, &gw_info) {
            Ok(routes) => routes,
            Err(e) => {
                if let Some(mut d) = dispatcher.take() {
                    d.shutdown().await;
                }
                return Err(e.into());
            }
        };
        info!(
            ?tun_ipv6,
            ipv6_upstream = gw_info.ipv6_available,
            "TUN routes installed"
        );

        // Process image paths for the standing lockdown cover's own
        // App-ID permit (`routing.install_lockdown` below) — see
        // `lockdown_app_ids`'s doc.
        let app_ids = lockdown_app_ids(config);

        // Re-read the intent fresh, right before the install it gates:
        // `standing_cover_expected` was snapshotted by the caller before
        // plugin-chain/DNS-bootstrap/TUN-device work that can take long
        // enough for an explicit `hole bridge unlock`-equivalent (the tray's
        // Unblock, `handle_unblock`) to land on a second, lock-free path in
        // between. A fresh `Off` overrides the stale `true` so a start that
        // began before an unblock cannot install a cover after it; any other
        // fresh read (`On`, `Unreadable`, `Unset`) leaves the snapshot's own
        // verdict (which already folded in `adopted_standing_cover`) alone.
        // This narrows, never widens, the window a full lock would close —
        // the remaining gap is the same class of race #878 tracks and this
        // plan does not fix.
        let standing_cover_expected = match state_dir.map(lockdown_state::load_intent) {
            Some(Intent::Off) => false,
            _ => standing_cover_expected,
        };

        // Standing lockdown cover (#527). Engaged only when intent is on; when
        // off this whole block is a no-op and the start is byte-identical to
        // today. Engaged AFTER routing.install (TUN exists => LUID resolvable)
        // and BEFORE Dns::apply, so the line is held the moment routes go live.
        // FAIL-FATAL: an engage error under intent-on aborts the start; the
        // locally-owned `routes` guard (declared above) Drops on the Err
        // unwind, tearing down — the opposite of the transient cover's
        // fail-open. Committed only on the Ok path (the field below).
        let lockdown = if standing_cover_expected {
            match routing.install_lockdown(server_ip, &tun_identity, &app_ids) {
                Ok(cover) => {
                    promote_adopted_claim(state_dir, owner);
                    Some(cover)
                }
                Err(e) => {
                    if let Some(mut d) = dispatcher.take() {
                        d.shutdown().await;
                    }
                    return Err(e.into());
                }
            }
        } else {
            None
        };

        // Phase 7: confine DNS egress to hole-tun and advertise the
        // configured resolver IPs on it, AFTER routes install so the OS
        // "best-route to DNS server" lookup resolves through the TUN.
        // OS UDP/53 to those IPs routes into hole-tun and is intercepted by
        // the in-TUN LocalDnsEndpoint; OS TCP/53 falls through the proxy
        // cascade to the real resolver over the tunnel. (No loopback :53
        // server.) Pass the FULL list, not a v4 filter: `set_servers`
        // advertises both the v4 and v6 families from their own entries (an
        // unconfigured family is left untouched), so a mixed or v6 resolver
        // list is carried end-to-end on both platforms.
        //
        // FAIL-FATAL on both error shapes: after #846 removed the
        // upstream-adapter rewrite, the WFP confinement (Windows) is the
        // ONLY thing standing between OS DNS and the LAN resolver — a
        // degraded-but-running session here would be a silent leak on a
        // session the UI reports as connected. `Cancelled` and every other
        // `DnsError` unwind the locally-owned `lockdown` / `routes` guards.
        let dns_applied = if forwarder.is_some() {
            let advertise_ips: Vec<IpAddr> = config.dns.servers.clone();
            // Ground truth for D4's filter: exactly the families `routes`
            // itself confirmed landed, read directly off the guard — no OS
            // probe, no second measurement , decision D4; see `RoutesInstalled::routed_families`).
            let routed = routes.routed_families();
            match dns
                .apply(advertise_ips, routed, tun_identity, server_ip, cancel.clone())
                .await
            {
                Ok(a) => Some(a),
                Err(DnsError::Cancelled) => {
                    if let Some(mut d) = dispatcher.take() {
                        d.shutdown().await;
                    }
                    return Err(ProxyError::Cancelled);
                }
                #[cfg(target_os = "windows")]
                Err(DnsError::Confine(e)) => {
                    if let Some(mut d) = dispatcher.take() {
                        d.shutdown().await;
                    }
                    return Err(ProxyError::DnsConfinementFailed { reason: e.to_string() });
                }
                Err(DnsError::Io(e)) => {
                    if let Some(mut d) = dispatcher.take() {
                        d.shutdown().await;
                    }
                    return Err(ProxyError::Runtime(e));
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
            lockdown,
            proxy: running_proxy,
            server_ip: Some(server_ip),
            started_at: Instant::now(),
            udp_proxy_available,
            ipv6_bypass_available: gw_info.ipv6_available,
            traffic_window: None,
        })
    }

    /// Back-compat shim: a plain stop is a user stop (target moves to `Off`,
    /// which releases the standing cover).
    pub async fn stop(&mut self) -> Result<(), ProxyError> {
        self.stop_with(SessionEvent::UserStopped).await
    }

    /// Stop the proxy in response to `event`. The standing lockdown cover's
    /// fate is no longer read off `event` directly — it comes from
    /// [`cover_step`], decided against the *persisted* [`Target`] `event`
    /// moves it to (see [`persist_session_event`](Self::persist_session_event)).
    /// Routes/DNS/proxy/plugin tear down identically regardless of `event`.
    ///
    /// One exhaustive match over the posture taken from `self`, replacing it
    /// with `Idle` up front: `Idle` is a no-op; `PendingStart` decides the
    /// held transient cover's fate directly from `event` (this is the
    /// bounded-window failclosed cover, a wholly separate mechanism from the
    /// standing one `cover_step` governs — see `apply_cover_step`); `Session`
    /// runs the full teardown below.
    pub async fn stop_with(&mut self, event: SessionEvent) -> Result<(), ProxyError> {
        let target = self.persist_session_event(event).await;

        match std::mem::replace(&mut self.posture, Posture::Idle) {
            Posture::Idle => Ok(()),
            Posture::PendingStart(b) => {
                // Fate of a block-until-connected cover a failed covered start
                // left engaged. Clear the stale error/death so a
                // Disconnect-from-blocked lands the same clean state a normal
                // stop does.
                match transient_cover_disposition(event) {
                    CoverDisposition::ReleaseNow => drop(b.cover),
                    CoverDisposition::KeepEngaged => b.cover.disarm(),
                }
                self.last_error = None;
                self.death_reason = None;
                Ok(())
            }
            Posture::Session(mut state) => {
                // Taken via a field access on `state`, not the destructuring
                // pattern below, so this stays the ONE reader
                // `no_bridge_source_derives_cover_state_from_a_session`'s
                // guard matches — a pattern-destructuring read is invisible
                // to that regex, and would leave it matching zero call
                // sites instead of the sanctioned one.
                let lockdown = state.lockdown.take();
                let RunningState {
                    dns,
                    dispatcher,
                    plugin_chain,
                    proxy,
                    routes,
                    ..
                } = *state;

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
                    match d.shutdown().await {
                        exit @ (crate::dispatcher::DriverExit::Drained
                        | crate::dispatcher::DriverExit::AlreadyDrained) => {
                            debug!(?exit, "dispatcher driver exited");
                        }
                        exit => warn!(?exit, "dispatcher driver did not exit cleanly"),
                    }
                }

                // 2. Stop plugin chain: reap the tracked identities explicitly — the
                // reap is the ONLY thing allowed to delete the state file, and only
                // once it has accounted for every record — then drop, which just
                // cancels the chain's token and aborts its task. Drop must not touch
                // the file: the abort cannot know whether teardown finished, so a
                // clear there would forget still-live plugins.
                if let Some(ref chain) = plugin_chain {
                    chain.kill_tracked();
                }
                drop(plugin_chain);

                // 3. Graceful proxy shutdown (stops SS SOCKS5).
                let res = proxy.stop().await;

                // 4. Routes tear down via RAII Drop.
                drop(routes);

                // 5. Standing lockdown cover: decided by `cover_step` against
                // the target `event` just moved us to, not by `event` itself.
                let presence = self.routing.lockdown_cover_presence();
                let intent = self.effective_lockdown_intent();
                let disposition = teardown_cover_disposition(event, intent, presence, &target);
                self.apply_cover_disposition(disposition, lockdown);

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

                // Clear any error from a previous failed start (#142) — except
                // on a GaveUp teardown: `check_health` just set last_error/
                // death_reason to explain why THIS session ended (#470), and
                // clearing them here would erase that explanation before the
                // GUI/toast ever reads it.
                if !event.preserves_death_reason() {
                    self.last_error = None;
                    self.death_reason = None;
                }
                self.active_config = None;
                self.udp_proxy_available = true;
                self.ipv6_bypass_available = true;
                info!("proxy stopped");
                res
            }
        }
    }

    /// Fold `adopted_standing_cover` into the persisted lockdown intent the
    /// same way `lockdown_enabled()`/`standing_cover_expected()` already do.
    /// Boot-time crash recovery (`route_recovery::record_recovery_outcome`)
    /// calls `set_standing_cover_adopted(true)` on a live-cover finding
    /// WITHOUT touching the intent file, so a raw `load_intent()` here would
    /// read `Unset`/`Off` for an adopted-but-unpersisted cover and
    /// `cover_step` would incorrectly release it.
    pub(crate) fn effective_lockdown_intent(&self) -> Intent {
        let intent = self
            .state_dir
            .as_deref()
            .map(lockdown_state::load_intent)
            .unwrap_or(Intent::Unset);
        if !matches!(intent, Intent::Off) && self.adopted_standing_cover {
            Intent::On
        } else {
            intent
        }
    }

    /// Act on a `cover_step` decision against the standing cover guard
    /// extracted from a torn-down `RunningState`.
    ///
    /// `Engage` is unreachable here: by the time a session's teardown runs,
    /// the TUN/routes it would need (`server_ip`, `TunIdentity`, `app_ids`)
    /// are already gone — engaging a fresh cover happens at connect time or
    /// at boot-time reconcile, never mid-teardown (`ipc::handle_lockdown`
    /// turning lockdown on mid-session only persists the intent; there is no
    /// `turn_lockdown_on`). Treating it like `Hold` is the safe direction:
    /// it never opens the host.
    fn apply_cover_disposition(&mut self, disposition: CoverDisposition, cover: Option<R::Cover>) {
        match disposition {
            CoverDisposition::ReleaseNow => {
                // The guard's own Drop can only WARN on a genuine OS failure
                // — Drop cannot return a value, and silence there is
                // indistinguishable from a clean release (see
                // `failclosed::Cover`'s Drop doc). Release via the fallible,
                // confirmable path FIRST — the same one the `Nobody` arm of
                // `turn_lockdown_off` uses — and clear the live-cover half of
                // the claim only on a CONFIRMED open host: a false clear here
                // is Rule #0 territory, the Unblock item disappearing exactly
                // when it is still needed.
                match self.routing.release_all_covers() {
                    Ok(()) => self.set_standing_cover_adopted(false),
                    Err(e) => tracing::warn!(
                        error = %e,
                        "lockdown cover release could not be confirmed; keeping the escape visible"
                    ),
                }
                drop(cover);
            }
            CoverDisposition::KeepEngaged => {
                if let Some(c) = cover {
                    c.disarm();
                }
            }
        }
    }

    /// Move the persisted [`Target`] according to `event` and return the new
    /// value. Runs before any teardown so `cover_step` below always sees the
    /// post-event target, never a stale pre-write one — `cover_step`'s
    /// `Target::Off` arm ignores intent entirely while `Target::Connected`'s
    /// arm is intent-dependent, so which arm applies must already reflect
    /// `event`.
    async fn persist_session_event(&mut self, event: SessionEvent) -> Target {
        let Some(state_dir) = self.state_dir.clone() else {
            // No file to consult, so `target_after` needs a stand-in. It must
            // be `Unreadable`, not `Off`: `Off` is a DECIDED target that
            // `cover_step` acts on (its `Off` arm ignores intent and releases
            // a live cover), which would turn every blip on a state-dir-less
            // manager into a kill-switch teardown. `Unreadable` authorises
            // neither surface, so the cover holds. `UserStopped`/`GaveUp` are
            // unaffected — `target_after` collapses both to `Off` from any
            // prior value.
            return target_after(Target::Unreadable, event);
        };
        let owner = self.state_owner;
        let outcome = tokio::task::spawn_blocking(move || {
            target::apply(&state_dir, owner, move |current| target_after(current, event))
        })
        .await;
        match outcome {
            Ok(Ok(new_target)) => new_target,
            Ok(Err(e)) => {
                tracing::error!(
                    error = %e,
                    "failed to persist target after session event; reading current disk state instead of guessing"
                );
                self.state_dir.as_deref().map(target::load).unwrap_or(Target::Off)
            }
            Err(e) => {
                tracing::error!(error = %e, "target-persistence task panicked; treating target as unreadable");
                Target::Unreadable
            }
        }
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
            if let Some(state) = self.posture.session() {
                if let Some(ref dispatcher) = state.dispatcher {
                    dispatcher.swap_rules(new_ruleset);
                }
            }
            self.active_config = Some(config.clone());
            info!("filter rules hot-swapped");
            Ok(())
        } else {
            // Slow path: full stop + start. Not a real disconnect — a
            // hot-swap-incapable config edit — so the target must not move
            // to `Off`. `Blipped`'s "reconciliation working, not a decision
            // to disconnect" semantics fit; `cover_step`'s `Connected`+`On`+
            // `Live` arm then holds the standing cover live across the gap,
            // rather than the old code's unconditional disengage-then-
            // re-engage (which briefly opened the host on every structural
            // reload).
            self.stop_with(SessionEvent::Blipped).await?;
            self.start(config).await
        }
    }

    /// Sync health check: detects a proxy task that exited on its own
    /// (e.g. shadowsocks panic or upstream connection failure). Performs no
    /// teardown itself — it only records the failure and reports it as a
    /// [`SessionEvent::GaveUp`] for the caller to feed into
    /// [`Self::stop_with`], so the give-up path and the cover decision it
    /// drives share the one teardown implementation instead of a hand-copy.
    ///
    /// **Error-discard note**: this function cannot await the dead
    /// handle, so the underlying task's `io::Result` is discarded.
    /// Callers that need the task's error must use `stop_with().await`
    /// instead. Not made async because every caller would then have to
    /// be made async too.
    pub fn check_health(&mut self) -> Option<SessionEvent> {
        let state = self.posture.session()?;
        if state.proxy.is_alive() {
            return None;
        }
        error!("proxy task exited unexpectedly");
        self.last_error = Some(DEATH_REASON.into());
        // Path-free death reason for the GUI status/toast (#470).
        self.death_reason = Some(DEATH_REASON);
        Some(SessionEvent::GaveUp)
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

/// Stable human-readable label for a `TunnelMode` — used by
/// `ProxyStartedDiag` so the dump output doesn't vary with Debug
/// formatting changes.
fn tunnel_mode_label(mode: &TunnelMode) -> &'static str {
    match mode {
        TunnelMode::Full => "full",
        TunnelMode::SocksOnly => "socks_only",
    }
}

/// Write the armed state to `bridge-lockdown.json` the moment an adopted claim
/// is first honoured by a real `install_lockdown`. A cover this bridge just
/// installed is first-hand evidence, stronger than the startup measurement
/// `decide_cover_recovery` grounds its own repair write in.
///
/// Promotes only over `Unset`/`Unreadable` — an intent already `On` needs no
/// write, and an explicit recorded `Off` must never be clobbered: it can race
/// this same start (an out-of-process `hole bridge unlock` writing `Off`
/// between `standing_cover_expected`'s snapshot and this call), and a claim is
/// never proof the intent is still unset.
///
/// Best-effort: the write only makes the preference durable, and failing the
/// connect over a bookkeeping error would be the worse trade.
fn promote_adopted_claim(state_dir: Option<&std::path::Path>, owner: Option<(u32, u32)>) {
    let Some(dir) = state_dir else {
        warn!("lockdown: standing cover installed with no state_dir; the kill switch cannot be persisted");
        return;
    };
    if matches!(
        lockdown_state::load_intent(dir),
        lockdown_state::Intent::On | lockdown_state::Intent::Off
    ) {
        return;
    }
    if let Err(e) = lockdown_state::set_enabled(dir, true, owner) {
        warn!(error = %e, "lockdown: could not persist the adopted kill switch; it will not survive this run");
    }
}

/// The process image paths the Windows lockdown cover permits by App-ID: the
/// resolved plugin binary (if a plugin is configured) and the bridge's own exe.
/// Empty on macOS (pf has no per-process matching). Path-keyed so the permit
/// survives a cutover rename.
fn lockdown_app_ids(config: &ProxyConfig) -> Vec<std::path::PathBuf> {
    #[cfg(not(target_os = "windows"))]
    {
        let _ = config;
        Vec::new()
    }
    #[cfg(target_os = "windows")]
    {
        let mut ids: Vec<std::path::PathBuf> = Vec::new();
        if let Some(ref plugin) = config.server.plugin {
            let resolved = crate::proxy::config::resolve_plugin_path(plugin);
            let path = std::path::PathBuf::from(&resolved);
            // `resolve_plugin_path` deliberately falls back to the bare
            // binary name when it can't find the plugin next to the bridge
            // exe, so shadowsocks can still do a PATH lookup at spawn — but
            // `FwpmGetAppIdFromFileName0` does no PATH search of its own and
            // needs a real file path. A bare name (no directory component)
            // narrows the permit set rather than breaking the cover; warn so
            // a bug report carries the signal, same disposition as the
            // `current_exe()` failure below.
            if path.parent().is_some_and(|d| !d.as_os_str().is_empty()) {
                ids.push(path);
            } else {
                warn!(plugin = %resolved, "lockdown: plugin path did not resolve to a real file; App-ID permit omitted");
            }
        }
        match std::env::current_exe() {
            Ok(exe) => ids.push(exe),
            // The bridge's own egress still rides the server-IP permit, so a
            // missing exe path narrows but does not break the cover. Warn so a
            // bug report carries the shrunken-permit-set signal.
            Err(e) => warn!(error = %e, "lockdown: current_exe() failed; bridge App-ID permit omitted"),
        }
        ids
    }
}

#[cfg(test)]
#[path = "proxy_manager_tests.rs"]
pub(crate) mod proxy_manager_tests;

#[cfg(test)]
#[path = "proxy_manager_release_tests.rs"]
mod proxy_manager_release_tests;

// E2E test platform policy:
//
// - **Non-galoshes** DistHarness e2e (`e2e_none`, lifecycle, cipher, and the
//   listener-selection tests) run on every Hole platform (Win+mac).
// - **galoshes-fronted** tests front a galoshes *server* via the garter
//   `ChainRunner` launcher (`plugin_e2e::ssserver`), which the `SsServerHandle`
//   fixture keeps alive for the test's lifetime. The socks-only WS/IPv6
//   roundtrips run on **Win+mac**; WS-TLS and QUIC are macOS-only (Windows
//   custom-cert limit), and the Full-mode `mod tun` variants are Windows-only
//   (`mod tun` is `cfg(target_os = "windows")` and needs elevation). Broader
//   galoshes transport coverage on Windows lives in the `plugin-e2e` crate.
// - Within `mod tun`, only the `_captures_unowned_destination` pair proves
//   tunnel transit. The `_local_networking_intact` pair and the listener
//   file's UDP test dial addresses the host holds, which never reach
//   `hole-tun`; they prove Full mode starts without breaking host-local
//   networking.
#[cfg(test)]
#[path = "proxy_manager_e2e_tests.rs"]
mod proxy_manager_e2e_tests;

// Session-level composition guard: a real Full-mode session started through
// the production path with the kill switch armed still carries its own
// tunnel traffic while an off-tunnel probe is blocked. See that module's doc
// for what it does and does not establish. Runs on both platforms Hole ships
// Full mode on — the elevated `tun` lane gates it
// (see that module's own doc), not a platform `cfg`.
#[cfg(test)]
#[path = "proxy_manager_live_tun_permit_e2e_tests.rs"]
mod proxy_manager_live_tun_permit_e2e_tests;

// a real Full-mode start's three OS-visible effects (utun,
// split routes, derived DNS config) and their clean removal, judged only by
// reading the OS back — never our own return values. macOS-only (the file is
// `#![cfg(target_os = "macos")]`); the module is still registered
// unconditionally so a non-macOS build still typechecks the `cfg`-gated
// contents.
#[cfg(test)]
#[path = "proxy_manager_macos_full_tunnel_privileged_tests.rs"]
mod proxy_manager_macos_full_tunnel_privileged_tests;

#[cfg(test)]
#[path = "proxy_manager_listener_e2e_tests.rs"]
mod proxy_manager_listener_e2e_tests;
