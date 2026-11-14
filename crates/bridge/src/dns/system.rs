//! System DNS apply + confine.
//!
//! The bridge advertises the configured resolver IPs on `hole-tun` (the
//! adapter it created, per `tun_engine::device::identity`) and, on Windows,
//! confines DNS egress to that adapter via `tun_engine::dns_confine`. On
//! macOS it publishes a supplemental resolver at a synthetic, session-scoped
//! `SCDynamicStore` key via `tun_engine::dns_steer`. Both mechanisms are
//! process-scoped and die with the bridge, so neither needs crash-recovery
//! state. DNS is written to no other adapter; `crate::dns_state` and
//! `crate::dns::recovery` cover the one exception, undoing an older build's
//! upstream-adapter rewrite after a crash.
//!
//! ## Fail-fatal
//!
//! On both platforms `apply` aborts the start if the confinement or steering
//! cannot engage, or the resolver IPs cannot be set: the confinement (Windows)
//! and the steering key (macOS) are the only things standing between OS DNS and
//! the LAN resolver, so a session that reports connected without them leaks DNS.
//!
//! ## macOS address families
//!
//! `advertise_ips` is filtered to the families the tunnel carries
//! ([`RoutedFamilies`]); an empty filtered list is refused rather than
//! advertising nothing. The steering key covers the whole machine, so the
//! TUN's alias plays no part in reaching it (see `apply_macos`).
//!
//! ## Cancellation
//!
//! `apply` checks `cancel` before engaging the confinement/steering and again
//! after: on Windows before setting resolvers, on macOS right after the engage
//! returns. A cancel after the engage drops it (Windows: the dynamic WFP
//! session ends with the guard; macOS: `withdraw`, best-effort) and returns
//! [`DnsError::Cancelled`]. Nothing is restored, since only `hole-tun` or the
//! steering key was ever touched.
//!
//! The mechanisms are described in
//! `docs/contributing/architecture/dns-forwarder.md#how-the-operating-system-reaches-it`.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;

use tokio_util::sync::CancellationToken;

use crate::dns_state::DnsPrior;

mod phase;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use phase::Cosmetic;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use phase::LeakBearing;

// Dns trait surface ===================================================================================================

/// Bridge-side system-DNS facade.
///
/// `Dns` and [`DnsApplied`] are the test-isolation seam for system-DNS
/// I/O, mirroring [`crate::proxy::Proxy`] and [`tun_engine::routing::Routing`].
/// Production goes through [`SystemDns`] (platform-specific); tests
/// substitute a mock via [`crate::proxy_manager::ProxyManager::new_with_dns`].
///
/// Callers outside the `SystemDns` impl may not call the platform free
/// functions: the workspace `clippy.toml` `disallowed_methods` rejects them,
/// as it does for the routing free functions. A helper that bypasses the
/// trait cannot be intercepted by the mock and would run real OS code from
/// unit tests (`docs/contributing/architecture/test-isolation.md`).
pub trait Dns: Send + Sync + 'static {
    /// RAII guard returned by [`apply`](Self::apply). Owns the confinement
    /// (Windows) or steering key (macOS) and the `DebugDropBomb`.
    ///
    /// Two teardown paths:
    ///
    /// - Preferred: call [`DnsApplied::shutdown`] (async) before drop, as
    ///   `ProxyManager::stop` does.
    /// - Fallback: `Drop`, synchronous, for crash or panic unwind. The
    ///   `DebugDropBomb` panics in debug builds if shutdown wasn't awaited,
    ///   so a missed shutdown fails the first test run.
    type Applied: DnsApplied;

    /// Confine DNS egress to `tun` and point the OS at `advertise_ips` (the
    /// configured upstream resolver IPs) on `tun` only. `server_ip` is the
    /// confinement's server permit: the tunnel's own handshake must stay
    /// reachable even when the server runs on port 53 (see
    /// `tun_engine::dns_confine::build_spec`).
    ///
    /// On Windows, `set_servers` splits `advertise_ips` per address family
    /// and sets the v4 and v6 families separately; a family with no
    /// entries is left untouched, never cleared. macOS instead publishes
    /// the mixed list (filtered by `routed` — see the module doc) at a
    /// synthetic supplemental-resolver key. OS UDP/53 to these IPs routes
    /// into `hole-tun` and is intercepted by the in-TUN `LocalDnsEndpoint`;
    /// OS TCP/53 takes the ordinary filter cascade to the real resolver, so
    /// the user's rule for that address decides its path. On Windows a
    /// `Bypass` rule fails: the confinement refuses the bypassed connect
    /// (bindreams/hole#1317).
    ///
    /// `routed` is the address families the tunnel is actually carrying —
    /// see [`RoutedFamilies`]. Windows ignores it (the WFP confinement
    /// blocks off-tunnel DNS egress regardless of family); macOS filters
    /// `advertise_ips` by it before publishing.
    ///
    /// **Cancellation.** The implementation checks `cancel.is_cancelled()`
    /// between the confinement/steering engage and the resolver-IP set (or,
    /// on macOS, immediately after the engage call returns), dropping the
    /// confinement/steering before returning [`DnsError::Cancelled`].
    fn apply(
        &self,
        advertise_ips: Vec<IpAddr>,
        routed: RoutedFamilies,
        tun: tun_engine::TunIdentity,
        server_ip: IpAddr,
        cancel: CancellationToken,
    ) -> impl std::future::Future<Output = Result<Self::Applied, DnsError>> + Send;
}

/// Which address families the tunnel is actually carrying, at the moment
/// [`Dns::apply`] runs. Read once from the routes `Routing::install` just
/// installed, never re-derived from the TUN's own IPv6 read-back or the
/// upstream gateway's IPv6 availability, which answer a different question.
/// Windows ignores it: the WFP confinement blocks off-tunnel DNS egress
/// regardless of family.
///
/// Defined in `tun-engine` and re-exported, since `hole-bridge` depends on
/// `tun-engine` and the only producer, `RoutesInstalled::routed_families`,
/// lives there.
pub use tun_engine::routing::RoutedFamilies;

/// RAII guard returned by [`Dns::apply`]. See [`Dns::Applied`] for the
/// shutdown contract.
pub trait DnsApplied: Send + 'static {
    /// Release the confinement (Windows) or withdraw the steering key
    /// (macOS), and flush the OS resolver cache.
    /// Async so the platform I/O can use `tokio::task::spawn_blocking` and
    /// never stall the runtime worker. Idempotent: calling twice is a
    /// no-op the second time.
    fn shutdown(&mut self) -> impl std::future::Future<Output = ()> + Send + '_;
}

/// Errors returned from [`Dns::apply`].
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    /// The cancel token fired during `apply`; any confinement or steering key
    /// was released (a failed macOS withdraw is best-effort and may leave the
    /// key published until the bridge exits).
    #[error("DNS apply cancelled")]
    Cancelled,

    /// Setting resolvers (Windows), publishing the steering key, or a panicked
    /// or cancelled blocking step failed, or no advertised resolver's address
    /// family is routed (macOS). A panicked or cancelled confine engage is
    /// reported here, not as [`DnsError::Confine`]. Always fatal (see the
    /// module doc).
    #[error("DNS apply failed: {0}")]
    Io(#[from] io::Error),

    /// The DNS-egress confinement could not be engaged (Windows only).
    /// Always fatal. `#[from]` (not just `#[source]`) so `phase::run`'s
    /// `E: Into<DnsError>` bound carries this variant through unchanged
    /// instead of collapsing it into `DnsError::Io` (see `phase.rs`).
    #[cfg(target_os = "windows")]
    #[error("could not confine DNS to the tunnel: {0}")]
    Confine(#[from] tun_engine::dns_confine::DnsConfineError),
}

// SystemDns ===========================================================================================================
//
// `SystemDns` carries a platform-specific backend trait object so tests
// can substitute a mock without touching the OS resolver. Mirrors
// [`tun_engine::routing::SystemRouting`].
//
// - Windows: `Arc<dyn WinDnsBackend>` + `Arc<dyn windows::DnsConfiner>`.
//   Production: `Win32Real` / `RealDnsConfiner`.
// - macOS: `Arc<dyn MacDnsBackend>`. Production: `Networksetup`.

/// Production [`Dns`] implementation.
#[derive(Clone)]
pub struct SystemDns {
    /// Win32 DNS backend. Production: [`windows::Win32Real`]; tests:
    /// substitute via [`Self::new_with_backend`].
    #[cfg(target_os = "windows")]
    backend: Arc<dyn windows::WinDnsBackend>,
    /// The DNS-egress confinement seam. Production:
    /// [`windows::RealDnsConfiner`]; tests: substitute via
    /// [`Self::new_with_backend`].
    #[cfg(target_os = "windows")]
    confiner: Arc<dyn windows::DnsConfiner>,
    /// macOS `networksetup` backend, used only for `flush`. Production:
    /// [`macos::Networksetup`]; tests: substitute via
    /// [`Self::new_with_mac_backend`].
    #[cfg(target_os = "macos")]
    backend: Arc<dyn macos::MacDnsBackend>,
    /// The DNS-steering seam. Production: [`macos::RealMacDnsSteerer`];
    /// tests: substitute via [`Self::new_with_mac_backend`].
    #[cfg(target_os = "macos")]
    steerer: Arc<dyn macos::MacDnsSteerer>,
}

impl Default for SystemDns {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemDns {
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "windows")]
            backend: Arc::new(windows::Win32Real),
            #[cfg(target_os = "windows")]
            confiner: Arc::new(windows::RealDnsConfiner),
            #[cfg(target_os = "macos")]
            backend: Arc::new(macos::Networksetup),
            #[cfg(target_os = "macos")]
            steerer: Arc::new(macos::RealMacDnsSteerer),
        }
    }

    /// Construct a [`SystemDns`] with a specific [`windows::WinDnsBackend`]
    /// and [`windows::DnsConfiner`] implementation. Used by
    /// `windows_tests.rs` to substitute mocks; production uses
    /// [`Self::new`].
    #[cfg(target_os = "windows")]
    pub fn new_with_backend(backend: Arc<dyn windows::WinDnsBackend>, confiner: Arc<dyn windows::DnsConfiner>) -> Self {
        Self { backend, confiner }
    }

    /// Construct a [`SystemDns`] with a specific [`macos::MacDnsBackend`]
    /// and [`macos::MacDnsSteerer`] implementation. Used by
    /// `macos_tests.rs` to substitute mocks; production uses [`Self::new`].
    #[cfg(target_os = "macos")]
    pub fn new_with_mac_backend(
        backend: Arc<dyn macos::MacDnsBackend>,
        steerer: Arc<dyn macos::MacDnsSteerer>,
    ) -> Self {
        Self { backend, steerer }
    }
}

impl Dns for SystemDns {
    type Applied = SystemDnsApplied;

    #[cfg(target_os = "windows")]
    async fn apply(
        &self,
        advertise_ips: Vec<IpAddr>,
        routed: RoutedFamilies,
        tun: tun_engine::TunIdentity,
        server_ip: IpAddr,
        cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        apply_windows(
            &self.backend,
            &self.confiner,
            advertise_ips,
            routed,
            tun,
            server_ip,
            cancel,
        )
        .await
    }

    #[cfg(target_os = "macos")]
    async fn apply(
        &self,
        advertise_ips: Vec<IpAddr>,
        routed: RoutedFamilies,
        tun: tun_engine::TunIdentity,
        server_ip: IpAddr,
        cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        let _ = server_ip;
        apply_macos(&self.backend, &self.steerer, advertise_ips, routed, tun, cancel).await
    }

    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    async fn apply(
        &self,
        _advertise_ips: Vec<IpAddr>,
        _routed: RoutedFamilies,
        _tun: tun_engine::TunIdentity,
        _server_ip: IpAddr,
        _cancel: CancellationToken,
    ) -> Result<Self::Applied, DnsError> {
        Ok(SystemDnsApplied {
            bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
            shutdown_completed: false,
        })
    }
}

/// Message stored in the `DebugDropBomb`. The `#[should_panic(expected =
/// ...)]` in `crate::dns::system::windows::windows_tests` matches this
/// exact string.
const BOMB_MSG: &str = "SystemDnsApplied dropped without awaiting shutdown()";

// Windows apply =======================================================================================================

#[cfg(target_os = "windows")]
async fn apply_windows(
    backend: &Arc<dyn windows::WinDnsBackend>,
    confiner: &Arc<dyn windows::DnsConfiner>,
    advertise_ips: Vec<IpAddr>,
    routed: RoutedFamilies,
    tun: tun_engine::TunIdentity,
    server_ip: IpAddr,
    cancel: CancellationToken,
) -> Result<SystemDnsApplied, DnsError> {
    let started = std::time::Instant::now();
    // Unused here — see `RoutedFamilies`'s and `Dns::apply`'s doc: the WFP
    // confinement below blocks off-tunnel DNS egress on both families
    // regardless of which the tunnel actually carries.
    let _ = routed;

    if cancel.is_cancelled() {
        return Err(DnsError::Cancelled);
    }

    // Confine DNS egress to hole-tun before advertising a resolver on it.
    // `LeakBearing`: `phase::run` propagates the error, keeping the
    // `DnsError::Confine` variant (see `phase.rs`).
    let confiner = Arc::clone(confiner);
    let luid = tun.luid();
    let confinement = phase::run::<LeakBearing, _, _>("confine", move || confiner.engage(luid, server_ip))
        .await?
        .expect("LeakBearing always returns Some on Ok — see phase.rs's doc");

    if cancel.is_cancelled() {
        // The confinement drops here (local variable going out of scope) —
        // nothing but this local guard reaches it, so dropping it IS the
        // whole disengage.
        return Err(DnsError::Cancelled);
    }

    // Address the adapter by the LUID of the device this process opened, never by
    // alias: on Windows the alias is the name Hole requested and never read
    // back, and a concurrent bridge's adapter can answer to it. With the
    // confinement up and no resolvers set, DNS is blacked out on a session the UI
    // reports as connected, so this step is `LeakBearing` too.
    let b = Arc::clone(backend);
    let ips = advertise_ips.clone();
    phase::run::<LeakBearing, _, _>("set-servers", move || b.set_servers(luid, &ips)).await?;

    // Flush. Best-effort — through the backend so MockBackend can count
    // it for the perf-regression test. `Cosmetic`: a failed cache flush
    // leaves a stale entry for one TTL window, not a leak.
    let b = Arc::clone(backend);
    let _ = phase::run::<Cosmetic, _, _>("flush", move || b.flush()).await;

    tracing::info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "apply_dns_settings done"
    );

    Ok(SystemDnsApplied {
        backend: Arc::clone(backend),
        confinement: Some(confinement),
        bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
        shutdown_completed: false,
    })
}

// macOS apply =========================================================================================================

#[cfg(target_os = "macos")]
async fn apply_macos(
    backend: &Arc<dyn macos::MacDnsBackend>,
    steerer: &Arc<dyn macos::MacDnsSteerer>,
    advertise_ips: Vec<IpAddr>,
    routed: RoutedFamilies,
    tun: tun_engine::TunIdentity,
    cancel: CancellationToken,
) -> Result<SystemDnsApplied, DnsError> {
    let started = std::time::Instant::now();
    // The steering key covers the whole machine, not one interface — unlike
    // Windows, which must resolve the LUID of the concrete adapter it owns
    // — so `tun` plays no role in reaching it. It stays a parameter only
    // for signature symmetry with `Dns::apply`; it is never read here.
    let _ = &tun;

    if cancel.is_cancelled() {
        return Err(DnsError::Cancelled);
    }

    // Advertise only resolvers whose address family has a live split route
    // (see `RoutedFamilies`). An empty result is refused rather than silently
    // publishing nothing.
    let filtered: Vec<IpAddr> = advertise_ips
        .into_iter()
        .filter(|ip| if ip.is_ipv6() { routed.v6 } else { routed.v4 })
        .collect();
    if filtered.is_empty() {
        return Err(DnsError::Io(io::Error::other(
            "no advertised DNS server's address family has a live split route; refusing to leave the OS on the LAN resolver",
        )));
    }

    // Publish the supplemental resolver key. `LeakBearing`: it is the only
    // thing steering OS DNS on macOS, so `phase::run` propagates a failure.
    let s = Arc::clone(steerer);
    let servers = filtered;
    let steering = phase::run::<LeakBearing, _, _>("dns-steer-engage", move || s.engage(&servers))
        .await?
        .expect("LeakBearing always returns Some on Ok — see phase.rs's doc");

    if cancel.is_cancelled() {
        // Withdraw before returning Cancelled — best-effort (`Cosmetic`): a
        // failed withdraw here does not change the Cancelled outcome, and
        // is not silent either (see `RealSteeringHandle::withdraw`'s log).
        let _ = phase::run::<Cosmetic, _, _>("dns-steer-withdraw", move || steering.withdraw()).await;
        return Err(DnsError::Cancelled);
    }

    // Flush. Best-effort — a failed cache flush leaves a stale entry for
    // one TTL window, not a leak.
    let b = Arc::clone(backend);
    let _ = phase::run::<Cosmetic, _, _>("flush", move || b.flush()).await;

    tracing::info!(
        elapsed_ms = started.elapsed().as_millis() as u64,
        "apply_dns_settings done"
    );

    Ok(SystemDnsApplied {
        backend: Arc::clone(backend),
        steering: Some(steering),
        bomb: drop_bomb::DebugDropBomb::new(BOMB_MSG),
        shutdown_completed: false,
    })
}

// SystemDnsApplied ====================================================================================================

/// RAII guard returned by [`SystemDns::apply`]. The preferred teardown
/// path is [`DnsApplied::shutdown`] (async) called by
/// `ProxyManager::stop`; the `DebugDropBomb` panics in debug builds if
/// shutdown wasn't awaited, catching missed-shutdown bugs at the first
/// test run. Release builds fall through to a best-effort sync fallback.
#[must_use = "SystemDnsApplied owns async cleanup; call .shutdown().await before drop"]
pub struct SystemDnsApplied {
    /// Win32 backend, used only for `flush` (nothing is restored).
    #[cfg(target_os = "windows")]
    backend: Arc<dyn windows::WinDnsBackend>,
    /// The engaged confinement. `None` only if `shutdown` already took it,
    /// or on macOS (where there is none to hold). Dropping it is the whole
    /// disengage — see `tun_engine::dns_confine`'s module doc.
    #[cfg(target_os = "windows")]
    confinement: Option<Box<dyn std::any::Any + Send>>,
    /// `networksetup` backend used for `flush` on macOS.
    #[cfg(target_os = "macos")]
    backend: Arc<dyn macos::MacDnsBackend>,
    /// The engaged DNS-steering key guard. `None` only if `shutdown`
    /// already took it. Dropping it without withdrawing is the
    /// crash/unwind fallback — see `tun_engine::dns_steer::Steering`'s doc.
    #[cfg(target_os = "macos")]
    steering: Option<Box<dyn macos::SteeringHandle>>,
    /// Runtime safeguard: panics in debug builds on drop if `shutdown`
    /// wasn't awaited. No-op in release.
    ///
    /// **DO NOT** gate the sync-fallback `Drop` path on `bomb.is_defused()`:
    /// `drop_bomb::DebugDropBomb::is_defused()` returns `true`
    /// unconditionally in release builds (`FakeBomb`), which would make
    /// the fallback dead code in release. The `shutdown_completed` flag
    /// below is the load-bearing release-mode signal.
    bomb: drop_bomb::DebugDropBomb,
    /// `true` after `DnsApplied::shutdown` has completed, in every build
    /// profile. `Drop` checks this (not `bomb.is_defused()`) to decide
    /// whether to run the sync-fallback flush.
    shutdown_completed: bool,
}

impl SystemDnsApplied {
    /// Whether the confinement is currently held. Test-only — production
    /// code has no reason to inspect this; the OS-level proof that
    /// dropping it actually reopens DNS lives in
    /// `dns_confine_global_net_state_filters_die_with_the_session`.
    #[cfg(all(test, target_os = "windows"))]
    pub(crate) fn confinement_engaged(&self) -> bool {
        self.confinement.is_some()
    }

    /// Whether the DNS-steering key is currently held. Test-only, mirrors
    /// [`Self::confinement_engaged`] — the OS-level proof that dropping it
    /// actually removes the key lives in `tun_engine::dns_steer`'s
    /// privileged lane.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn steering_engaged(&self) -> bool {
        self.steering.is_some()
    }
}

impl DnsApplied for SystemDnsApplied {
    async fn shutdown(&mut self) {
        self.bomb.defuse();
        self.shutdown_completed = true;

        #[cfg(target_os = "windows")]
        {
            // Dropping the confinement is the whole disengage (see
            // `tun_engine::dns_confine`). No adapter restore: only `hole-tun`
            // was touched, and the teardown that follows removes it.
            self.confinement.take();
        }

        #[cfg(target_os = "macos")]
        if let Some(steering) = self.steering.take() {
            // `Cosmetic`: a failed withdraw must not fail a stop;
            // `RealSteeringHandle::withdraw` logs it with the key.
            let _ = phase::run::<Cosmetic, _, _>("dns-steer-withdraw", move || steering.withdraw()).await;
        }

        #[cfg(any(target_os = "windows", target_os = "macos"))]
        let backend = Arc::clone(&self.backend);
        let _ = tokio::task::spawn_blocking(move || {
            #[cfg(any(target_os = "windows", target_os = "macos"))]
            {
                let _ = backend.flush();
            }
        })
        .await;
    }
}

impl Drop for SystemDnsApplied {
    /// Sync fallback for crash / panic unwind. `DebugDropBomb`'s own
    /// Drop panics in debug builds if not defused (catching
    /// missed-shutdown bugs); release builds suppress the panic and we
    /// run the best-effort sync fallback below.
    ///
    /// The release signal is `shutdown_completed`, not `bomb.is_defused()`
    /// — see the `shutdown_completed` field doc.
    fn drop(&mut self) {
        if self.shutdown_completed {
            return;
        }
        tracing::warn!("SystemDnsApplied dropped without shutdown() — sync fallback");
        // The `confinement`/`steering` field's own Drop releases it
        // unconditionally — no explicit action needed here. Best-effort
        // flush only.
        #[cfg(any(target_os = "windows", target_os = "macos"))]
        {
            let _ = self.backend.flush();
        }
    }
}

#[cfg(target_os = "windows")]
pub mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

// Re-export DnsPrior helpers so callers don't need a separate import just
// for the "construct from raw lines" side.
pub use crate::dns_state::DnsPrior as Prior;
pub use crate::dns_state::DnsPriorAdapter as PriorAdapter;

// Upgrade-sweep evidence gate =========================================================================================
//
// Used ONLY by `crate::dns::recovery`'s upgrade sweep, which undoes an
// older build's own upstream-adapter DNS rewrite after a crash — the one
// place a write to another adapter is still correct. See that module's
// doc for why the gate is per family, not per adapter, and why it never
// clears a file it found no evidence for.

/// What [`restore_family_if_ours`] did for one adapter + family.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyOutcome {
    /// The live setting matched the recorded evidence, and was written
    /// back to `prior` (it differed from `prior`).
    Restored,
    /// The live setting matched the recorded evidence AND already equalled
    /// `prior` — nothing needed writing.
    AlreadyCorrect,
    /// The live setting did NOT match the recorded evidence — someone
    /// else owns this family now. Nothing was read as ownership, nothing
    /// was written.
    SkippedNotOurs,
    /// `advertised`'s subset for this family was empty (a file of unknown
    /// provenance, or a family Hole never advertised) — no sound evidence
    /// either way. Nothing was written.
    NoEvidence,
    /// A read or write failed at the platform level.
    Failed,
}

/// Evaluate and, if warranted, restore ONE family of ONE recorded adapter.
/// `advertised_family_subset` must already be filtered to the family this
/// call is judging (the caller splits `DnsState.advertised` by family
/// before calling — the union is not comparable to a live per-family read).
///
/// Check-then-act: the live setting is read and compared, then the prior is
/// written, with nothing atomic between. A change landing in that window is
/// overwritten. An error from the read or the write is discarded and the
/// outcome is `Failed`; nothing logs it (bindreams/hole#1321).
#[cfg(target_os = "windows")]
pub(crate) fn restore_family_if_ours(
    backend: &dyn windows::WinDnsBackend,
    alias: &str,
    ipv6: bool,
    prior: &DnsPrior,
    advertised_family_subset: &[IpAddr],
) -> FamilyOutcome {
    if advertised_family_subset.is_empty() {
        return FamilyOutcome::NoEvidence;
    }
    let live = match backend.get_settings(alias) {
        Ok(Some(adapter)) => {
            if ipv6 {
                adapter.v6
            } else {
                adapter.v4
            }
        }
        Ok(None) => return FamilyOutcome::SkippedNotOurs,
        Err(_) => return FamilyOutcome::Failed,
    };
    if !dns_prior_matches_family_subset(&live, advertised_family_subset) {
        return FamilyOutcome::SkippedNotOurs;
    }
    if &live == prior {
        return FamilyOutcome::AlreadyCorrect;
    }
    match backend.restore_family(alias, ipv6, prior) {
        Ok(()) => FamilyOutcome::Restored,
        Err(_) => FamilyOutcome::Failed,
    }
}

/// The macOS counterpart of the Windows `restore_family_if_ours`, with the same
/// check-then-act window and discarded error.
#[cfg(target_os = "macos")]
pub(crate) fn restore_family_if_ours(
    backend: &dyn macos::MacDnsBackend,
    service: &str,
    ipv6: bool,
    prior: &DnsPrior,
    advertised_family_subset: &[IpAddr],
) -> FamilyOutcome {
    if advertised_family_subset.is_empty() {
        return FamilyOutcome::NoEvidence;
    }
    let live = match backend.get_settings(service) {
        Ok(Some(adapter)) => {
            if ipv6 {
                adapter.v6
            } else {
                adapter.v4
            }
        }
        Ok(None) => return FamilyOutcome::SkippedNotOurs,
        Err(_) => return FamilyOutcome::Failed,
    };
    if !dns_prior_matches_family_subset(&live, advertised_family_subset) {
        return FamilyOutcome::SkippedNotOurs;
    }
    if &live == prior {
        return FamilyOutcome::AlreadyCorrect;
    }
    match backend.restore_family(service, ipv6, prior) {
        Ok(()) => FamilyOutcome::Restored,
        Err(_) => FamilyOutcome::Failed,
    }
}

/// The live family setting is "still Hole's" iff it is a static list whose
/// members equal `advertised_family_subset` (order-independent). DHCP/None
/// never matches — a family Hole is still holding always reads back as a
/// static list of the exact IPs it advertised.
fn dns_prior_matches_family_subset(live: &DnsPrior, advertised_family_subset: &[IpAddr]) -> bool {
    let DnsPrior::Static { servers } = live else {
        return false;
    };
    let mut a = servers.clone();
    let mut b = advertised_family_subset.to_vec();
    a.sort();
    b.sort();
    a == b
}

#[cfg(test)]
#[path = "system_tests.rs"]
mod system_tests;
