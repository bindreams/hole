//! Pure reconciliation decisions, and the order the two surfaces move in.
//!
//! Split out from any call site so cover fate and tunnel fate stop being
//! expressible by imitation (`StopReason`'s two-variant trap, `check_health`
//! hand-copying `stop_with`'s arm). Nothing here
//! performs I/O: every function is a table lookup from measured/decided
//! inputs to a step, and the actual driving of those steps lives elsewhere.

use std::path::Path;
use std::sync::Arc;

use tokio::sync::Mutex;
use tokio_util::sync::CancellationToken;
use tun_engine::routing::failclosed::lockdown_state::Intent;
use tun_engine::routing::{CoverPresence, Routing};

use crate::dns::system::Dns;
use crate::proxy::Proxy;
use crate::proxy_manager::{ProxyManager, ProxyState};
use crate::target::{self, Target};
#[cfg(test)]
use hole_common::protocol::ProxyConfig;

// Steps ===============================================================================================================

/// What the standing lockdown cover should do this reconcile pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverStep {
    /// Install the cover; it is not confirmed live and both the target and
    /// the intent authorise it.
    Engage,
    /// No action: the cover's current state already matches what target and
    /// intent authorise (or nothing can be measured/acted on right now).
    Hold,
    /// Remove the cover. Either the target no longer authorises it (it
    /// moved to `Off`, regardless of intent — the engaged block follows the
    /// target, not the preference) or the intent was turned off mid-session
    /// (unticking releases immediately, it does not wait for stop).
    Release,
}

/// What the tunnel session should do this reconcile pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStep {
    /// Start a session: the target authorises one and none is live.
    Start,
    /// No action: a session is already live and should stay, or none is
    /// live and none is authorised.
    Hold,
    /// Tear the session down: the target no longer authorises it.
    Stop,
}

/// One decided action against one surface, tagged so [`step_order`] can
/// return a caller-agnostic sequence rather than a pair of typed slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    Cover(CoverStep),
    Tunnel(TunnelStep),
}

// cover_step ==========================================================================================================

/// Decide what the standing lockdown cover should do.
///
/// `intent` and `target` are independent inputs, not a redundant pair:
/// `intent` is the ticked preference, which survives disconnects
/// (`bridge-lockdown.json`); `target` is what the user asked to connect to
/// right now. A `Target::Connected` with `Intent::Off` yields `Hold`, not
/// `Engage` — the preference gates whether a connect is allowed to arm the
/// cover at all.
///
/// Once the target is anything other than `Connected`, `intent` stops
/// mattering: the engaged block follows the target (model point 6), so a
/// target that moved to `Off` releases a live cover even with the
/// preference still `On`. Reading
/// the preference back out of a disarmed cover is exactly the boot-time job
/// [`tun_engine::routing::decide_cover_recovery`] does instead; this
/// function is the steady-state reconcile decision, not the recovery one,
/// and does not re-derive intent from presence.
///
/// `Target::Unreadable` authorises neither surface — there is nothing to
/// preserve and nothing to disarm — so it holds regardless of intent or
/// presence.
///
/// Exhaustive on every axis with no wildcard arm, so a new `Intent`,
/// `CoverPresence`, or `Target` variant is a compile error here, the same
/// idiom `decide_cover_recovery` uses.
pub fn cover_step(intent: Intent, presence: CoverPresence, target: &Target) -> CoverStep {
    use CoverPresence as P;
    use Intent as I;

    match target {
        Target::Unreadable => CoverStep::Hold,

        // The target no longer authorises the cover, regardless of what the
        // preference says — this is the surface no longer being derived
        // from the tunnel, applied to the opposite direction too.
        Target::Off => match presence {
            P::Live => CoverStep::Release,
            P::Recorded => CoverStep::Release,
            P::Indeterminate => CoverStep::Release,
            P::Absent => CoverStep::Hold,
            P::Unreachable => CoverStep::Hold,
        },

        Target::Connected { .. } => match (intent, presence) {
            // `On` authorises the cover outright.
            (I::On, P::Live) => CoverStep::Hold,
            (I::On, P::Recorded) => CoverStep::Engage,
            (I::On, P::Indeterminate) => CoverStep::Engage,
            (I::On, P::Absent) => CoverStep::Engage,
            (I::On, P::Unreachable) => CoverStep::Hold,

            // `Unreadable` reads as armed (`Intent::reads_armed`), the same
            // conservative lean the sibling file uses: an unreadable
            // preference is not consent to disarm.
            (I::Unreadable, P::Live) => CoverStep::Hold,
            (I::Unreadable, P::Recorded) => CoverStep::Engage,
            (I::Unreadable, P::Indeterminate) => CoverStep::Engage,
            (I::Unreadable, P::Absent) => CoverStep::Engage,
            (I::Unreadable, P::Unreachable) => CoverStep::Hold,

            // `Off` never authorises engaging, and releases whatever is
            // actionable.
            (I::Off, P::Live) => CoverStep::Release,
            (I::Off, P::Recorded) => CoverStep::Release,
            (I::Off, P::Indeterminate) => CoverStep::Release,
            (I::Off, P::Absent) => CoverStep::Hold,
            (I::Off, P::Unreachable) => CoverStep::Hold,

            // `Unset` (no recorded preference at all) is not evidence to
            // arm; it is treated like `Off` here. Inferring `On` from a
            // live probe against an unset preference is `decide_cover_recovery`'s
            // boot-time job (`record_intent_on`), not this function's.
            (I::Unset, P::Live) => CoverStep::Release,
            (I::Unset, P::Recorded) => CoverStep::Release,
            (I::Unset, P::Indeterminate) => CoverStep::Release,
            (I::Unset, P::Absent) => CoverStep::Hold,
            (I::Unset, P::Unreachable) => CoverStep::Hold,
        },
    }
}

// tunnel_step =========================================================================================================

/// Decide what the tunnel session should do.
///
/// `Target::Unreadable` authorises neither starting nor stopping: an
/// unreadable target is not consent to connect, but it is equally not the
/// user asking to disconnect, so an already-live session is left alone
/// rather than torn down on a corrupt read.
pub fn tunnel_step(session_live: bool, target: &Target) -> TunnelStep {
    match target {
        Target::Unreadable => TunnelStep::Hold,
        Target::Connected { .. } => {
            if session_live {
                TunnelStep::Hold
            } else {
                TunnelStep::Start
            }
        }
        Target::Off => {
            if session_live {
                TunnelStep::Stop
            } else {
                TunnelStep::Hold
            }
        }
    }
}

// step_order ==========================================================================================================

/// The order the two surfaces move in this reconcile pass.
///
/// Engaging goes lockdown-then-tunnel; releasing goes tunnel-then-lockdown.
/// This is the fix for the ordering inversion `check_health` had — releasing
/// the cover before tearing the session down, leaving egress open while the
/// tunnel was still half-standing. `step_order` makes the order a value
/// derived from the decision, not a second statement sequence an author can
/// get wrong at a new call site.
pub fn step_order(cover: CoverStep, tunnel: TunnelStep) -> [Phase; 2] {
    match cover {
        CoverStep::Release => [Phase::Tunnel(tunnel), Phase::Cover(cover)],
        CoverStep::Engage | CoverStep::Hold => [Phase::Cover(cover), Phase::Tunnel(tunnel)],
    }
}

// reconcile_once ======================================================================================================

/// Reconcile the persisted target once, at startup, before any GUI or client
/// has connected (closes #617).
///
/// Must run strictly after `route_recovery::recover_and_record` completes —
/// that call is what measures `CoverPresence` and folds a live-cover finding
/// into the manager's `adopted_standing_cover` claim, which
/// `ProxyManager::effective_lockdown_intent` (not a raw `load_intent`) needs
/// to avoid releasing a cover crash recovery just adopted but that
/// `bridge-lockdown.json` itself doesn't yet record.
///
/// At the moment this runs, no session has ever started on this
/// `ProxyManager`, so `tunnel_step` can only decide `Start` or `Hold`, never
/// `Stop`. A bare `CoverStep::Engage` with no accompanying
/// `TunnelStep::Start` cannot arise either: `Engage` only arises for
/// `Target::Connected`, whose `tunnel_step` is unconditionally `Start` here.
/// So `Phase::Cover(Engage)` is a no-op in this driver — the standing cover's
/// actual engage happens inside `start_cancellable`'s own
/// `standing_cover_expected()` gate, once the TUN device and routes it needs
/// exist. The `covered = true` argument to `start_cancellable` is what holds
/// a loopback+server transient cover across that connect window when the
/// lockdown intent is off.
/// Fold the GUI-pushed startup preference into the persisted target, and
/// write the result back before anything else reads it.
///
/// The persisted target records *what* the user last connected to; the
/// preference records *whether* a boot may act on it. Both are needed, and
/// applying the preference here — rather than at each reader — is what keeps
/// reconciliation single-input: [`cover_step`] and [`tunnel_step`] below see
/// one already-decided [`Target`], not a target plus a modifier they would
/// each have to combine identically.
///
/// The resolution is persisted rather than kept in memory so the file agrees
/// with what was actually done: a `DoNotConnect` boot leaves `Off` on disk,
/// and an `AlwaysConnect` boot that substituted the pushed candidate leaves
/// that config. A later transition then reads one value instead of
/// re-deriving a different answer from a stale file.
///
/// A failed *write* is not a reason to ignore the preference — the resolved
/// value is still returned and honoured for this pass, and only the
/// persistence is lost.
async fn resolve_and_persist_startup_target(state_dir: &Path, owner: Option<(u32, u32)>) -> Target {
    let dir = state_dir.to_path_buf();
    // `load_startup_preference` and `apply` are both sync, and `apply` takes
    // the `TargetExclusive` file lock — the same reason `ipc::persist_after_start`
    // runs its pair of them off the runtime.
    tokio::task::spawn_blocking(move || {
        let pref = target::load_startup_preference(&dir);
        let behavior = pref.on_startup;
        let candidate = pref.candidate.clone();
        match target::apply(&dir, owner, move |persisted| {
            target::resolve_startup_target(persisted, behavior, candidate)
        }) {
            Ok(resolved) => resolved,
            Err(error) => {
                tracing::warn!(
                    %error,
                    "reconcile_once: could not persist the resolved startup target; honouring it for this boot only"
                );
                target::resolve_startup_target(target::load(&dir), pref.on_startup, pref.candidate)
            }
        }
    })
    .await
    .unwrap_or_else(|error| {
        // A panicked blocking task leaves the preference unknown. `Unreadable`
        // is the lean that authorises neither starting nor stopping, matching
        // `tunnel_step`'s treatment of an unreadable target file.
        tracing::warn!(%error, "reconcile_once: startup-target resolution failed; treating the target as unreadable");
        Target::Unreadable
    })
}

pub async fn reconcile_once<P, R, D>(
    state_dir: &Path,
    proxy: &Arc<Mutex<ProxyManager<P, R, D>>>,
    cancel: &CancellationToken,
) where
    P: Proxy,
    R: Routing,
    D: Dns,
{
    let mut pm = proxy.lock().await;
    let target = resolve_and_persist_startup_target(state_dir, pm.state_owner()).await;

    let intent = pm.effective_lockdown_intent();
    let presence = pm.cover_presence();
    let session_live = pm.state() == ProxyState::Running;

    let cover = cover_step(intent, presence, &target);
    let tunnel = tunnel_step(session_live, &target);

    for phase in step_order(cover, tunnel) {
        match phase {
            Phase::Cover(CoverStep::Release) => match pm.routing_handle().release_all_covers() {
                Ok(()) => pm.set_standing_cover_adopted(false),
                Err(error) => {
                    tracing::warn!(%error, "reconcile_once: failed to release a stray standing cover");
                }
            },
            // Engaging happens inside `start_cancellable` below, not here —
            // see the fn doc.
            Phase::Cover(CoverStep::Engage) | Phase::Cover(CoverStep::Hold) => {}
            Phase::Tunnel(TunnelStep::Start) => {
                let Target::Connected { config } = &target else {
                    debug_assert!(false, "tunnel_step only yields Start for Target::Connected");
                    continue;
                };
                // A child of the caller's process-level shutdown token, so a
                // stop arriving mid-boot-connect is observed cooperatively
                // rather than waited out. This used to be a fresh, unreachable
                // `CancellationToken::new()` — which meant a SIGTERM/SCM-Stop
                // during a boot reconnect to an unreachable server was not
                // seen until the DNS/TCP/plugin-readiness bounds all elapsed,
                // and on Windows that is after the service already reported
                // `Running` to SCM.
                if let Err(error) = pm.start_cancellable(config, true, cancel.child_token()).await {
                    tracing::warn!(%error, "reconcile_once: failed to start the persisted target");
                }
            }
            Phase::Tunnel(TunnelStep::Hold) => {}
            Phase::Tunnel(TunnelStep::Stop) => {
                debug_assert!(
                    false,
                    "tunnel_step cannot yield Stop at boot: no session has ever started yet"
                );
            }
        }
    }
}

#[cfg(test)]
#[path = "reconciler_tests.rs"]
mod reconciler_tests;
