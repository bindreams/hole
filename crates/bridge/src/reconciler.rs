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
use crate::target::{self, SessionEvent, Target};
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
/// mattering: the engaged block follows the target, so a
/// target that moved to `Off` releases a live cover even with the
/// preference still `On` — that is intentional, not an oversight. Reading
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
            // actionable: unticking releases mid-session.
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

// teardown_cover_disposition ==========================================================================================

/// What a torn-down session's standing cover should do. Two arms, not three:
/// `disarm` releases the process's own claim (closing the Windows FWPM engine
/// handle) while leaving the persistent filters in force, so "a successor
/// adopts it" and "leave it in place across a blip" are the same operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverDisposition {
    /// Release the filters now, via the confirmable `release_all_covers`.
    ReleaseNow,
    /// Leave the filters in force and give up this process's claim.
    KeepEngaged,
}

/// Decide a torn-down session's cover fate from the CAUSE of the teardown.
///
/// Exhaustive over [`SessionEvent`] with no wildcard, so a sixth variant
/// cannot inherit an answer by falling into someone else's group — the defect
/// this function exists to remove, and the one the transient-cover match
/// reproduced by grouping on shared consequence to the target.
///
/// `UserStopped` is an explicit user disarm: it releases regardless of intent,
/// presence or target, because an escape must resolve an unknown toward
/// releasing, never toward "nothing to do".
///
/// `GaveUp` is deliberately NOT grouped with it. Both move the target to
/// `Off`, but giving up is the SYSTEM concluding the target is unreachable,
/// not the user asking to open the host — so it defers to [`cover_step`],
/// preserving today's behaviour rather than silently changing a policy nobody
/// has been asked about.
pub fn teardown_cover_disposition(
    event: SessionEvent,
    intent: Intent,
    presence: CoverPresence,
    target: &Target,
) -> CoverDisposition {
    match event {
        // The one unconditional arm: an explicit user disarm releases whatever
        // the probe says, because an escape must resolve an unknown toward
        // releasing.
        SessionEvent::UserStopped => CoverDisposition::ReleaseNow,
        // Everything else defers to `cover_step`, INCLUDING the two pre-exit
        // events. What makes a cutover keep its cover is the intent being ON,
        // not the event: `cover_step` already owns that axis, and its
        // `Off`/`Unset` arms sweep a stranded cover rather than leaving the
        // host blocked with nothing owning the filters.
        SessionEvent::CutoverRestart | SessionEvent::ProcessExiting | SessionEvent::GaveUp | SessionEvent::Blipped => {
            match cover_step(intent, presence, target) {
                CoverStep::Release => CoverDisposition::ReleaseNow,
                CoverStep::Hold | CoverStep::Engage => CoverDisposition::KeepEngaged,
            }
        }
    }
}

/// Decide the TRANSIENT block-until-connected cover's fate from the cause of
/// the teardown.
///
/// Separate from [`teardown_cover_disposition`] because the two covers answer
/// different questions. The standing cover asks what the target authorises;
/// this one asks only **"will a successor process adopt these filters"** —
/// true for `CutoverRestart` alone, where a replacement bridge is already
/// starting. Nothing adopts them on a clean shutdown, so keeping them there
/// blocks the host from boot until the bridge next runs.
///
/// Exhaustive with no wildcard: the arm this replaced grouped
/// `CutoverRestart | Blipped | ProcessExiting` by their shared consequence to
/// the target, which is what let `ProcessExiting` inherit an answer chosen for
/// a cutover.
///
/// `Blipped` deliberately keeps today's behaviour pending an open question:
/// a blip's cover arguably *should* survive an in-process retry, but
/// `stop_with` has already replaced the posture with `Idle` by this point, so
/// nothing would own it. Changing it is a policy call, not a defect fix.
pub fn transient_cover_disposition(event: SessionEvent) -> CoverDisposition {
    match event {
        SessionEvent::CutoverRestart => CoverDisposition::KeepEngaged,
        SessionEvent::Blipped => CoverDisposition::KeepEngaged,
        SessionEvent::UserStopped | SessionEvent::GaveUp | SessionEvent::ProcessExiting => CoverDisposition::ReleaseNow,
    }
}

// step_order ==========================================================================================================

/// The order the two surfaces move in this reconcile pass.
///
/// Engaging goes lockdown-then-tunnel; releasing goes tunnel-then-lockdown.
/// This is the fix for the ordering inversion `check_health` had (releasing
/// the cover at `proxy_manager.rs:2047`, before tearing the session down at
/// `2058` — egress open while the tunnel was still half-standing):
/// `step_order` makes the order a value derived from the decision, not a
/// second statement sequence an author can get wrong at a new call site.
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
///
/// Before deciding anything, the persisted target is folded through
/// `target::resolve_startup_target` against the GUI-pushed startup
/// preference (R8: "one decider, not two" — the startup behaviour is
/// applied first, to produce the target, so reconciliation afterward has
/// exactly one input) and the resolved value is persisted via `target::apply`
/// before use, not merely held in memory: `DoNotConnect` must durably write
/// `Off` so a later status read (or a session-event write, should one ever
/// race this early) sees the same target this pass reconciles toward, not
/// the stale one it overrode.
pub async fn reconcile_once<P, R, D>(
    state_dir: &Path,
    owner: Option<(u32, u32)>,
    proxy: &Arc<Mutex<ProxyManager<P, R, D>>>,
    cancel: &CancellationToken,
) where
    P: Proxy,
    R: Routing,
    D: Dns,
{
    let pref = target::load_startup_preference(state_dir);
    let state_dir_owned = state_dir.to_path_buf();
    let target = match tokio::task::spawn_blocking(move || {
        target::apply(&state_dir_owned, owner, move |current| {
            target::resolve_startup_target(current, pref.on_startup, pref.candidate)
        })
    })
    .await
    {
        Ok(Ok(target)) => target,
        Ok(Err(error)) => {
            tracing::error!(
                %error,
                "reconcile_once: failed to persist the startup-resolved target; reading current disk state instead of guessing"
            );
            target::load(state_dir)
        }
        Err(error) => {
            tracing::error!(%error, "reconcile_once: startup-target resolution task panicked; treating target as unreadable");
            Target::Unreadable
        }
    };

    let mut pm = proxy.lock().await;
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
                // A child of the process-wide shutdown token, so a SIGTERM /
                // SCM Stop arriving mid-boot abandons the auto-connect instead
                // of racing it. A token minted here would be one
                // nothing else holds: uncancellable by construction.
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
pub(crate) mod reconciler_tests;
