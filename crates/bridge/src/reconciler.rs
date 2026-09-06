//! Pure reconciliation decisions, and the order the two surfaces move in.
//!
//! Split out from any call site so cover fate and tunnel fate stop being
//! expressible by imitation (`StopReason`'s two-variant trap, `check_health`
//! hand-copying `stop_with`'s arm) — see this plan's "Cause 1". Nothing here
//! performs I/O: every function is a table lookup from measured/decided
//! inputs to a step, and the actual driving of those steps lives elsewhere.

use crate::target::Target;
#[cfg(test)]
use hole_common::protocol::ProxyConfig;
use tun_engine::routing::failclosed::lockdown_state::Intent;
use tun_engine::routing::CoverPresence;

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
    /// (Q4: unticking releases immediately, it does not wait for stop).
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
/// preference still `On` — that is Q4/Q5's point, not an oversight. Reading
/// the preference back out of a disarmed cover is exactly the boot-time job
/// [`tun_engine::routing::decide_cover_recovery`] does instead; this
/// function is the steady-state reconcile decision, not the recovery one,
/// and does not re-derive intent from presence.
///
/// `Target::Unreadable` authorises neither surface — there is nothing to
/// preserve and nothing to disarm — so it holds regardless of intent or
/// presence (R4).
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
            // actionable — Q4's "unticking releases mid-session".
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
/// `Target::Unreadable` authorises neither starting nor stopping (R4): an
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

#[cfg(test)]
#[path = "reconciler_tests.rs"]
mod reconciler_tests;
