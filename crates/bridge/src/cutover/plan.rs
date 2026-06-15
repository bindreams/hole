//! Pure cutover planners. cfg-free, generic-free, table-tested. The cutover
//! NEVER co-engages a transient cover — that is structural here (the enum has
//! no transient-cover variant) and is the load-bearing recovery invariant.

/// What the cutover must do to be leak-correct, decided purely from the
/// lockdown intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CutoverPlan {
    /// Lockdown ON: the persistent WFP/pf cover already holds the gap. The
    /// cutover engages NOTHING; the bridge's shutdown disarms the guard so the
    /// filters survive, and the new bridge re-adopts them.
    StandingCoverHolds,
    /// Lockdown OFF: plain restart. A brief leak is accepted — gated by
    /// informed consent upstream. No transient cover is engaged (which would
    /// risk the Mullvad-#8470 brick).
    PlainRestart,
}

/// Decide the cutover plan from the lockdown intent.
pub fn plan_cutover(lockdown_on: bool) -> CutoverPlan {
    if lockdown_on {
        CutoverPlan::StandingCoverHolds
    } else {
        CutoverPlan::PlainRestart
    }
}

/// Whether a cover MUST be in force across the restart for the cutover to be
/// leak-correct. Consulted as a debug-assert by the actor (the standing cover
/// is already engaged from `start_inner` under lockdown-on; the actor asserts
/// presence, never engages).
pub fn cover_needed(lockdown_on: bool, running: bool) -> bool {
    lockdown_on && running
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod plan_tests;
