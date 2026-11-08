//! Whether a start runs under the transient block-until-connected cover, and what it does about that cover.
//!
//! The decision is one exhaustive match in [`Coverage::plan`]; no call site matches a [`Coverage`] variant
//! (`coverage_policy_lives_on_the_type_not_at_call_sites`).

/// Whether a start runs under the transient block-until-connected cover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coverage {
    Uncovered,
    /// `unblock_snapshot` is the Unblock count the caller read when the start began, before it waited for this
    /// manager (the IPC handler reads it before locking `state.proxy`). An Unblock committed since is concurrent
    /// with the start, and the transient cover section compares against this one value (see
    /// `engage_transient_cover`); the start takes no snapshot of its own.
    Covered {
        unblock_snapshot: u64,
    },
}

/// What a start does about the transient cover. See [`Coverage::plan`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CoverPlan {
    /// Engage the transient cover, or keep the held one, comparing the Unblock count to `unblock_snapshot`.
    Engage { unblock_snapshot: u64 },
    /// A standing lockdown cover holds the host or takes over at connect, so the held transient cover is released:
    /// engaging both would, on macOS, clobber the singular pf ruleset. The host is uncovered from the release until
    /// the standing cover engages after the plugin chain and `routing.install` (open: bindreams/hole#1206).
    HandToLockdown,
    /// A manual connect or reload: release the held transient cover; the host is fail-open by design.
    FailOpen,
}

impl Coverage {
    /// The start's plan for the transient cover, given whether a standing lockdown cover is expected (see
    /// `ProxyManager::standing_cover_expected`).
    pub fn plan(self, standing_cover_expected: bool) -> CoverPlan {
        match self {
            Coverage::Covered { unblock_snapshot } if !standing_cover_expected => {
                CoverPlan::Engage { unblock_snapshot }
            }
            Coverage::Covered { .. } => CoverPlan::HandToLockdown,
            Coverage::Uncovered => CoverPlan::FailOpen,
        }
    }
}

#[cfg(test)]
#[path = "coverage_tests.rs"]
mod coverage_tests;
