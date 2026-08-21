// The single answer to "who, inside this process, holds a fail-closed cover".
//
// This is deliberately a different question from "is the host held closed
// right now" — that needs an OS probe this stage does not have. `Nobody`
// means no live guard in this process owns a cover; it does NOT mean the
// host is open. A cover stranded by an unclean exit, or adopted at startup,
// is `Nobody` here and can still block every packet. Do not let a future
// site treat "nobody holds it" as "nothing is blocking".

/// Derived once from [`super::Posture`] by [`super::Posture::cover_holder`]
/// — no other site may recompute it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum CoverHolder {
    Nobody,
    PendingStart,
    Session { standing: bool },
}

impl CoverHolder {
    /// True only for `Session { standing: true }` — the standing kill-switch
    /// cover engaged by this session. Never a statement about the host.
    pub(super) fn standing_engaged(self) -> bool {
        matches!(self, CoverHolder::Session { standing: true })
    }

    /// True only for `PendingStart` — the block-until-connected cover held
    /// while a covered start has failed and left the host fail-closed.
    pub(super) fn transient_engaged(self) -> bool {
        matches!(self, CoverHolder::PendingStart)
    }

    /// Whether a start-time reachability probe's egress could be classified
    /// as blocked by one of Hole's own covers, so the probe must be skipped
    /// rather than misreport Hole's own cover as censorship.
    ///
    /// Thunk, not bool: eager evaluation would read the intent file on every
    /// start, including covered ones, changing `warn!` output on a corrupt
    /// file.
    pub(super) fn suppresses_reachability_probe(self, lockdown_intent: impl FnOnce() -> bool) -> bool {
        self.standing_engaged() || self.transient_engaged() || lockdown_intent()
    }
}

#[cfg(test)]
#[path = "cover_tests.rs"]
mod cover_tests;
