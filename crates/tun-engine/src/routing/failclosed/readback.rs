//! What a SET of reads says about whether the object they were looking for is
//! there — the one rule that decides when "I did not see it" may be reported
//! as "it is not there".
//!
//! Platform-free and `#[cfg]`-free on purpose. Its only production caller is
//! Windows' `verify_boottime_twins`, which reads a boot-time filter back out
//! of two FWPM enumeration views; putting the rule here rather than in that
//! FFI loop is what lets every lane falsify it, for the reason
//! `clearance_tests` gives about the fold it guards.

/// A set of reads' verdict about one sought object.
///
/// Three causes, and only one of them is evidence of absence. Deriving that one
/// from the negation of the others — "some view was readable and did not hold
/// it, therefore it is gone" — is the merge this type exists to refuse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readback<T> {
    /// A view that WAS read holds it. Carries the object, so a caller's own
    /// health checks run against what was actually found rather than against
    /// the fact that something was.
    Found(T),
    /// EVERY view was read and none holds it. The only verdict that is
    /// evidence of absence.
    Absent,
    /// No readable view holds it and at least one view could not be read (or
    /// there was no view at all). Absence of evidence.
    Unreadable,
}

/// Classify a set of reads. Pure and total over the slice.
///
/// **A positive find outranks an unreadable view.** The search runs first, so
/// an object held by the view that WAS read is reported found whatever the
/// other answered — an error there costs nothing, because finding it is what
/// the read is for.
///
/// **Absence is concluded only from a COMPLETE set of readable views.** This
/// is bindreams/hole#1010's F2. Judging it off "every view errored" — i.e.
/// reporting absent as soon as one view is readable and empty — rests the
/// conclusion on the union of the READABLE views, which is only sound if every
/// view would hold the object. Hole's caller reads two FWPM enumeration types
/// precisely because that premise does not hold: WFP's reference does not pin
/// down what `enumType` means for a condition-less template, so only one of
/// them may return the filter. If that is the one that errored, the other's
/// empty answer is evidence of nothing — and the caller is fail-fatal, so
/// treating it as evidence refuses a kill-switch-armed user's connect.
///
/// **An empty set is [`Readback::Unreadable`], never `Absent`**, the same trap
/// `sibling_evidence` refuses one module up: "no readable view holds it" is
/// vacuously true of nothing read, and the vacuous reading is the one with a
/// consequence.
pub(crate) fn verdict<T: Copy, E>(views: &[Result<Vec<T>, E>], wanted: impl Fn(&T) -> bool) -> Readback<T> {
    if let Some(found) = views
        .iter()
        .filter_map(|v| v.as_ref().ok())
        .flatten()
        .find(|t| wanted(t))
    {
        return Readback::Found(*found);
    }
    if views.is_empty() || views.iter().any(Result::is_err) {
        return Readback::Unreadable;
    }
    Readback::Absent
}

#[cfg(test)]
#[path = "readback_tests.rs"]
mod readback_tests;
