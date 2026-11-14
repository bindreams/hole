//! What a set of reads says about whether the object they were looking for is there: the one rule that decides when
//! "I did not see it" may be reported as "it is not there".
//!
//! Platform-free and `#[cfg]`-free. Its only production caller is Windows' `verify_boottime_twins`, which reads a
//! boot-time filter back out of two FWPM enumeration views; living here lets every lane test the rule.

/// A set of reads' verdict about one sought object.
///
/// Three causes, and only one is evidence of absence. It is never derived from the negation of the others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Readback<T> {
    /// A view that was read holds it. Carries the object, so a caller's own health checks run against what was found.
    Found(T),
    /// Every view was read and none holds it. The only verdict that is evidence of absence.
    Absent,
    /// No readable view holds it and at least one view could not be read, or there was no view at all.
    Unreadable,
}

/// Classify a set of reads. Pure and total over the slice.
///
/// A positive find outranks an unreadable view: an object held by a view that was read is found whatever another
/// answered.
///
/// Absence is concluded only from a complete set of readable views. The caller reads two FWPM enumeration types
/// because only one of them may return the filter, so the other's empty answer is evidence of nothing when the first
/// errored. The caller is fail-fatal, so treating it as absence would refuse a connect.
///
/// An empty set is [`Readback::Unreadable`], never `Absent`: "no readable view holds it" is vacuously true of nothing
/// read.
pub(crate) fn verdict<T: Copy, E>(views: &[Result<Vec<T>, E>], wanted: impl Fn(&T) -> bool) -> Readback<T> {
    let (records, unread) = merge(views);
    if let Some(found) = records.into_iter().find(|t| wanted(t)) {
        return Readback::Found(found);
    }
    if views.is_empty() || unread.is_some() {
        return Readback::Unreadable;
    }
    Readback::Absent
}

/// The records of every readable view, in view order, and the first read error among the rest.
///
/// The fold [`verdict`] is built on, for a caller that needs every matching record rather than one: an error in
/// one view never hides what another returned, and it is still reported. `None` means every view was read, so an
/// empty `views` is `None` too; whether that vacuous answer may be read as "complete" is the caller's to decide, as
/// [`verdict`] decides it.
pub(crate) fn merge<T: Copy, E>(views: &[Result<Vec<T>, E>]) -> (Vec<T>, Option<&E>) {
    let records = views
        .iter()
        .filter_map(|v| v.as_ref().ok())
        .flatten()
        .copied()
        .collect();
    (records, views.iter().find_map(|v| v.as_ref().err()))
}

#[cfg(test)]
#[path = "readback_tests.rs"]
mod readback_tests;
