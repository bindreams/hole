//! When "I did not see it" may be reported as "it is not there".
//!
//! `#[cfg]`-free: the rule is platform-free even though its only production
//! caller is Windows' boot-time twin read-back, and a rule proved only on the
//! platform that has the hazard is proved nowhere else.

use super::{verdict, Readback};

/// A stand-in for the FWPM `FilterRecord` the production caller searches for:
/// a key to match on, plus a payload, so `Found` carrying the object the
/// PREDICATE selected — rather than whichever one a view happened to list
/// first — is assertable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Record {
    key: u8,
    payload: u8,
}

const WANTED: u8 = 7;

fn held() -> Record {
    Record {
        key: WANTED,
        payload: 0xaa,
    }
}

fn other() -> Record {
    Record { key: 99, payload: 0xbb }
}

fn classify(views: &[Result<Vec<Record>, u32>]) -> Readback<Record> {
    verdict(views, |r| r.key == WANTED)
}

#[skuld::test]
fn an_unreadable_view_never_concludes_absence() {
    // bindreams/hole#1010 F2. The caller reads two views ONLY because just one
    // of them may hold the object; under that premise the readable one's empty
    // answer proves nothing about the one that errored. Its caller is
    // fail-fatal, so concluding absence here refuses a connect outright.
    assert_eq!(classify(&[Err(0x8032_0005), Ok(vec![])]), Readback::Unreadable);
    assert_eq!(classify(&[Ok(vec![]), Err(0x8032_0005)]), Readback::Unreadable);
    assert_eq!(
        classify(&[Err(0x8032_0005), Ok(vec![other()])]),
        Readback::Unreadable,
        "a readable view holding somebody ELSE's object is still not evidence about this one"
    );
}

#[skuld::test]
fn a_complete_set_of_readable_views_is_the_one_thing_that_proves_absence() {
    // The mirror, and the reason the rule is an asymmetry rather than a
    // blanket softening: a read that WAS taken and does not hold the object is
    // real evidence, and the caller must still act on it.
    assert_eq!(classify(&[Ok(vec![]), Ok(vec![])]), Readback::Absent);
    assert_eq!(classify(&[Ok(vec![other()]), Ok(vec![])]), Readback::Absent);
    assert_eq!(classify(&[Ok(vec![])]), Readback::Absent);
}

#[skuld::test]
fn a_find_in_a_readable_view_outranks_an_error_in_the_other() {
    // The search runs before the error check. Finding the object is what the
    // read is for, so an error on a view that did not need to answer costs
    // nothing.
    let record = held();
    assert_eq!(classify(&[Err(0x8032_0005), Ok(vec![record])]), Readback::Found(record));
    assert_eq!(classify(&[Ok(vec![record]), Err(0x8032_0005)]), Readback::Found(record));
    assert_eq!(
        classify(&[Ok(vec![other(), record]), Ok(vec![])]),
        Readback::Found(record),
        "the object is picked out of the view by the predicate, not by position"
    );
}

#[skuld::test]
fn nothing_read_at_all_is_unreadable_and_never_absent() {
    // "No readable view holds it" is vacuously true of nothing read, and the
    // vacuous reading is the one with a consequence — the same trap
    // `sibling_evidence` refuses for an empty sibling set.
    assert_eq!(classify(&[]), Readback::Unreadable);
    assert_eq!(
        classify(&[Err(0x8032_0005), Err(0x8032_0005)]),
        Readback::Unreadable,
        "every view unreadable is the case the shipped predicate got right"
    );
}
