//! Who owns a pf cover record, and so who may drop its token, as tables over
//! what the record reads. Platform-free: the rules are about two parties and a
//! file, and a rule proved only on the host that has `pfctl` is proved nowhere.

use super::super::failclosed_state::FailClosedState;
use super::super::StateFile;
use super::*;
use crate::error::RoutingError;

fn absent() -> StateFile<FailClosedState> {
    StateFile::Absent
}

fn live(token: &str) -> StateFile<FailClosedState> {
    StateFile::Present(record(token, false))
}

fn tombstone_of(token: &str) -> StateFile<FailClosedState> {
    StateFile::Present(record(token, true))
}

fn record(token: &str, releasing: bool) -> FailClosedState {
    FailClosedState {
        version: super::super::failclosed_state::SCHEMA_VERSION,
        pf_token: token.into(),
        pf_was_enabled: false,
        releasing,
    }
}

fn unusable(token: Option<&str>) -> StateFile<FailClosedState> {
    StateFile::Unusable {
        pf_token: token.map(str::to_owned),
    }
}

const MINE: &str = "424242";
const OTHER: &str = "7";

// Held ================================================================================================================

#[skuld::test]
fn a_live_record_naming_the_token_is_held() {
    assert_eq!(Held::of(&live(MINE), MINE), Held::Held);
}

#[skuld::test]
fn a_release_is_an_absent_record_a_tombstone_or_another_engages_record() {
    assert_eq!(Held::of(&absent(), MINE), Held::Released);
    assert_eq!(
        Held::of(&tombstone_of(MINE), MINE),
        Held::Released,
        "a release claimed it"
    );
    assert_eq!(Held::of(&live(OTHER), MINE), Held::Released, "another engage's record");
}

#[skuld::test]
fn a_record_that_cannot_be_read_is_not_a_release() {
    // A read or parse failure says nothing about whether a release ran, so it
    // must not be reported as one.
    assert_eq!(Held::of(&unusable(Some(MINE)), MINE), Held::Unreadable);
    assert_eq!(Held::of(&unusable(None), MINE), Held::Unreadable);
    assert_eq!(Held::of(&unusable(Some(OTHER)), MINE), Held::Unreadable);
}

#[skuld::test]
fn only_a_release_supersedes_and_an_unreadable_record_is_a_state_failure() {
    assert!(Held::Held.refusal("standing").is_none());
    assert!(matches!(
        Held::Released.refusal("standing"),
        Some(RoutingError::SupersededByRelease)
    ));
    let unreadable = Held::Unreadable.refusal("standing").expect("a refusal");
    assert!(
        matches!(&unreadable, RoutingError::RouteSetup(m) if m.contains("standing")),
        "{unreadable}"
    );
}

#[skuld::test]
fn a_superseding_refusal_cancels_the_start_and_an_unreadable_one_does_not() {
    assert!(Held::Released.refusal("x").unwrap().cancels_the_start());
    assert!(!Held::Unreadable.refusal("x").unwrap().cancels_the_start());
}

// Claim and un-claim ==================================================================================================

#[skuld::test]
fn a_release_claims_a_live_record_with_its_tombstone() {
    let claimed = tombstone(&live(MINE)).expect("a live record can be claimed");
    assert_eq!(claimed, record(MINE, true));
}

#[skuld::test]
fn nothing_else_is_claimed() {
    assert!(tombstone(&absent()).is_none(), "nothing to claim");
    assert!(tombstone(&tombstone_of(MINE)).is_none(), "already claimed");
    assert!(
        tombstone(&unusable(Some(MINE))).is_none(),
        "an unusable file carries no flag"
    );
}

#[skuld::test]
fn an_engage_takes_back_only_a_tombstone() {
    assert_eq!(unclaimed(&tombstone_of(MINE)), Some(record(MINE, false)));
    assert!(unclaimed(&live(MINE)).is_none());
    assert!(unclaimed(&absent()).is_none());
    assert!(unclaimed(&unusable(Some(MINE))).is_none());
}

// What a clear would find =============================================================================================

#[skuld::test]
fn a_claimed_clear_would_find_what_the_release_clear_finds() {
    for current in [
        absent(),
        live(MINE),
        tombstone_of(MINE),
        tombstone_of(OTHER),
        unusable(Some(MINE)),
        unusable(None),
    ] {
        assert_eq!(
            would_clear(&current, Some(MINE), true),
            release_clear(&current, Some(MINE)),
            "{current:?}"
        );
    }
}

#[skuld::test]
fn an_unclaimed_clear_would_remove_any_record_naming_the_token_and_nothing_else() {
    assert_eq!(would_clear(&live(MINE), Some(MINE), false), Cleared::Removed);
    assert_eq!(
        would_clear(&tombstone_of(MINE), Some(MINE), false),
        Cleared::Removed,
        "a tombstone nobody holds the right to settle is leftover"
    );
    assert_eq!(would_clear(&unusable(Some(MINE)), Some(MINE), false), Cleared::Removed);
    assert_eq!(would_clear(&unusable(None), None, false), Cleared::Removed);
    assert_eq!(would_clear(&live(OTHER), Some(MINE), false), Cleared::Gone);
    assert_eq!(would_clear(&absent(), Some(MINE), false), Cleared::Gone);
}

// A release's clear ===================================================================================================

#[skuld::test]
fn a_release_clears_its_own_tombstone() {
    let cleared = release_clear(&tombstone_of(MINE), Some(MINE));
    assert_eq!(cleared, Cleared::Removed);
    assert!(cleared.refusal().is_none());
}

#[skuld::test]
fn a_release_finds_its_record_already_gone_and_that_is_not_a_failure() {
    let cleared = release_clear(&absent(), Some(MINE));
    assert_eq!(cleared, Cleared::Gone);
    assert!(cleared.refusal().is_none());
}

#[skuld::test]
fn a_release_never_clears_a_record_an_engage_re_asserted() {
    // The engage's restore failed after the release's restore succeeded, so it put
    // its own live record back. The host may be blocked: not a clean release.
    let cleared = release_clear(&live(MINE), Some(MINE));
    assert_eq!(cleared, Cleared::Replaced);
    assert!(matches!(cleared.refusal(), Some(RoutingError::RouteSetup(_))));
}

#[skuld::test]
fn a_release_leaves_a_record_under_another_token_alone() {
    assert_eq!(release_clear(&live(OTHER), Some(MINE)), Cleared::Replaced);
    assert_eq!(release_clear(&tombstone_of(OTHER), Some(MINE)), Cleared::Replaced);
}

#[skuld::test]
fn a_release_of_an_unusable_record_clears_it_when_the_token_matches() {
    assert_eq!(release_clear(&unusable(Some(MINE)), Some(MINE)), Cleared::Removed);
    assert_eq!(release_clear(&unusable(None), None), Cleared::Removed);
    assert_eq!(release_clear(&unusable(Some(OTHER)), Some(MINE)), Cleared::Replaced);
}

// An engage's clear and re-assert =====================================================================================

#[skuld::test]
fn an_engage_clears_a_live_or_unreadable_record_naming_its_token_but_never_a_tombstone() {
    assert!(holds_clear(&live(MINE), MINE));
    assert!(
        holds_clear(&unusable(Some(MINE)), MINE),
        "its own record, gone unreadable"
    );
    assert!(!holds_clear(&tombstone_of(MINE), MINE), "the release owns it");
    assert!(!holds_clear(&live(OTHER), MINE));
    assert!(!holds_clear(&unusable(Some(OTHER)), MINE));
    assert!(!holds_clear(&unusable(None), MINE));
    assert!(!holds_clear(&absent(), MINE));
}

#[skuld::test]
fn a_failed_back_out_re_asserts_only_over_nothing_or_its_own_tombstone() {
    assert!(reasserts(&absent(), MINE), "the release already cleared");
    assert!(reasserts(&tombstone_of(MINE), MINE), "the release is yet to clear");
    assert!(!reasserts(&live(MINE), MINE), "already there");
    assert!(!reasserts(&live(OTHER), MINE), "another engage's");
    assert!(!reasserts(&tombstone_of(OTHER), MINE), "another release's");
    assert!(!reasserts(&unusable(Some(MINE)), MINE), "not ours to overwrite blind");
}

// Any record naming a token ===========================================================================================

#[skuld::test]
fn naming_matches_any_record_with_the_token_and_an_unusable_one_with_none() {
    assert!(names(&live(MINE), Some(MINE)));
    assert!(names(&tombstone_of(MINE), Some(MINE)));
    assert!(names(&unusable(Some(MINE)), Some(MINE)));
    assert!(names(&unusable(None), None));
    assert!(!names(&live(MINE), None));
    assert!(!names(&live(OTHER), Some(MINE)));
    assert!(!names(&absent(), Some(MINE)));
    assert!(!names(&absent(), None));
}
