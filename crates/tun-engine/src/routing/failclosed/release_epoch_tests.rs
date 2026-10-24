//! The release epoch orders an engage against a release without either waiting
//! for the other. Every test drives one interleaving by calling the other side
//! from inside a step, so nothing here depends on timing.

use std::cell::Cell;

use super::*;

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

/// A cover whose drop is observable.
struct Cover<'a>(&'a Cell<u32>);

impl Drop for Cover<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get() + 1);
    }
}

fn is_superseded<T>(r: &Result<T, RoutingError>) -> bool {
    matches!(r, Err(RoutingError::SupersededByRelease))
}

#[skuld::test]
fn a_watch_with_no_release_since_checks_ok() {
    let d = dir();
    let watch = watch_releases(d.path()).expect("no release is in flight");
    assert!(watch.check().is_ok());
}

#[skuld::test]
fn a_release_that_began_and_ended_after_the_watch_fails_its_check() {
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    drop(begin_release(d.path()));
    assert!(
        is_superseded(&watch.check()),
        "the release is over, but it ran inside the window"
    );
}

#[skuld::test]
fn a_release_still_in_flight_fails_the_check() {
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    let _release = begin_release(d.path());
    assert!(is_superseded(&watch.check()));
}

#[skuld::test]
fn a_watch_cannot_open_while_a_release_is_in_flight() {
    let d = dir();
    let release = begin_release(d.path());
    assert!(is_superseded(&watch_releases(d.path())));
    drop(release);
    assert!(watch_releases(d.path()).is_ok(), "and opens again once it ends");
}

#[skuld::test]
fn a_watch_opened_after_a_release_ended_is_not_failed_by_it() {
    let d = dir();
    drop(begin_release(d.path()));
    let watch = watch_releases(d.path()).unwrap();
    assert!(watch.check().is_ok());
}

#[skuld::test]
fn overlapping_releases_keep_the_watch_closed_until_both_end() {
    let d = dir();
    let first = begin_release(d.path());
    let second = begin_release(d.path());
    drop(first);
    assert!(
        is_superseded(&watch_releases(d.path())),
        "one release is still in flight"
    );
    drop(second);
    assert!(watch_releases(d.path()).is_ok());
}

#[skuld::test]
fn a_release_is_in_flight_until_its_guard_drops_even_on_an_unwind() {
    let d = dir();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _release = begin_release(d.path());
        panic!("a release body panics");
    }));
    assert!(unwound.is_err());
    assert!(
        watch_releases(d.path()).is_ok(),
        "a panicking release must not leave the state dir permanently in flight"
    );
}

#[skuld::test]
fn the_epoch_is_per_state_dir() {
    let (a, b) = (dir(), dir());
    let watch_a = watch_releases(a.path()).unwrap();
    let _release_b = begin_release(b.path());
    assert!(watch_a.check().is_ok(), "a release in B does not touch a watch on A");
    assert!(watch_releases(a.path()).is_ok());
    assert!(is_superseded(&watch_releases(b.path())));
}

// engage_within_watch =================================================================================================

#[skuld::test]
fn an_engage_with_no_release_keeps_its_cover() {
    let d = dir();
    let drops = Cell::new(0);
    let cover = engage_within_watch(d.path(), || Ok(Cover(&drops))).expect("no release ran");
    assert_eq!(drops.get(), 0);
    drop(cover);
}

#[skuld::test]
fn an_engage_does_not_start_while_a_release_is_in_flight() {
    let d = dir();
    let _release = begin_release(d.path());
    let engaged = Cell::new(false);
    let result = engage_within_watch(d.path(), || {
        engaged.set(true);
        Ok(())
    });
    assert!(is_superseded(&result));
    assert!(!engaged.get(), "nothing is installed over a release in flight");
}

#[skuld::test]
fn a_release_that_begins_during_the_engage_drops_the_cover_and_supersedes_it() {
    let d = dir();
    let drops = Cell::new(0);
    let result = engage_within_watch(d.path(), || {
        drop(begin_release(d.path()));
        Ok(Cover(&drops))
    });
    assert!(is_superseded(&result));
    assert_eq!(
        drops.get(),
        1,
        "the engage's own cover is its back-out, dropped exactly once"
    );
}

#[skuld::test]
fn an_engage_that_fails_reports_its_own_error_not_a_supersession() {
    let d = dir();
    let result: Result<(), _> = engage_within_watch(d.path(), || {
        drop(begin_release(d.path()));
        Err(RoutingError::RouteSetup("the engage failed".into()))
    });
    assert!(matches!(result, Err(RoutingError::RouteSetup(_))), "{result:?}");
}

// The facade ==========================================================================================================

use super::super::{sweep_with_witness, Clearance, SweepOutcome};

#[skuld::test]
fn every_sweep_runs_as_a_release_in_flight() {
    // `release_all` and `disengage_lockdown` both go through `sweep_with_witness`,
    // so a sweep is announced before its closure makes its first firewall call.
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    let mut announced = false;
    let _clearance = sweep_with_witness(d.path(), None, |_| {
        announced = is_superseded(&watch_releases(d.path()));
        SweepOutcome::completed(Clearance::proven())
    })
    .unwrap();
    assert!(announced);
    assert!(is_superseded(&watch.check()));
    assert!(watch_releases(d.path()).is_ok(), "and it ends with the sweep");
}

#[skuld::test]
fn a_failing_sweep_ends_its_release_too() {
    let d = dir();
    let result = sweep_with_witness(d.path(), None, |_| {
        SweepOutcome::failed(Clearance::proven(), RoutingError::RouteSetup("the sweep failed".into()))
    });
    assert!(result.is_err());
    assert!(watch_releases(d.path()).is_ok());
}

/// The text of `fn <name>(...)` in the facade, up to its closing brace.
fn facade_body(name: &str) -> &'static str {
    const FACADE: &str = include_str!("../failclosed.rs");
    let start = FACADE
        .find(&format!("pub fn {name}("))
        .unwrap_or_else(|| panic!("the facade has no `{name}`"));
    let rest = &FACADE[start..];
    &rest[..rest.find("\n}\n").expect("the function ends")]
}

#[skuld::test]
fn every_engage_entry_runs_inside_a_release_watch() {
    // The platform engages are privileged, so the wiring is pinned lexically:
    // an entry that called `platform::engage*` outside the watch would install
    // a cover a release could overtake.
    for name in ["engage", "engage_lockdown"] {
        let body = facade_body(name);
        assert!(body.contains("engage_within_watch("), "`{name}` must run in a watch");
    }
}
