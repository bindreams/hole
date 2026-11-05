//! The release epoch orders an engage against a release without either waiting
//! for the other. Every test drives one interleaving by calling the other side
//! from inside a step, so nothing here depends on timing.

use super::*;

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn is_superseded<T>(r: &Result<T, RoutingError>) -> bool {
    matches!(r, Err(RoutingError::SupersededByRelease))
}

/// A release that has reached the firewall: begun, then marked just before its first delete.
fn deleting(d: &Path) -> ReleaseInFlight {
    let release = begin_release(d);
    release.about_to_delete();
    release
}

#[skuld::test]
fn a_watch_with_no_release_since_checks_ok() {
    let d = dir();
    let watch = watch_releases(d.path()).expect("no release is in flight");
    assert!(watch.check().is_ok());
}

#[skuld::test]
fn a_release_that_deleted_and_ended_after_the_watch_fails_its_check() {
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    drop(deleting(d.path()));
    assert!(
        is_superseded(&watch.check()),
        "the release is over, but it deleted inside the window"
    );
}

#[skuld::test]
fn a_release_that_ended_before_touching_the_firewall_does_not_fail_the_check() {
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    drop(begin_release(d.path()));
    assert!(
        watch.check().is_ok(),
        "a release that failed before its first delete changed nothing the install could have raced"
    );
}

#[skuld::test]
fn a_release_still_in_flight_fails_the_check_marked_or_not() {
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    let release = begin_release(d.path());
    assert!(is_superseded(&watch.check()), "begun, not yet marked");
    release.about_to_delete();
    assert!(is_superseded(&watch.check()), "marked");
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
    drop(deleting(d.path()));
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
    let _release_b = deleting(b.path());
    assert!(watch_a.check().is_ok(), "a release in B does not touch a watch on A");
    assert!(watch_releases(a.path()).is_ok());
    assert!(is_superseded(&watch_releases(b.path())));
}

/// The `decide` of a record update runs under that record's lock; a watch check there takes no second lock.
#[skuld::test]
fn check_runs_inside_a_record_update() {
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();

    let (checked, _) = super::super::lockdown_state::file(d.path())
        .update(&util::versioned_file::DefaultPlacement::default(), |_| {
            (util::versioned_file::Change::Keep, watch.check().is_ok())
        })
        .unwrap();

    assert!(checked);
}

// The sweeps ==========================================================================================================

use super::super::{sweep_with_witness, Clearance, SweepOutcome};

#[skuld::test]
fn every_sweep_runs_as_a_release_in_flight() {
    // `release_all` and `disengage_lockdown` both go through `sweep_with_witness`,
    // so a sweep is announced before its closure makes its first firewall call.
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    let mut announced = false;
    let _clearance = sweep_with_witness(d.path(), None, |_, release| {
        announced = is_superseded(&watch_releases(d.path()));
        release.about_to_delete();
        SweepOutcome::completed(Clearance::proven())
    })
    .unwrap();
    assert!(announced);
    assert!(is_superseded(&watch.check()));
    assert!(watch_releases(d.path()).is_ok(), "and it ends with the sweep");
}

#[skuld::test]
fn a_sweep_that_failed_before_the_firewall_supersedes_nothing() {
    let d = dir();
    let watch = watch_releases(d.path()).unwrap();
    let result = sweep_with_witness(d.path(), None, |_, _| {
        SweepOutcome::failed(
            Clearance::proven(),
            RoutingError::RouteSetup("the engine would not open".into()),
        )
    });
    assert!(result.is_err());
    assert!(watch.check().is_ok());
}

#[skuld::test]
fn a_failing_sweep_ends_its_release_too() {
    let d = dir();
    let result = sweep_with_witness(d.path(), None, |_, _| {
        SweepOutcome::failed(Clearance::proven(), RoutingError::RouteSetup("the sweep failed".into()))
    });
    assert!(result.is_err());
    assert!(watch_releases(d.path()).is_ok());
}
