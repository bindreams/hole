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
    assert!(watch_releases(d.path()).check().is_ok());
}

#[skuld::test]
fn a_release_that_deleted_and_ended_after_the_watch_fails_its_check() {
    let d = dir();
    let watch = watch_releases(d.path());
    drop(deleting(d.path()));
    assert!(
        is_superseded(&watch.check()),
        "the release is over, but it deleted inside the window"
    );
}

#[skuld::test]
fn a_release_that_ended_before_touching_the_firewall_does_not_fail_the_check() {
    let d = dir();
    let watch = watch_releases(d.path());
    drop(begin_release(d.path()));
    assert!(
        watch.check().is_ok(),
        "a release that failed before its first delete changed nothing the install could have raced"
    );
}

#[skuld::test]
fn a_release_still_in_flight_fails_the_check_marked_or_not() {
    let d = dir();
    let watch = watch_releases(d.path());
    let release = begin_release(d.path());
    assert!(is_superseded(&watch.check()), "begun, not yet marked");
    release.about_to_delete();
    assert!(is_superseded(&watch.check()), "marked");
}

#[skuld::test]
fn a_watch_opened_during_a_release_is_failed_by_it_even_after_it_ends() {
    // The install read the state an Unblock writes while the Unblock was still persisting it.
    let d = dir();
    let release = begin_release(d.path());
    let watch = watch_releases(d.path());
    assert!(is_superseded(&watch.check()), "in flight");
    drop(release);
    assert!(
        is_superseded(&watch.check()),
        "ended without marking, but the watch was opened inside it"
    );
    assert!(
        watch_releases(d.path()).check().is_ok(),
        "a watch opened once it ended is clean"
    );
}

#[skuld::test]
fn a_watch_opened_after_a_release_ended_is_not_failed_by_it() {
    let d = dir();
    drop(deleting(d.path()));
    let watch = watch_releases(d.path());
    assert!(watch.check().is_ok());
}

#[skuld::test]
fn overlapping_releases_fail_a_check_until_both_end() {
    let d = dir();
    let first = begin_release(d.path());
    let second = begin_release(d.path());
    let watch = watch_releases(d.path());
    drop(first);
    assert!(is_superseded(&watch.check()), "one release is still in flight");
    drop(second);
    assert!(watch_releases(d.path()).check().is_ok());
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
        watch_releases(d.path()).check().is_ok(),
        "a panicking release must not leave the state dir permanently in flight"
    );
}

#[skuld::test]
fn the_epoch_is_per_state_dir() {
    let (a, b) = (dir(), dir());
    let watch_a = watch_releases(a.path());
    let _release_b = deleting(b.path());
    assert!(watch_a.check().is_ok(), "a release in B does not touch a watch on A");
    assert!(is_superseded(&watch_releases(b.path()).check()));
}

/// The `decide` of a record update runs under that record's lock; a watch check there takes no second lock.
#[skuld::test]
fn check_runs_inside_a_record_update() {
    let d = dir();
    let watch = watch_releases(d.path());

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
    let mut announced = false;
    let _clearance = sweep_with_witness(d.path(), None, |_, _| {
        announced = is_superseded(&watch_releases(d.path()).check());
        SweepOutcome::completed(Clearance::proven())
    })
    .unwrap();
    assert!(announced);
    assert!(watch_releases(d.path()).check().is_ok(), "and it ends with the sweep");
}

#[skuld::test]
fn a_sweep_that_reached_the_firewall_supersedes_a_watch_opened_before_it() {
    let d = dir();
    let watch = watch_releases(d.path());
    let _clearance = sweep_with_witness(d.path(), None, |_, release| {
        release.about_to_delete();
        SweepOutcome::completed(Clearance::proven())
    })
    .unwrap();
    assert!(is_superseded(&watch.check()));
}

#[skuld::test]
fn a_sweep_that_failed_before_the_firewall_supersedes_nothing() {
    let d = dir();
    let watch = watch_releases(d.path());
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
    assert!(watch_releases(d.path()).check().is_ok());
}
