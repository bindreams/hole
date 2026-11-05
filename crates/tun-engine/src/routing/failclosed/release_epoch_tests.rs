//! The release epoch orders an engage against a release without either
//! waiting for the other. Every test drives one interleaving by calling the other side
//! from inside a step, so nothing here depends on timing.

use super::*;

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().unwrap()
}

fn verdict(watch: &ReleaseWatch) -> Option<Overtaken> {
    watch.check().err()
}

#[skuld::test]
fn a_watch_with_no_release_since_checks_ok() {
    let d = dir();
    assert_eq!(verdict(&watch_releases(d.path())), None);
}

#[skuld::test]
fn a_release_that_ended_after_the_watch_supersedes_it() {
    let d = dir();
    let watch = watch_releases(d.path());
    drop(begin_release(d.path()));
    assert_eq!(
        verdict(&watch),
        Some(Overtaken::Superseded),
        "a release supersedes unless it says it changed nothing"
    );
}

#[skuld::test]
fn a_release_that_changed_nothing_does_not_fail_the_check() {
    let d = dir();
    let watch = watch_releases(d.path());
    begin_release(d.path()).changed_nothing();
    assert_eq!(
        verdict(&watch),
        None,
        "a release that failed before its first delete changed nothing the install could have raced"
    );
}

#[skuld::test]
fn a_release_in_flight_leaves_the_watch_in_doubt_until_it_says_what_it_did() {
    let d = dir();
    let watch = watch_releases(d.path());
    let release = begin_release(d.path());
    assert_eq!(verdict(&watch), Some(Overtaken::InDoubt), "nothing has moved yet");
    release.changed_nothing();
    assert_eq!(
        verdict(&watch),
        None,
        "it changed nothing, so there is nothing to doubt"
    );
}

#[skuld::test]
fn a_watch_opened_before_a_release_that_changed_something_stays_superseded_after_it_ends() {
    let d = dir();
    let watch = watch_releases(d.path());
    let release = begin_release(d.path());
    assert_eq!(verdict(&watch), Some(Overtaken::InDoubt), "in flight");
    drop(release);
    assert_eq!(verdict(&watch), Some(Overtaken::Superseded), "ended with a change");
    assert_eq!(verdict(&watch), Some(Overtaken::Superseded), "and it stays so");
}

#[skuld::test]
fn a_watch_opened_during_a_release_that_changed_something_is_superseded_when_it_ends() {
    // The install read the state an Unblock writes while the Unblock was still persisting it.
    let d = dir();
    let release = begin_release(d.path());
    let watch = watch_releases(d.path());
    assert_eq!(verdict(&watch), Some(Overtaken::InDoubt), "in flight");
    drop(release);
    assert_eq!(verdict(&watch), Some(Overtaken::Superseded), "ended with a change");
    assert_eq!(
        verdict(&watch_releases(d.path())),
        None,
        "a watch opened once it ended is clean"
    );
}

#[skuld::test]
fn a_watch_opened_during_a_release_that_changed_nothing_is_clear_when_it_ends() {
    let d = dir();
    let release = begin_release(d.path());
    let watch = watch_releases(d.path());
    release.changed_nothing();
    assert_eq!(verdict(&watch), None);
}

#[skuld::test]
fn a_watch_opened_after_a_release_ended_is_not_failed_by_it() {
    let d = dir();
    drop(begin_release(d.path()));
    assert_eq!(verdict(&watch_releases(d.path())), None);
}

#[skuld::test]
fn overlapping_releases_leave_a_watch_in_doubt_until_both_end() {
    let d = dir();
    let first = begin_release(d.path());
    let second = begin_release(d.path());
    let watch = watch_releases(d.path());
    first.changed_nothing();
    assert_eq!(
        verdict(&watch),
        Some(Overtaken::InDoubt),
        "one release is still in flight"
    );
    second.changed_nothing();
    assert_eq!(verdict(&watch), None);
}

#[skuld::test]
fn a_release_is_in_flight_until_its_guard_drops_even_on_an_unwind() {
    let d = dir();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _release = begin_release(d.path());
        panic!("a release body panics");
    }));
    assert!(unwound.is_err());
    assert_eq!(
        verdict(&watch_releases(d.path())),
        None,
        "a panicking release must not leave the state dir permanently in flight"
    );
}

#[skuld::test]
fn a_release_that_unwinds_supersedes_a_watch_opened_before_it() {
    let d = dir();
    let watch = watch_releases(d.path());
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _release = begin_release(d.path());
        panic!("a release body panics");
    }));
    assert!(unwound.is_err());
    assert_eq!(
        verdict(&watch),
        Some(Overtaken::Superseded),
        "it did not say it changed nothing"
    );
}

#[skuld::test]
fn the_epoch_is_per_state_dir() {
    let (a, b) = (dir(), dir());
    let watch_a = watch_releases(a.path());
    let _release_b = begin_release(b.path());
    assert_eq!(verdict(&watch_a), None, "a release in B does not touch a watch on A");
    assert_eq!(verdict(&watch_releases(b.path())), Some(Overtaken::InDoubt));
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
    let mut announced = None;
    let _clearance = sweep_with_witness(d.path(), None, |_| {
        announced = verdict(&watch_releases(d.path()));
        SweepOutcome::completed(Clearance::proven())
    })
    .unwrap();
    assert_eq!(announced, Some(Overtaken::InDoubt));
    assert_eq!(verdict(&watch_releases(d.path())), None, "and it ends with the sweep");
}

#[skuld::test]
fn a_sweep_that_completes_supersedes_a_watch_opened_before_it() {
    let d = dir();
    let watch = watch_releases(d.path());
    let _clearance = sweep_with_witness(d.path(), None, |_| SweepOutcome::completed(Clearance::proven())).unwrap();
    assert_eq!(verdict(&watch), Some(Overtaken::Superseded));
}

/// A macOS sweep has no firewall-unreached exit: a successful sweep over nothing to restore is a release too.
#[skuld::test]
fn a_sweep_with_nothing_to_delete_still_supersedes_a_watch_opened_before_it() {
    let d = dir();
    let watch = watch_releases(d.path());
    let result = sweep_with_witness(d.path(), None, |_| SweepOutcome::completed(Clearance::proven()));
    assert!(result.is_ok());
    assert_eq!(verdict(&watch), Some(Overtaken::Superseded));
}

#[skuld::test]
fn a_sweep_that_failed_after_reaching_the_firewall_supersedes_a_watch_opened_before_it() {
    let d = dir();
    let watch = watch_releases(d.path());
    let result = sweep_with_witness(d.path(), None, |_| {
        SweepOutcome::failed(Clearance::proven(), RoutingError::RouteSetup("a delete failed".into()))
    });
    assert!(result.is_err());
    assert_eq!(verdict(&watch), Some(Overtaken::Superseded));
}

#[skuld::test]
fn a_sweep_that_never_reached_the_firewall_supersedes_nothing() {
    let d = dir();
    let watch = watch_releases(d.path());
    let result = sweep_with_witness(d.path(), None, |_| {
        SweepOutcome::unreached(
            Clearance::proven(),
            RoutingError::RouteSetup("the engine would not open".into()),
        )
    });
    assert!(result.is_err());
    assert_eq!(verdict(&watch), None);
}

#[skuld::test]
fn a_failing_sweep_ends_its_release_too() {
    let d = dir();
    let result = sweep_with_witness(d.path(), None, |_| {
        SweepOutcome::failed(Clearance::proven(), RoutingError::RouteSetup("the sweep failed".into()))
    });
    assert!(result.is_err());
    assert_eq!(verdict(&watch_releases(d.path())), None);
}
