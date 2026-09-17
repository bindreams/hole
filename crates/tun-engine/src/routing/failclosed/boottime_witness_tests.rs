//! The evidence a SEQUENCE of sweeps carries, which is the only shape the
//! defect this module fixes can take.
//!
//! Every test here drives at least two sweeps over one `state_dir`. A single
//! observation slice cannot express "an earlier sweep removed the sibling", so
//! a suite built from single slices — which is what
//! `Clearance::leftover_keys`'s first form shipped with — cannot see a gate
//! that goes permanently silent after one ordinary user action.
//!
//! `#[cfg]`-free for the reason `clearance_tests` gives: the hazard is
//! Windows-only and its proof must not live only on Windows.

use std::path::Path;

use super::super::{ArmingWitness, Clearance, KeyLifetime, KeyObservation, KeyOutcome, KeyRole, RoutingError};
use super::{next_record, WitnessUpdate};

/// An ordinary key, whose outcome speaks only for itself.
fn obs(key: &'static str, lifetime: KeyLifetime, outcome: KeyOutcome) -> KeyObservation {
    KeyObservation {
        key,
        lifetime,
        outcome,
        role: KeyRole::Plain,
    }
}

/// The `PERSISTENT` half of the rule a twin copies — the only key in a sweep
/// whose outcome says whether a standing cover is installed right now.
fn sibling(outcome: KeyOutcome) -> KeyObservation {
    KeyObservation {
        key: "lockdown filter",
        lifetime: KeyLifetime::Persistent,
        outcome,
        role: KeyRole::BootTimeSibling,
    }
}

const TWIN: &str = "lockdown boot-time block-all V4";

/// The twin as any sweep sees it on a boot where no bridge engaged: its
/// runtime object is not live, so the delete finds nothing — on a host that
/// armed the kill switch years ago and on one that never armed it at all.
fn twin_not_found() -> KeyObservation {
    obs(TWIN, KeyLifetime::BootTime, KeyOutcome::NotFound)
}

/// The twin on the boot that armed it: the delete removed a live object and
/// something watched it go.
fn twin_removed() -> KeyObservation {
    obs(TWIN, KeyLifetime::BootTime, KeyOutcome::Removed)
}

/// Run one sweep against `state_dir`'s record, exactly as `release_all` and
/// `disengage_lockdown` do — consult, fold, write back.
fn sweep(state_dir: &Path, observations: &[KeyObservation]) -> Clearance {
    super::super::sweep_with_witness(state_dir, None, |witness| {
        Ok(Clearance::from_observations(observations, witness))
    })
    .expect("the sweep body cannot fail")
}

fn dir() -> tempfile::TempDir {
    tempfile::tempdir().expect("tempdir")
}

#[skuld::test]
fn a_sweep_that_consumed_the_sibling_leaves_a_later_one_able_to_report() {
    // bindreams/hole#1010 F1, end to end. The user arms the kill switch in one
    // boot, reboots (BFE re-adds the PERSISTENT half from its own store; the
    // twin's runtime object is gone), turns the switch off, and later
    // uninstalls.
    //
    // Sweep 1 is the ONE sweep in the whole lifecycle that can see the
    // evidence — and it is also the sweep that deletes it. Sweep 2 is the
    // uninstall gate, running at the moment `RemoveFiles` is about to delete
    // the only binary on the host that could issue an FWPM delete. Reading the
    // empty sibling set as "no cover was ever here" is what made that silent.
    let state = dir();

    let first = sweep(state.path(), &[sibling(KeyOutcome::Removed), twin_not_found()]);
    assert_eq!(first.leftover_keys(), [TWIN], "the sweep that holds the evidence");

    let second = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
    assert_eq!(
        second.leftover_keys(),
        [TWIN],
        "the sibling is gone because the FIRST sweep removed it; its absence is not evidence the \
         twin was never armed, and going silent here deletes hole.exe over a live boot-time record"
    );
}

#[skuld::test]
fn a_host_that_never_armed_a_twin_stays_silent_across_every_sweep() {
    // The overwhelmingly common uninstall, and the whole reason the report is
    // not simply `is_proven()`. Nothing was ever armed, so no record exists and
    // no sibling answers — three sweeps in a row have nothing to say. Firing
    // here on every Windows uninstall is what trains an operator to ignore the
    // host where it is real.
    let state = dir();
    for round in 0..3 {
        let c = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
        assert!(!c.is_proven(), "round {round}: the twin is still unproven");
        assert!(c.leftover_keys().is_empty(), "round {round}: {:?}", c.leftover_keys());
    }
    assert_eq!(
        super::load(state.path()),
        ArmingWitness::Unset,
        "a host that never armed a twin must not be littered with a record saying so"
    );
}

#[skuld::test]
fn a_sweep_that_watched_every_twin_go_clears_the_record() {
    // The other direction, and what keeps the report from becoming permanent
    // noise: turning the kill switch off in the SAME boot that engaged it
    // deletes a live boot-time object and watches it happen, which is proof for
    // any lifetime. A later uninstall has nothing to warn about.
    let state = dir();
    super::record_armed(state.path(), None);

    let off = sweep(state.path(), &[sibling(KeyOutcome::Removed), twin_removed()]);
    assert!(off.is_proven());
    assert!(off.leftover_keys().is_empty());
    assert_eq!(super::load(state.path()), ArmingWitness::Disarmed);

    let uninstall = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
    assert!(
        uninstall.leftover_keys().is_empty(),
        "every twin this host armed was watched being removed: {:?}",
        uninstall.leftover_keys()
    );
}

#[skuld::test]
fn an_empty_sibling_set_never_clears_a_recorded_twin() {
    // The defect one level down. "No standing cover is installed NOW" is what
    // the sibling answers, and it is not evidence about a boot-time record —
    // that is the entire premise of `KeyLifetime::BootTime`. A sweep that wrote
    // the record off on it would consume the persisted witness exactly as the
    // live one was consumed, just one release later.
    let state = dir();
    super::record_armed(state.path(), None);

    for round in 0..3 {
        let c = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
        assert_eq!(c.leftover_keys(), [TWIN], "round {round}");
        assert_eq!(super::load(state.path()), ArmingWitness::Armed, "round {round}");
    }
}

#[skuld::test]
fn the_engage_records_the_twin_before_any_sweep_could_have_seen_it() {
    // The sibling can be removed by something that is not a sweep at all — an
    // external FWPM delete, a firewall reset, an image restore. No sweep ever
    // held the evidence, so no sweep could have copied it; the engage is the
    // only site that knows the fact at the moment it becomes true.
    let state = dir();
    super::record_armed(state.path(), None);

    let c = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
    assert_eq!(
        c.leftover_keys(),
        [TWIN],
        "the record is the only surviving evidence and it must be enough"
    );
}

#[skuld::test]
fn a_sweep_that_failed_writes_nothing_down() {
    // `Err` means a delete was refused or the engine could not be reached.
    // Neither says anything about a key, so the record keeps what it held —
    // the same rule `KeyOutcome::Failed` states for a single key, applied to a
    // whole sweep.
    let state = dir();
    super::record_armed(state.path(), None);

    let failed: Result<Clearance, RoutingError> = super::super::sweep_with_witness(state.path(), None, |_| {
        Err(RoutingError::RouteSetup("the firewall refused the delete".into()))
    });
    assert!(failed.is_err());
    assert_eq!(
        super::load(state.path()),
        ArmingWitness::Armed,
        "a sweep that learned nothing must not overwrite what an earlier one learned"
    );
}

#[skuld::test]
fn a_record_that_cannot_be_read_reports_rather_than_suppressing() {
    // Losing the record is not evidence that nothing was armed — the same
    // asymmetry `lockdown_state::Intent::Unreadable` carries, and the same one
    // `SiblingEvidence::Unknown` carries. Both axes refuse to read absence of
    // evidence as evidence of absence.
    let state = dir();
    std::fs::write(state.path().join(super::STATE_FILE_NAME), b"{ not json").expect("write");
    assert_eq!(super::load(state.path()), ArmingWitness::Unreadable);

    let c = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
    assert_eq!(c.leftover_keys(), [TWIN]);
}

#[skuld::test]
fn a_record_at_another_schema_version_reports_rather_than_suppressing() {
    // A version-skewed file is a file whose meaning is unknown, not an absent
    // one. Discarding it as absence is how a downgrade would silently disarm
    // the gate.
    let state = dir();
    std::fs::write(
        state.path().join(super::STATE_FILE_NAME),
        br#"{"version": 99, "armed": false}"#,
    )
    .expect("write");
    assert_eq!(super::load(state.path()), ArmingWitness::Unreadable);
}

#[skuld::test]
fn a_recorded_twin_survives_being_read_back() {
    let state = dir();
    assert_eq!(super::load(state.path()), ArmingWitness::Unset);
    super::record_armed(state.path(), None);
    assert_eq!(super::load(state.path()), ArmingWitness::Armed);
}

#[skuld::test]
fn every_update_and_record_pair_has_one_answer_and_only_proof_writes_false() {
    // The whole write table in one place. The two cells that matter: `Disarm`
    // over `Unset` writes NOTHING (a host that never armed a twin must not be
    // littered with a record), and `Disarm` over `Unreadable` DOES write (a
    // corrupt file would otherwise report forever, and this sweep just proved
    // there is nothing to report).
    let table = [
        (ArmingWitness::Armed, WitnessUpdate::Leave, None),
        (ArmingWitness::Disarmed, WitnessUpdate::Leave, None),
        (ArmingWitness::Unset, WitnessUpdate::Leave, None),
        (ArmingWitness::Unreadable, WitnessUpdate::Leave, None),
        (ArmingWitness::Armed, WitnessUpdate::Arm, None),
        (ArmingWitness::Disarmed, WitnessUpdate::Arm, Some(true)),
        (ArmingWitness::Unset, WitnessUpdate::Arm, Some(true)),
        (ArmingWitness::Unreadable, WitnessUpdate::Arm, Some(true)),
        (ArmingWitness::Armed, WitnessUpdate::Disarm, Some(false)),
        (ArmingWitness::Disarmed, WitnessUpdate::Disarm, None),
        (ArmingWitness::Unset, WitnessUpdate::Disarm, None),
        (ArmingWitness::Unreadable, WitnessUpdate::Disarm, Some(false)),
    ];
    for (current, update, want) in table {
        assert_eq!(next_record(current, update), want, "{current:?} + {update:?}");
    }
}

#[skuld::test]
fn a_sweep_carrying_no_boot_time_key_at_all_leaves_the_record_alone() {
    // macOS's shape, and any future sweep list that drops the twins. "Every
    // boot-time key proved empty" is vacuously true of an empty set, so the
    // natural reading of the write rule would clear a real record the moment
    // the twins left the sweep list — silently, and in the direction that
    // hurts.
    let state = dir();
    super::record_armed(state.path(), None);

    let c = sweep(state.path(), &[sibling(KeyOutcome::Removed)]);
    assert!(c.is_proven(), "nothing in this sweep went unproven");
    assert_eq!(
        super::load(state.path()),
        ArmingWitness::Armed,
        "a sweep with no boot-time key observed nothing the record is about"
    );
}
