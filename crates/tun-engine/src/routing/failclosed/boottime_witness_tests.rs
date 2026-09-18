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

use super::super::{
    ArmingWitness, Clearance, KeyLifetime, KeyObservation, KeyOutcome, KeyRole, RoutingError, SweepOutcome,
};
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
        SweepOutcome::completed(Clearance::from_observations(observations, witness))
    })
    .expect("the sweep body cannot fail")
}

/// A sweep that issued every delete, observed `observations`, and THEN found a
/// failing code among them — the shape both Windows sweeps have, where no
/// code is inspected until all of them are in.
fn failing_sweep(state_dir: &Path, observations: &[KeyObservation]) -> RoutingError {
    super::super::sweep_with_witness(state_dir, None, |witness| {
        SweepOutcome::failed(
            Clearance::from_observations(observations, witness),
            RoutingError::RouteSetup("the firewall refused one of the deletes".into()),
        )
    })
    .expect_err("the sweep body failed")
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
fn arming_then_unblocking_in_one_boot_clears_the_record_and_stays_clear() {
    // The most ordinary kill-switch lifecycle there is: arm the switch, then
    // hit "Unblock Network" (or turn it off) in the SAME boot, then uninstall
    // later. The unblock deletes a LIVE twin and gets `ERROR_SUCCESS` back.
    //
    // This sequence used to be the one that had to stay loud and is now the
    // one that goes quiet, and the flip is exactly bindreams/hole#1043's
    // assumption: the by-key delete purges the boot-time policy record along
    // with the runtime object it demonstrably removed. The silence is
    // therefore about a twin somebody WATCHED go, not about one nobody
    // measured — which is the distinction #1003 collapsed. What still cannot
    // go quiet is an empty answer; that is
    // `an_empty_sibling_set_never_clears_a_recorded_twin`.
    let state = dir();
    super::record_armed(state.path(), None);

    let off = sweep(state.path(), &[sibling(KeyOutcome::Removed), twin_removed()]);
    assert!(
        off.leftover_keys().is_empty(),
        "the unblock watched the twin go: {:?}",
        off.leftover_keys()
    );
    assert_eq!(
        super::load(state.path()),
        ArmingWitness::Disarmed,
        "a watched removal is the one observation that retracts the record"
    );

    let uninstall = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
    assert!(
        uninstall.leftover_keys().is_empty(),
        "and the uninstall after it has nothing to say either — no cover installed, no record \
         outstanding: {:?}",
        uninstall.leftover_keys()
    );
}

#[skuld::test]
fn an_uninstall_on_the_boot_that_armed_the_twin_watched_it_go() {
    // Arm the kill switch, then uninstall straight away. The MSI stops the
    // bridge and runs `release-covers` while the twins are still live, so
    // every key — sibling and twin alike — answers `ERROR_SUCCESS`.
    //
    // The gate is the very sweep doing the removing, so no persisted record
    // could ever rescue this one — which is why it mattered so much that the
    // twin's own delete be conclusive. Under #1043's assumption it is: the
    // sweep took the record away with the object, and `RemoveFiles` deleting
    // the binary afterwards strands nothing.
    let state = dir();
    super::record_armed(state.path(), None);

    let uninstall = sweep(state.path(), &[sibling(KeyOutcome::Removed), twin_removed()]);
    assert!(uninstall.is_proven(), "every key this sweep touched was watched going");
    assert!(uninstall.leftover_keys().is_empty(), "{:?}", uninstall.leftover_keys());
    assert_eq!(super::load(state.path()), ArmingWitness::Disarmed);
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
fn a_failed_sweep_that_already_removed_the_sibling_still_records_what_it_saw() {
    // bindreams/hole#1010 F1. Both Windows sweeps ISSUE every delete before
    // inspecting ANY code, so `Err` arrives AFTER the sibling's own delete
    // succeeded: the sibling is gone from the host and its `Removed` is
    // sitting in the observation set. Returning early on the failure threw
    // that away, and one act then consumed BOTH evidence sources — the live
    // sibling deleted, the record never written.
    //
    // The state dir starts empty on purpose: this is the host the disjointness
    // argument names the sibling as the fallback for (an OS in-place reset, a
    // profile migration, a user deleting the folder), so the record is the
    // thing that has to be created here, not merely preserved.
    let state = dir();
    let err = failing_sweep(
        state.path(),
        &[
            sibling(KeyOutcome::Removed),
            twin_not_found(),
            obs("lockdown app-id filter", KeyLifetime::Persistent, KeyOutcome::Failed),
        ],
    );
    assert!(format!("{err}").contains("refused"), "the failure still travels: {err}");
    assert_eq!(
        super::load(state.path()),
        ArmingWitness::Armed,
        "the sibling's delete succeeded before any code was read; discarding that observation is \
         what let one failing app-id delete silence every later sweep"
    );

    let uninstall = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_not_found()]);
    assert_eq!(
        uninstall.leftover_keys(),
        [TWIN],
        "the sibling is gone because the FAILED sweep removed it, so the record is the only \
         evidence left and it must be there"
    );
}

#[skuld::test]
fn a_sweep_that_never_reached_the_firewall_writes_nothing_down() {
    // The other failure cause, and it is a different one: `FwpmEngineOpen0`
    // failing means no delete was ever ISSUED, so there is no observation to
    // carry — the empty fold, not a discarded one. Nothing about a key was
    // learned, so the record keeps what it held, in BOTH directions: a host
    // with no record must not gain one, and a host with one must not lose it.
    let fresh = dir();
    let err = failing_sweep(fresh.path(), &[]);
    assert!(format!("{err}").contains("refused"), "{err}");
    assert_eq!(
        super::load(fresh.path()),
        ArmingWitness::Unset,
        "an unreachable firewall observed nothing, so it must not litter a host that never armed \
         a twin with a record saying it did"
    );

    // The other direction, and it is live rather than forward-looking: a fold
    // that read an empty observation set as "every boot-time key proved empty"
    // would answer `Disarm` here and throw away what an earlier sweep learned,
    // on a failure that observed nothing at all.
    let armed = dir();
    super::record_armed(armed.path(), None);
    failing_sweep(armed.path(), &[]);
    assert_eq!(
        super::load(armed.path()),
        ArmingWitness::Armed,
        "and it must not overwrite what an earlier sweep learned"
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
fn every_update_and_record_pair_has_one_write_answer() {
    // The whole write table in one place. Three properties it pins, each of
    // which was a bug in some earlier shape of this file:
    //
    // * `Arm` over `Disarmed` DOES write — a file that says "not armed" was
    //   written by something that claimed a proof, and this sweep just found a
    //   twin it could NOT prove gone.
    // * `Disarm` over `Unset` writes NOTHING. A host that never armed a twin
    //   must not gain a file saying so, on every `release-covers` it ever
    //   runs.
    // * `Disarm` over `Unreadable` DOES write — a corrupt file reports forever
    //   otherwise, and this sweep watched the twin go.
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
fn a_host_that_never_armed_a_twin_is_not_littered_by_a_sweep_that_watched_one_go() {
    // The `Disarm` + `Unset` cell above, end to end. Every `release-covers` on
    // a clean host sweeps the twin keys, and on the boot a bridge DID engage
    // the twins are live, so `ERROR_SUCCESS` here is not exotic. Writing
    // `armed: false` would create a state file on a host that has nothing to
    // record, in a directory the uninstall is about to remove.
    let state = dir();
    let c = sweep(state.path(), &[sibling(KeyOutcome::NotFound), twin_removed()]);
    assert!(c.leftover_keys().is_empty(), "{:?}", c.leftover_keys());
    assert_eq!(super::load(state.path()), ArmingWitness::Unset);
    assert!(
        !state.path().join(super::STATE_FILE_NAME).exists(),
        "no file at all, not a file that says nothing"
    );
}

#[skuld::test]
fn a_record_that_cannot_be_read_is_replaced_by_a_sweep_that_watched_the_twin_go() {
    // The `Disarm` + `Unreadable` cell, end to end, and the one direction an
    // unreadable record MAY be overwritten. Everywhere else a lost record
    // reports (`a_record_that_cannot_be_read_reports_rather_than_suppressing`)
    // — but that is absence of evidence, and this sweep has evidence: it
    // watched the twin's delete remove a live object.
    let state = dir();
    std::fs::write(state.path().join(super::STATE_FILE_NAME), b"{ not json").expect("write");
    assert_eq!(super::load(state.path()), ArmingWitness::Unreadable);

    let c = sweep(state.path(), &[sibling(KeyOutcome::Removed), twin_removed()]);
    assert!(c.leftover_keys().is_empty(), "{:?}", c.leftover_keys());
    assert_eq!(
        super::load(state.path()),
        ArmingWitness::Disarmed,
        "a corrupt record would otherwise report for the life of the state dir"
    );
}

#[skuld::test]
fn a_record_that_says_not_armed_is_re_armed_rather_than_left_alone() {
    // The one cell above that actually writes over an existing file, driven
    // end to end. Nothing in this version writes `armed: false`, so such a
    // file can only come from a hand-edit or a future version with a
    // reboot-capable measurement behind it — and either way a sweep that finds
    // an unproven twin beside a live cover has just contradicted it.
    let state = dir();
    std::fs::write(
        state.path().join(super::STATE_FILE_NAME),
        format!(r#"{{"version": {}, "armed": false}}"#, super::SCHEMA_VERSION),
    )
    .expect("write");
    assert_eq!(super::load(state.path()), ArmingWitness::Disarmed);

    let c = sweep(state.path(), &[sibling(KeyOutcome::Removed), twin_not_found()]);
    assert_eq!(c.leftover_keys(), [TWIN]);
    assert_eq!(super::load(state.path()), ArmingWitness::Armed);
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

// Where the engage arms the record ====================================================================================

/// The text of the item starting at `head`, bounded by its own column-0
/// closing brace, so a guard cannot drift onto a neighbour or read its own
/// prose. (The same helper `windows_tests` uses for its source tripwires; it
/// is copied rather than shared because that module compiles only on Windows,
/// which is exactly what the guard below must not depend on.)
fn item_body<'a>(src: &'a str, head: &str) -> &'a str {
    let start = src
        .find(head)
        .unwrap_or_else(|| panic!("{head} must exist in windows.rs"));
    let after = &src[start..];
    let end = after.find("\n}\n").map(|i| i + 2).unwrap_or(after.len());
    &after[..end]
}

#[skuld::test]
fn the_engage_arms_the_record_at_the_commit_and_nowhere_downstream_of_it() {
    // Source tripwire, the technique and the reason of `windows_tests`'
    // `neither_engage_discards_its_pre_delete_codes`: no fixture in any lane
    // can make a real `FwpmTransactionCommit0` succeed and the read-back after
    // it fail, and that single run is the only one where this ordering is
    // observable at all. The privileged lane's
    // `..._every_engage_rearms_the_twins_...` asserts `load(dir) == Armed`
    // after an engage that already returned `Ok`, so it cannot tell "recorded
    // at the commit" from "recorded after the read-back".
    //
    // It lives here rather than beside that guard for the reason this module's
    // doc and `record_armed`'s own doc both give: the hazard is Windows-only
    // and its proof must not live only on Windows.
    //
    // What it holds. `commit_and_record` is one step because the fact the
    // record describes becomes true the instant the commit returns
    // `ERROR_SUCCESS` — the twins are in the store, the cover is in force —
    // and every statement after it can fail over a cover that still stands.
    // Moving the record down beside `verify_boottime_twins`, so it "only goes
    // in once the twins are confirmed", reads as MORE careful and is
    // bindreams/hole#1003: a host whose read-back fails then holds a
    // committed, in-force boot-time block-all with nothing recorded, and when
    // its `PERSISTENT` sibling is later cleared by something that is not a
    // sweep — an external FWPM delete, a firewall reset — no sweep ever held
    // the evidence to copy. That is not hypothetical: this PR introduced that
    // exact split once, in the round that fixed its predecessor, with the
    // whole suite green.
    let src = include_str!("windows.rs");

    let engage = item_body(src, "pub fn engage_lockdown(");
    // Matched on the call, not on the name: this body's own prose names
    // `commit_and_record` (the comment under the call says why the record
    // precedes the read-back), so a `contains("commit_and_record")` would go
    // on passing over a body that had inlined the commit and kept only the
    // sentence about it.
    assert_eq!(
        engage.matches("commit_and_record(engine, state_dir, owner)?").count(),
        1,
        "engage_lockdown must commit through commit_and_record, exactly once:\n{engage}"
    );
    assert_eq!(
        engage.matches("FwpmTransactionCommit0").count(),
        0,
        "engage_lockdown must reach its commit only through commit_and_record — inlining it for \
         readability is what separates the commit from the record it has to carry:\n{engage}"
    );

    let commit = item_body(src, "unsafe fn commit_and_record(");
    let commit_at = commit
        .find("FwpmTransactionCommit0")
        .unwrap_or_else(|| panic!("commit_and_record must be the site that commits:\n{commit}"));
    let record_at = commit
        .find("record_armed(")
        .unwrap_or_else(|| panic!("commit_and_record must be the site that arms the record:\n{commit}"));
    assert!(
        commit_at < record_at,
        "the record must be written AFTER the commit that makes it true — written first, it \
         survives an aborted transaction and claims a twin on a host that has none:\n{commit}"
    );

    // Counted on the call site, file-wide: a record moved out of
    // `commit_and_record` lands wherever the mover found convenient, and only
    // one of those places is inside any one body. Matched on `record_armed(`
    // rather than the bare name so a doc link — the shape a prose mention
    // takes in this file — is not read as a write.
    let arming_sites: Vec<&str> = src.lines().filter(|l| l.contains("record_armed(")).collect();
    assert_eq!(
        arming_sites.len(),
        1,
        "windows.rs may arm the boot-time record in exactly one place; found {arming_sites:?}"
    );
    assert!(
        commit.contains(arming_sites[0].trim()),
        "the one site that arms the record must sit inside commit_and_record, beside the commit \
         that makes it true — not downstream of a read-back that can fail over a cover already in \
         force: {arming_sites:?}"
    );
}
