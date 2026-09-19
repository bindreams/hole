//! What a cover release PROVED, as distinct from what it attempted.
//!
//! `#[cfg]`-free on purpose: the fold under test is the decision the uninstall
//! gate reads, and it must be falsifiable on every platform's lane rather than
//! only on the one where the filters it describes exist.

use super::*;

/// Fold a sweep against a host with NO persisted record — the state every
/// test below that is only about the sibling axis wants, and the one an
/// ordinary host is in. `ArmingWitness::Unset` contributes no evidence, so
/// what these assert is the sibling's own rule in isolation.
fn fold(observations: &[KeyObservation]) -> Clearance {
    Clearance::from_observations(observations, ArmingWitness::Unset)
}

/// An ordinary key, whose outcome speaks only for itself.
fn obs(key: &'static str, lifetime: KeyLifetime, outcome: KeyOutcome) -> KeyObservation {
    KeyObservation {
        key,
        lifetime,
        outcome,
        role: KeyRole::Plain,
    }
}

/// The PERSISTENT half of the rule a boot-time twin copies — the one key
/// whose outcome says whether a standing cover is installed on this host.
fn sibling(outcome: KeyOutcome) -> KeyObservation {
    KeyObservation {
        key: "lockdown filter",
        lifetime: KeyLifetime::Persistent,
        outcome,
        role: KeyRole::BootTimeSibling,
    }
}

/// The twin as a sweep sees it on any boot where no bridge engaged.
fn unproven_twin() -> KeyObservation {
    obs(
        "lockdown boot-time block-all V4",
        KeyLifetime::BootTime,
        KeyOutcome::NotFound,
    )
}

#[skuld::test]
fn a_sweep_that_observed_nothing_is_proven_clear() {
    // macOS, and any Windows host whose swept set is empty: there is no key
    // whose absence went unproven, so the gate has nothing to qualify.
    assert!(fold(&[]).is_proven());
    assert!(Clearance::proven().is_proven());
    assert!(Clearance::proven().unproven_keys().is_empty());
}

#[skuld::test]
fn a_persistent_key_that_answered_not_found_is_proven_empty() {
    // BFE's store is the only record of a PERSISTENT filter and a by-key
    // delete addresses it directly, so "not found" is proof the key carries
    // nothing. This is the case the old whitelist got right.
    let c = fold(&[obs("lockdown filter", KeyLifetime::Persistent, KeyOutcome::NotFound)]);
    assert!(c.is_proven(), "not-found on a persistent key proves it empty");
    assert!(c.unproven_keys().is_empty());
}

#[skuld::test]
fn a_boot_time_key_that_answered_not_found_is_not_proven_empty() {
    // The #1003 pre-BFE case, and the whole reason this type exists: a
    // boot-time object is live only between kernel start and BFE start, so on
    // a boot where the bridge never engaged the key answers "not found"
    // whether or not a boot-time policy record is still provisioned behind
    // it. The old code folded this into `Ok` and the MSI read that as "safe
    // to delete hole.exe".
    let c = fold(&[obs(
        "lockdown boot-time block-all V4",
        KeyLifetime::BootTime,
        KeyOutcome::NotFound,
    )]);
    assert!(!c.is_proven(), "not-found on a boot-time key proves nothing");
    assert_eq!(c.unproven_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn a_boot_time_key_the_delete_removed_is_proven_by_the_watched_removal() {
    // The asymmetry that makes the boot-time row two answers rather than one.
    // A removal somebody watched happen is proof HERE, under the repo owner's
    // assumption that `FwpmFilterDeleteByKey0` purges the boot-time policy
    // record along with the runtime object it demonstrably removes
    // (bindreams/hole#1043 tracks verifying that on real hardware — no lane
    // reboots, so nothing in CI can settle it).
    //
    // It is NOT symmetric with a not-found, which stays proof of nothing: see
    // `a_boot_time_key_that_answered_not_found_is_not_proven_empty`. The
    // difference is what the sweep watched — a removal is an event it saw, an
    // empty answer is the ordinary reading on every boot where no object is
    // live.
    let c = fold(&[obs(
        "lockdown boot-time block-all V4",
        KeyLifetime::BootTime,
        KeyOutcome::Removed,
    )]);
    assert!(c.is_proven());
    assert!(c.unproven_keys().is_empty());
}

#[skuld::test]
fn a_failing_sweep_outcome_carries_its_observations_beside_the_error() {
    // bindreams/hole#1010 F1, at the type. The failure and the clearance
    // travel together in one value, so no `?` can take the second away with
    // the first — which is what happened while the sweeps returned a
    // `Result`, on a codebase whose sweeps issue every delete before reading
    // any code.
    let outcome = SweepOutcome::failed(
        fold(&[sibling(KeyOutcome::Removed), unproven_twin()]),
        RoutingError::RouteSetup("one delete was refused".into()),
    );
    assert_eq!(
        outcome.clearance().witness_update(),
        crate::routing::failclosed::boottime_witness::WitnessUpdate::Arm,
        "the sibling this sweep already removed is still evidence, and the record is written \
         from it"
    );
    assert_eq!(outcome.clearance().leftover_keys(), ["lockdown boot-time block-all V4"]);
    assert!(outcome.into_result().is_err(), "and the failure still travels");

    let clean = SweepOutcome::completed(Clearance::proven());
    assert!(clean.clearance().is_proven());
    assert!(clean.into_result().is_ok());
}

#[skuld::test]
fn a_mixed_sweep_names_every_unproven_key_and_only_those() {
    // The operator message has to be actionable, and after this point the
    // label is all anyone has to look a key up by. A count would not survive
    // that requirement.
    let c = fold(&[
        obs("lockdown filter", KeyLifetime::Persistent, KeyOutcome::NotFound),
        obs("boot-time block-all V4", KeyLifetime::BootTime, KeyOutcome::NotFound),
        obs("transient filter", KeyLifetime::Persistent, KeyOutcome::Removed),
        obs("boot-time block-all V6", KeyLifetime::BootTime, KeyOutcome::Removed),
        obs(
            "boot-time block-all V6 twin",
            KeyLifetime::BootTime,
            KeyOutcome::NotFound,
        ),
    ]);
    assert!(!c.is_proven());
    assert_eq!(
        c.unproven_keys(),
        ["boot-time block-all V4", "boot-time block-all V6 twin"],
        "the two boot-time keys that answered EMPTY are unproven; the one whose removal was \
         watched is proven, and no persistent key joins either group"
    );
}

#[skuld::test]
fn a_delete_that_failed_proves_nothing_for_either_lifetime() {
    // The anti-pattern this type exists to refuse: "not NotFound, therefore
    // Removed". An access denial, an RPC failure and a genuine removal share
    // the consequence "the code was not FWP_E_FILTER_NOT_FOUND" and nothing
    // else. Folding them together hands the uninstall gate a proof of removal
    // nobody observed — and `RemoveFiles` then deletes the only binary that
    // could have acted on the difference.
    for lifetime in [KeyLifetime::Persistent, KeyLifetime::BootTime] {
        let o = obs("lockdown filter", lifetime, KeyOutcome::Failed);
        assert!(
            !o.proves_empty(),
            "a delete that neither removed nor found-empty proves nothing ({lifetime:?})"
        );
        let c = fold(&[o]);
        assert!(!c.is_proven(), "{lifetime:?}");
        assert_eq!(c.unproven_keys(), ["lockdown filter"]);
    }
}

#[skuld::test]
fn every_outcome_lifetime_pair_has_one_answer() {
    // The whole table, so the rule is readable in one place and a new variant
    // cannot be added without landing here. The two rows differ in exactly one
    // cell, `NotFound`: a persistent key's only record is the one the by-key
    // delete addresses, so an empty answer is proof, while a boot-time key
    // answers empty on every boot where its runtime object is not live — on a
    // host that armed the switch years ago and on one that never armed it.
    // `Removed` is proof for both under bindreams/hole#1043's purge
    // assumption, and `Failed` proves nothing anywhere.
    let table = [
        (KeyLifetime::Persistent, KeyOutcome::Removed, true),
        (KeyLifetime::Persistent, KeyOutcome::NotFound, true),
        (KeyLifetime::Persistent, KeyOutcome::Failed, false),
        (KeyLifetime::BootTime, KeyOutcome::Removed, true),
        (KeyLifetime::BootTime, KeyOutcome::NotFound, false),
        (KeyLifetime::BootTime, KeyOutcome::Failed, false),
    ];
    for (lifetime, outcome, proves) in table {
        assert_eq!(
            obs("k", lifetime, outcome).proves_empty(),
            proves,
            "{lifetime:?} + {outcome:?}"
        );
    }
}

#[skuld::test]
fn clearance_reports_the_same_key_once_per_observation_it_could_not_prove() {
    // Two distinct keys can share a label (the Windows sweep labels by cover
    // kind, not by GUID). Deduplicating would under-report how much of the
    // sweep went unproven, so the fold does not.
    let c = fold(&[
        obs("lockdown boot-time filter", KeyLifetime::BootTime, KeyOutcome::NotFound),
        obs("lockdown boot-time filter", KeyLifetime::BootTime, KeyOutcome::NotFound),
    ]);
    assert_eq!(c.unproven_keys().len(), 2);
}

// What is worth REPORTING, as distinct from what was proven ===========================================================
//
// A boot-time key answers empty on every boot where no bridge engaged, so an
// unproven twin is the ordinary outcome of an ordinary uninstall rather than
// the exceptional one. The sibling — the PERSISTENT half of the same rule,
// which BFE re-adds at every boot — is the only key in the sweep that can say
// whether a record was ever possible here.

#[skuld::test]
fn a_twin_on_a_host_with_no_standing_cover_is_unproven_but_not_reported() {
    // The overwhelmingly common uninstall: the kill switch was never armed,
    // so every key answers empty. The twin is still UNPROVEN — nothing
    // measured it — but a twin is only ever added in the same transaction as
    // the sibling, and the sibling is not installed either, so there is
    // nothing to tell an operator. Reporting here on every uninstall is what
    // trains them to ignore the host where it is real.
    let c = fold(&[sibling(KeyOutcome::NotFound), unproven_twin()]);
    assert!(!c.is_proven(), "the sweep still proved nothing about the twin");
    assert_eq!(c.unproven_keys(), ["lockdown boot-time block-all V4"]);
    assert!(
        c.leftover_keys().is_empty(),
        "no standing cover is installed, so no twin could have been added beside one: {:?}",
        c.leftover_keys()
    );
}

#[skuld::test]
fn a_twin_beside_a_cover_this_sweep_removed_is_reported() {
    // The dangerous case, and the whole reason the report survives: armed in
    // an earlier boot, rebooted, uninstalled without ever connecting. BFE
    // re-added the PERSISTENT half from its own store, so the sibling's
    // delete removes a live object — while the twin, which BFE never re-adds,
    // answers empty. That is a host where a boot-time record is genuinely
    // possible.
    let c = fold(&[sibling(KeyOutcome::Removed), unproven_twin()]);
    assert_eq!(c.leftover_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn a_sweep_carrying_no_sibling_at_all_reports_its_unproven_twins() {
    // The fold's dangerous default. "Every sibling answered empty" is
    // vacuously true of an empty set, so the natural reading would suppress
    // every report the moment a boot-time key outlived its sibling in some
    // future sweep list — silently, and in the direction that hurts.
    let c = fold(&[unproven_twin()]);
    assert_eq!(
        c.leftover_keys(),
        ["lockdown boot-time block-all V4"],
        "with no sibling to ask, nothing was ruled out"
    );
}

#[skuld::test]
fn a_sibling_whose_delete_failed_cannot_rule_out_a_leftover() {
    // `Failed` is the unelevated / DACL-denied sweep. It is not "the key was
    // empty" and must never be read as one — the same anti-pattern
    // `proves_empty` refuses, applied to the second axis.
    let c = fold(&[sibling(KeyOutcome::Failed), unproven_twin()]);
    assert!(
        c.leftover_keys().contains(&"lockdown boot-time block-all V4"),
        "a sibling that could not be read rules nothing out: {:?}",
        c.leftover_keys()
    );
}

#[skuld::test]
fn one_removed_sibling_outweighs_an_empty_one() {
    // The twins are a V4/V6 pair and so are their siblings, and the two
    // families fail independently — a host with no IPv6 binding is an
    // ordinary cause of a V6-only empty answer. One live sibling is evidence
    // a cover is installed; the other answering empty does not retract it.
    let c = fold(&[
        sibling(KeyOutcome::NotFound),
        sibling(KeyOutcome::Removed),
        unproven_twin(),
    ]);
    assert_eq!(c.leftover_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn an_uninstall_on_the_boot_that_engaged_is_quiet_because_it_watched_the_twin_go() {
    // The MSI stops the bridge and runs `release-covers` on the boot the kill
    // switch was armed, so the sibling AND the twin are both live and both
    // answer `ERROR_SUCCESS`.
    //
    // This case used to be the loud one and is now the quiet one, and the
    // flip is the whole content of bindreams/hole#1043's assumption. The
    // silence here is NOT the #1003 silence: that one came from a twin nobody
    // measured (an empty answer read as proof), while this sweep watched both
    // halves of the rule go. Under the assumption that the by-key delete
    // purges the record with the object, a watched removal leaves nothing to
    // report — and reporting it anyway would name two keys this very call
    // deleted, on the host that has just been cleaned up.
    //
    // The evidence the report DOES fire on is untouched: a twin that answered
    // empty beside a live sibling still reports
    // (`a_twin_beside_a_cover_this_sweep_removed_is_reported`).
    let c = fold(&[
        sibling(KeyOutcome::Removed),
        obs(
            "lockdown boot-time block-all V4",
            KeyLifetime::BootTime,
            KeyOutcome::Removed,
        ),
    ]);
    assert!(c.is_proven());
    assert!(c.leftover_keys().is_empty(), "{:?}", c.leftover_keys());
    // A platform with no boot-time key class still has nothing to say.
    assert!(Clearance::proven().leftover_keys().is_empty());
}

#[skuld::test]
fn every_sibling_evidence_has_one_answer_and_only_an_empty_one_suppresses() {
    // The whole second table, beside `proves_empty`'s, so both rules are
    // readable in one place and a new `KeyOutcome` cannot be added without
    // landing in each. Only an all-empty sibling set suppresses; a removal
    // and an unreadable answer report for opposite reasons.
    let table = [
        (KeyOutcome::Removed, SiblingEvidence::Installed, true),
        (KeyOutcome::NotFound, SiblingEvidence::Absent, false),
        (KeyOutcome::Failed, SiblingEvidence::Unknown, true),
    ];
    for (outcome, evidence, reports) in table {
        assert_eq!(sibling_evidence(&[sibling(outcome)]), evidence, "{outcome:?}");
        let c = fold(&[sibling(outcome), unproven_twin()]);
        assert_eq!(
            c.leftover_keys().contains(&"lockdown boot-time block-all V4"),
            reports,
            "{outcome:?}"
        );
    }
    assert_eq!(
        sibling_evidence(&[]),
        SiblingEvidence::Unknown,
        "an empty sibling set rules nothing out"
    );
    assert_eq!(
        sibling_evidence(&[obs("k", KeyLifetime::Persistent, KeyOutcome::Removed)]),
        SiblingEvidence::Unknown,
        "a PLAIN key speaks only for itself, however it answered"
    );
}

// The second evidence source, and why one is not enough ===============================================================
//
// The sibling is LIVE evidence and the only kind that survives a wiped
// `state_dir`; it is also consumed by the first sweep that removes it. The
// persisted record (`boottime_witness`) survives that removal and is lost by
// the wipe. `leftover_keys` reports when EITHER says a record is possible, so
// it is silent only where both are.

#[skuld::test]
fn a_recorded_twin_reports_even_where_the_sibling_is_gone() {
    // The #1010 F1 shape as a single fold: the sibling was deleted by an
    // earlier sweep, so this one can only answer `Absent`. Before the record
    // existed, that answer alone suppressed the report — forever, after one
    // ordinary "turn the kill switch off".
    let c = Clearance::from_observations(&[sibling(KeyOutcome::NotFound), unproven_twin()], ArmingWitness::Armed);
    assert_eq!(c.leftover_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn a_live_sibling_reports_even_where_the_record_is_gone() {
    // The other half of the union, and the reason the record did not simply
    // replace the sibling: a wiped or recreated `state_dir` reads `Unset`,
    // which is indistinguishable from a host that never armed a twin. The
    // standing cover itself is still installed and says so.
    let c = Clearance::from_observations(&[sibling(KeyOutcome::Removed), unproven_twin()], ArmingWitness::Unset);
    assert_eq!(c.leftover_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn every_evidence_pair_has_one_answer_and_only_both_ruling_out_suppresses() {
    // The whole union table, so the rule is readable in one place and neither
    // axis can gain a variant without landing here. A cell is `false` only
    // where the sweep found no cover AND no record says one was ever armed.
    let sibling_axis = [
        (KeyOutcome::Removed, SiblingEvidence::Installed, true),
        (KeyOutcome::Failed, SiblingEvidence::Unknown, true),
        (KeyOutcome::NotFound, SiblingEvidence::Absent, false),
    ];
    let witness_axis = [
        (ArmingWitness::Armed, true),
        (ArmingWitness::Unreadable, true),
        (ArmingWitness::Disarmed, false),
        (ArmingWitness::Unset, false),
    ];
    for (outcome, evidence, sibling_reports) in sibling_axis {
        assert_eq!(sibling_evidence(&[sibling(outcome)]), evidence, "{outcome:?}");
        for (witness, witness_reports) in witness_axis {
            let c = Clearance::from_observations(&[sibling(outcome), unproven_twin()], witness);
            assert_eq!(
                !c.leftover_keys().is_empty(),
                sibling_reports || witness_reports,
                "{evidence:?} + {witness:?}"
            );
            assert!(
                !c.is_proven(),
                "{evidence:?} + {witness:?}: the proof record never moves"
            );
        }
    }
}

#[skuld::test]
fn a_sweep_with_no_boot_time_key_reports_nothing_however_loudly_both_sources_speak() {
    // The report is about unproven KEYS, not about covers or records. A sweep
    // list carrying no boot-time key — macOS's shape — has nothing to name
    // whatever the evidence says about what this host once armed, and that is
    // what keeps `leftover_keys` a key report rather than a second presence
    // probe.
    let c = Clearance::from_observations(
        &[
            sibling(KeyOutcome::Removed),
            obs("lockdown filter", KeyLifetime::Persistent, KeyOutcome::Removed),
        ],
        ArmingWitness::Armed,
    );
    assert!(c.is_proven());
    assert!(c.leftover_keys().is_empty());
}

#[skuld::test]
fn corroboration_moves_only_toward_reporting() {
    // The uninstall gate folds in every peer `state_dir` it already locks,
    // because the record is per-dir while the filters it describes are
    // machine-wide. A peer that never armed a twin must not retract one that
    // did — a union over hosts is only sound in the cautious direction.
    let armed = Clearance::from_observations(&[sibling(KeyOutcome::NotFound), unproven_twin()], ArmingWitness::Armed);
    for peer in [
        ArmingWitness::Unset,
        ArmingWitness::Disarmed,
        ArmingWitness::Armed,
        ArmingWitness::Unreadable,
    ] {
        assert_eq!(
            armed.clone().corroborate(peer).leftover_keys(),
            ["lockdown boot-time block-all V4"],
            "{peer:?} must not retract an armed record"
        );
    }

    let quiet = Clearance::from_observations(&[sibling(KeyOutcome::NotFound), unproven_twin()], ArmingWitness::Unset);
    assert!(quiet
        .clone()
        .corroborate(ArmingWitness::Unset)
        .leftover_keys()
        .is_empty());
    assert_eq!(
        quiet.corroborate(ArmingWitness::Armed).leftover_keys(),
        ["lockdown boot-time block-all V4"],
        "a peer's record is what an elevated non-service bridge's twin is recorded in"
    );
}

#[skuld::test]
fn every_sighting_and_sibling_pair_has_one_write_answer() {
    // What a sweep tells the record, as distinct from what it tells the
    // operator. Three load-bearing properties. First: an unproven twin on a
    // host whose siblings all answered empty writes NOTHING — `Arm` there
    // would manufacture a report out of a host that never armed anything, and
    // a retraction would re-create the consumed-witness defect one level down.
    // Second: `Disarm` is reachable ONLY from a sweep that watched every
    // boot-time key it touched go, which is the one observation
    // bindreams/hole#1043's assumption makes conclusive — and it does not
    // consult the sibling at all, because a watched removal is evidence about
    // the twin itself and needs no corroboration. Third: the MIXED row still
    // arms — one twin watched going says nothing about the other that answered
    // empty.
    use crate::routing::failclosed::boottime_witness::WitnessUpdate;
    let removed_twin = obs(
        "lockdown boot-time block-all V4",
        KeyLifetime::BootTime,
        KeyOutcome::Removed,
    );
    let table = [
        (vec![sibling(KeyOutcome::Removed)], WitnessUpdate::Leave),
        (vec![sibling(KeyOutcome::NotFound)], WitnessUpdate::Leave),
        (vec![], WitnessUpdate::Leave),
        (vec![sibling(KeyOutcome::Removed), unproven_twin()], WitnessUpdate::Arm),
        (vec![unproven_twin()], WitnessUpdate::Arm),
        (vec![sibling(KeyOutcome::Failed), unproven_twin()], WitnessUpdate::Arm),
        (
            vec![sibling(KeyOutcome::NotFound), unproven_twin()],
            WitnessUpdate::Leave,
        ),
        (vec![sibling(KeyOutcome::Removed), removed_twin], WitnessUpdate::Disarm),
        (vec![sibling(KeyOutcome::NotFound), removed_twin], WitnessUpdate::Disarm),
        (vec![sibling(KeyOutcome::Failed), removed_twin], WitnessUpdate::Disarm),
        (vec![removed_twin], WitnessUpdate::Disarm),
        (
            vec![
                obs("twin A", KeyLifetime::BootTime, KeyOutcome::Removed),
                obs("twin B", KeyLifetime::BootTime, KeyOutcome::NotFound),
                sibling(KeyOutcome::Removed),
            ],
            WitnessUpdate::Arm,
        ),
        (
            vec![
                obs("twin A", KeyLifetime::BootTime, KeyOutcome::Removed),
                obs("twin B", KeyLifetime::BootTime, KeyOutcome::Failed),
                sibling(KeyOutcome::Removed),
            ],
            WitnessUpdate::Arm,
        ),
        // The SAME two mixed sweeps with the unproven twin FIRST. The fold
        // accumulates ("any twin unproven"), and a last-observation-wins fold
        // would read these two as `AllProven` and DISARM over a twin nothing
        // measured — the false silence the whole record exists to exclude. The
        // V4/V6 pair is delete-ordered, so which half answers first is not
        // something a test may assume.
        (
            vec![
                obs("twin A", KeyLifetime::BootTime, KeyOutcome::NotFound),
                obs("twin B", KeyLifetime::BootTime, KeyOutcome::Removed),
                sibling(KeyOutcome::Removed),
            ],
            WitnessUpdate::Arm,
        ),
        (
            vec![
                obs("twin A", KeyLifetime::BootTime, KeyOutcome::Failed),
                obs("twin B", KeyLifetime::BootTime, KeyOutcome::Removed),
                sibling(KeyOutcome::Removed),
            ],
            WitnessUpdate::Arm,
        ),
    ];
    for (observations, want) in table {
        assert_eq!(
            fold(&observations).witness_update(),
            want,
            "{:?}",
            observations.iter().map(|o| (o.key, o.outcome)).collect::<Vec<_>>()
        );
    }
}
