//! What a cover release PROVED, as distinct from what it attempted.
//!
//! `#[cfg]`-free on purpose: the fold under test is the decision the uninstall
//! gate reads, and it must be falsifiable on every platform's lane rather than
//! only on the one where the filters it describes exist.

use super::*;

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
    assert!(Clearance::from_observations(&[]).is_proven());
    assert!(Clearance::proven().is_proven());
    assert!(Clearance::proven().unproven_keys().is_empty());
}

#[skuld::test]
fn a_persistent_key_that_answered_not_found_is_proven_empty() {
    // BFE's store is the only record of a PERSISTENT filter and a by-key
    // delete addresses it directly, so "not found" is proof the key carries
    // nothing. This is the case the old whitelist got right.
    let c = Clearance::from_observations(&[obs("lockdown filter", KeyLifetime::Persistent, KeyOutcome::NotFound)]);
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
    let c = Clearance::from_observations(&[obs(
        "lockdown boot-time block-all V4",
        KeyLifetime::BootTime,
        KeyOutcome::NotFound,
    )]);
    assert!(!c.is_proven(), "not-found on a boot-time key proves nothing");
    assert_eq!(c.unproven_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn a_boot_time_key_the_delete_actually_removed_is_proven_empty() {
    // The half #1010 measured: against a LIVE boot-time object the delete
    // returns ERROR_SUCCESS and the filter leaves the BOOTTIME_ONLY view.
    // A removal we watched happen is proof; only the empty answer is not.
    let c = Clearance::from_observations(&[obs(
        "lockdown boot-time block-all V4",
        KeyLifetime::BootTime,
        KeyOutcome::Removed,
    )]);
    assert!(c.is_proven());
    assert!(c.unproven_keys().is_empty());
}

#[skuld::test]
fn a_mixed_sweep_names_every_unproven_key_and_only_those() {
    // The operator message has to be actionable, and after this point the
    // label is all anyone has to look a key up by. A count would not survive
    // that requirement.
    let c = Clearance::from_observations(&[
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
        "only the boot-time keys that answered not-found are unproven"
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
        let c = Clearance::from_observations(&[o]);
        assert!(!c.is_proven(), "{lifetime:?}");
        assert_eq!(c.unproven_keys(), ["lockdown filter"]);
    }
}

#[skuld::test]
fn every_outcome_lifetime_pair_has_one_answer_and_only_removal_is_universal() {
    // The whole table, so the rule is readable in one place and a new variant
    // cannot be added without landing here. `Removed` is the only outcome that
    // proves anything on a boot-time key; `Failed` proves nothing anywhere.
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
    let c = Clearance::from_observations(&[
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
    let c = Clearance::from_observations(&[sibling(KeyOutcome::NotFound), unproven_twin()]);
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
    let c = Clearance::from_observations(&[sibling(KeyOutcome::Removed), unproven_twin()]);
    assert_eq!(c.leftover_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn a_sweep_carrying_no_sibling_at_all_reports_its_unproven_twins() {
    // The fold's dangerous default. "Every sibling answered empty" is
    // vacuously true of an empty set, so the natural reading would suppress
    // every report the moment a boot-time key outlived its sibling in some
    // future sweep list — silently, and in the direction that hurts.
    let c = Clearance::from_observations(&[unproven_twin()]);
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
    let c = Clearance::from_observations(&[sibling(KeyOutcome::Failed), unproven_twin()]);
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
    let c = Clearance::from_observations(&[
        sibling(KeyOutcome::NotFound),
        sibling(KeyOutcome::Removed),
        unproven_twin(),
    ]);
    assert_eq!(c.leftover_keys(), ["lockdown boot-time block-all V4"]);
}

#[skuld::test]
fn a_proven_sweep_reports_nothing_however_live_the_cover_was() {
    // An uninstall on the boot that engaged: the sibling AND the twin were
    // both removed and watched going. A cover was certainly installed, and
    // there is still nothing to report, because the report is about unproven
    // keys and not about covers.
    let c = Clearance::from_observations(&[
        sibling(KeyOutcome::Removed),
        obs(
            "lockdown boot-time block-all V4",
            KeyLifetime::BootTime,
            KeyOutcome::Removed,
        ),
    ]);
    assert!(c.is_proven());
    assert!(c.leftover_keys().is_empty());
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
        let c = Clearance::from_observations(&[sibling(outcome), unproven_twin()]);
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
