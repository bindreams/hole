//! What a cover release PROVED, as distinct from what it attempted.
//!
//! `#[cfg]`-free on purpose: the fold under test is the decision the uninstall
//! gate reads, and it must be falsifiable on every platform's lane rather than
//! only on the one where the filters it describes exist.

use super::*;

fn obs(key: &'static str, lifetime: KeyLifetime, outcome: KeyOutcome) -> KeyObservation {
    KeyObservation { key, lifetime, outcome }
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
    // The operator message has to be actionable — `netsh wfp` is what is left
    // after this point, and it needs to name which keys to look for. A count
    // would not survive that requirement.
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
