use super::*;

#[skuld::test]
fn save_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    let st = LockdownState {
        version: SCHEMA_VERSION,
        enabled: true,
    };
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), Some(st));
}

#[skuld::test]
fn load_absent_is_none_and_load_enabled_is_false() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(load(tmp.path()), None);
    assert!(!load_enabled(tmp.path()), "absent file => default-off");
}

#[skuld::test]
fn load_rejects_schema_mismatch() {
    let tmp = tempfile::tempdir().unwrap();
    let st = LockdownState {
        version: SCHEMA_VERSION + 1,
        enabled: true,
    };
    save(tmp.path(), &st, None).unwrap();
    assert_eq!(load(tmp.path()), None, "future schema must be discarded");
}

#[skuld::test]
fn set_enabled_is_last_writer_wins() {
    let tmp = tempfile::tempdir().unwrap();
    set_enabled(tmp.path(), true, None).unwrap();
    assert!(load_enabled(tmp.path()));
    set_enabled(tmp.path(), false, None).unwrap();
    assert!(!load_enabled(tmp.path()), "second writer wins");
}

// Intent ==============================================================================================================

/// Write `bytes` verbatim as the intent file, bypassing [`save`]'s serializer.
fn write_raw(dir: &Path, bytes: &[u8]) {
    std::fs::write(dir.join(STATE_FILE_NAME), bytes).unwrap();
}

#[skuld::test]
fn load_intent_absent_file_is_unset() {
    let tmp = tempfile::tempdir().unwrap();
    assert_eq!(
        load_intent(tmp.path()),
        Intent::Unset,
        "an absent file is an UNKNOWN intent, never a recorded off"
    );
}

#[skuld::test]
fn load_intent_reads_the_persisted_bool() {
    let tmp = tempfile::tempdir().unwrap();
    set_enabled(tmp.path(), true, None).unwrap();
    assert_eq!(load_intent(tmp.path()), Intent::On);
    set_enabled(tmp.path(), false, None).unwrap();
    assert_eq!(load_intent(tmp.path()), Intent::Off);
}

#[skuld::test]
fn load_intent_unparseable_file_is_unreadable() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), b"{not json");
    assert_eq!(load_intent(tmp.path()), Intent::Unreadable);
    write_raw(tmp.path(), br#"{"version":1,"enabled":true,"stray":1}"#);
    assert_eq!(
        load_intent(tmp.path()),
        Intent::Unreadable,
        "deny_unknown_fields is a parse failure, not an off intent"
    );
}

#[skuld::test]
fn load_intent_future_schema_is_unreadable() {
    let tmp = tempfile::tempdir().unwrap();
    save(
        tmp.path(),
        &LockdownState {
            version: SCHEMA_VERSION + 1,
            enabled: true,
        },
        None,
    )
    .unwrap();
    assert_eq!(load_intent(tmp.path()), Intent::Unreadable);
}

#[skuld::test]
fn intent_folds_disagree_only_on_unreadable() {
    // (intent, reads_armed, installs_standing_cover)
    let table = [
        (Intent::On, true, true),
        (Intent::Off, false, false),
        (Intent::Unset, false, false),
        (
            // The one disagreement, and the reason for two folds: an unreadable
            // record is not consent to disarm (so the tray keeps the escape),
            // yet it is not authority to skip the transient cover either (so a
            // covered start still blocks rather than leaks).
            Intent::Unreadable,
            true,
            false,
        ),
    ];
    for (intent, armed, standing) in table {
        assert_eq!(
            intent.reads_armed(),
            armed,
            "{intent:?}.reads_armed() must be {armed}: armed for the escape"
        );
        assert_eq!(
            intent.installs_standing_cover(),
            standing,
            "{intent:?}.installs_standing_cover() must be {standing}: standing only on an explicit on"
        );
    }
}

#[skuld::test]
fn load_enabled_is_the_reads_armed_fold() {
    let tmp = tempfile::tempdir().unwrap();
    assert!(!load_enabled(tmp.path()), "absent file => not armed");
    write_raw(tmp.path(), b"{not json");
    assert!(
        load_enabled(tmp.path()),
        "a corrupt file reads as ARMED — it is not consent to disarm"
    );
}

#[skuld::test]
fn clear_removes_file_and_tolerates_absence() {
    let tmp = tempfile::tempdir().unwrap();
    set_enabled(tmp.path(), true, None).unwrap();
    assert!(tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap();
    assert!(!tmp.path().join(STATE_FILE_NAME).exists());
    clear(tmp.path()).unwrap(); // second clear is a no-op
}

// update / promote_unrecorded -----------------------------------------------------------------------------------------

#[skuld::test]
fn update_holds_the_record_lock_while_deciding() {
    let tmp = tempfile::tempdir().unwrap();
    let mut held_inside = false;
    update(tmp.path(), None, |_| {
        held_inside = LOCK.try_acquire().is_none();
        None
    })
    .unwrap();
    assert!(
        held_inside,
        "the read, the decision and the write must be one critical section"
    );
    assert!(LOCK.try_acquire().is_some(), "the lock must be released on return");
}

#[skuld::test]
fn update_decides_on_the_classified_intent_and_writes_only_some() {
    let tmp = tempfile::tempdir().unwrap();
    let mut seen = Vec::new();
    assert_eq!(
        update(tmp.path(), None, |i| {
            seen.push(i);
            None
        })
        .unwrap(),
        None
    );
    assert_eq!(load_intent(tmp.path()), Intent::Unset, "None must not write");
    assert_eq!(
        update(tmp.path(), None, |i| {
            seen.push(i);
            Some(true)
        })
        .unwrap(),
        Some(true)
    );
    assert_eq!(load_intent(tmp.path()), Intent::On);
    update(tmp.path(), None, |i| {
        seen.push(i);
        Some(false)
    })
    .unwrap();
    assert_eq!(load_intent(tmp.path()), Intent::Off);
    assert_eq!(seen, [Intent::Unset, Intent::Unset, Intent::On]);
}

#[skuld::test]
fn promote_declines_over_a_recorded_off_and_on() {
    for (enabled, want) in [(false, Intent::Off), (true, Intent::On)] {
        let tmp = tempfile::tempdir().unwrap();
        set_enabled(tmp.path(), enabled, None).unwrap();
        assert!(!promote_unrecorded(tmp.path(), None).unwrap());
        assert_eq!(load_intent(tmp.path()), want, "a recorded value is never rewritten");
    }
}

#[skuld::test]
fn promote_writes_over_unset_and_unreadable() {
    let unset = tempfile::tempdir().unwrap();
    assert!(promote_unrecorded(unset.path(), None).unwrap());
    assert_eq!(load_intent(unset.path()), Intent::On);

    let unreadable = tempfile::tempdir().unwrap();
    write_raw(unreadable.path(), b"{not json");
    assert!(promote_unrecorded(unreadable.path(), None).unwrap());
    assert_eq!(load_intent(unreadable.path()), Intent::On);
}

#[skuld::test]
fn unblock_then_promote_leaves_off() {
    let tmp = tempfile::tempdir().unwrap();
    set_enabled(tmp.path(), false, None).unwrap();
    promote_unrecorded(tmp.path(), None).unwrap();
    assert_eq!(load_intent(tmp.path()), Intent::Off);
}

#[skuld::test]
fn promote_then_unblock_leaves_off() {
    let tmp = tempfile::tempdir().unwrap();
    promote_unrecorded(tmp.path(), None).unwrap();
    set_enabled(tmp.path(), false, None).unwrap();
    assert_eq!(load_intent(tmp.path()), Intent::Off);
}

#[skuld::test]
fn admits_adoption_promotion_is_exhaustive_per_variant() {
    assert!(Intent::Unset.admits_adoption_promotion());
    assert!(Intent::Unreadable.admits_adoption_promotion());
    assert!(!Intent::On.admits_adoption_promotion());
    assert!(!Intent::Off.admits_adoption_promotion());
}
