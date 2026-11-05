use super::*;
use util::versioned_file::UnreadableKind;

#[skuld::test]
fn set_then_load_roundtrips() {
    let tmp = tempfile::tempdir().unwrap();
    set_enabled(tmp.path(), true, None).unwrap();
    assert_eq!(load(tmp.path()), Some(LockdownState { enabled: true }));
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
    write_raw(tmp.path(), br#"{"version":2,"enabled":true}"#);
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

/// Write `bytes` verbatim as the intent file, bypassing the serializer.
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
    write_raw(tmp.path(), br#"{"version":1,"enabled":"yes"}"#);
    assert_eq!(
        load_intent(tmp.path()),
        Intent::Unreadable,
        "a field of the wrong type is a parse failure, not an off intent"
    );
}

#[skuld::test]
fn load_intent_future_schema_is_unreadable() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), br#"{"version":2,"enabled":true}"#);
    assert_eq!(load_intent(tmp.path()), Intent::Unreadable);
}

#[skuld::test]
fn a_stray_field_does_not_make_the_intent_unreadable() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), br#"{"version":1,"enabled":true,"stray":1}"#);
    assert_eq!(load_intent(tmp.path()), Intent::On);
}

#[skuld::test]
fn every_unreadable_intent_classifies_as_unreadable() {
    // Newer, corrupt, obsolete (version 0 is at the chain's floor) and a read that fails (a directory at the name).
    for (what, plant) in [
        (
            "newer",
            Box::new(|dir: &Path| write_raw(dir, br#"{"version":2,"enabled":true}"#)) as Box<dyn Fn(&Path)>,
        ),
        ("corrupt", Box::new(|dir: &Path| write_raw(dir, b"{not json"))),
        (
            "obsolete",
            Box::new(|dir: &Path| write_raw(dir, br#"{"version":0,"enabled":true}"#)),
        ),
        (
            "a failed read",
            Box::new(|dir: &Path| std::fs::create_dir(dir.join(STATE_FILE_NAME)).unwrap()),
        ),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        plant(tmp.path());
        assert_eq!(load_intent(tmp.path()), Intent::Unreadable, "{what}");
    }
}

#[skuld::test]
fn set_enabled_over_a_corrupt_intent_backs_it_up() {
    let tmp = tempfile::tempdir().unwrap();
    write_raw(tmp.path(), b"{not json");

    set_enabled(tmp.path(), true, None).unwrap();

    assert_eq!(load_intent(tmp.path()), Intent::On);
    let backup = tmp.path().join(format!("{STATE_FILE_NAME}.unreadable.bak"));
    assert_eq!(std::fs::read(backup).unwrap(), b"{not json");
}

#[skuld::test]
fn set_enabled_over_a_newer_intent_backs_it_up() {
    let tmp = tempfile::tempdir().unwrap();
    let newer: &[u8] = br#"{"version":2,"enabled":false}"#;
    write_raw(tmp.path(), newer);

    set_enabled(tmp.path(), true, None).unwrap();

    assert_eq!(load_intent(tmp.path()), Intent::On);
    let backup = tmp.path().join(format!("{STATE_FILE_NAME}.unreadable.bak"));
    assert_eq!(std::fs::read(backup).unwrap(), newer);
}

#[skuld::test]
fn a_directory_at_the_name_is_an_unreadable_intent_of_kind_not_a_file() {
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join(STATE_FILE_NAME)).unwrap();
    let Loaded::Unreadable { kind, .. } = file(tmp.path()).observe().loaded else {
        panic!("a directory at the name must not read");
    };
    assert_eq!(kind, UnreadableKind::NotAFile);
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

// promote_unrecorded --------------------------------------------------------------------------------------------------

/// Each intent the promotion can meet, planted as bytes, with whether it must write and what the file reads as
/// afterwards. Only an absent file is promoted: a recorded `On` or `Off` is a decision, and a file this release cannot
/// read may hold one (a newer or obsolete `enabled: false` is a user's `Off`).
#[skuld::test]
fn update_decides_on_the_classified_intent_and_writes_only_some() {
    let cases: [(&str, Option<&[u8]>, bool, Intent); 6] = [
        ("unset", None, true, Intent::On),
        ("on", Some(br#"{"version":1,"enabled":true}"#), false, Intent::On),
        ("off", Some(br#"{"version":1,"enabled":false}"#), false, Intent::Off),
        ("corrupt", Some(b"{not json"), false, Intent::Unreadable),
        (
            "newer",
            Some(br#"{"version":2,"enabled":false}"#),
            false,
            Intent::Unreadable,
        ),
        (
            "obsolete",
            Some(br#"{"version":0,"enabled":false}"#),
            false,
            Intent::Unreadable,
        ),
    ];
    for (what, planted, wrote, after) in cases {
        let tmp = tempfile::tempdir().unwrap();
        if let Some(bytes) = planted {
            write_raw(tmp.path(), bytes);
        }

        assert_eq!(promote_unrecorded(tmp.path(), None).unwrap(), wrote, "{what}");

        assert_eq!(load_intent(tmp.path()), after, "{what}");
        if !wrote {
            let kept = std::fs::read(tmp.path().join(STATE_FILE_NAME)).unwrap();
            assert_eq!(
                Some(kept.as_slice()),
                planted,
                "{what}: a recorded intent is not rewritten"
            );
        }
    }
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
fn promote_writes_over_unset_only() {
    let unset = tempfile::tempdir().unwrap();
    assert!(promote_unrecorded(unset.path(), None).unwrap());
    assert_eq!(load_intent(unset.path()), Intent::On);
}

#[skuld::test]
fn promote_over_a_read_that_fails_declines_and_leaves_the_name_alone() {
    // A directory at the name: the read fails with something other than "not found", so the intent is unknown, not
    // unset. Declining is `Ok(false)`, not a refusal, and nothing is written or backed up.
    let tmp = tempfile::tempdir().unwrap();
    std::fs::create_dir(tmp.path().join(STATE_FILE_NAME)).unwrap();

    assert!(!promote_unrecorded(tmp.path(), None).unwrap());

    assert!(tmp.path().join(STATE_FILE_NAME).is_dir());
    assert_eq!(
        std::fs::read_dir(tmp.path()).unwrap().count(),
        1,
        "nothing was written beside it"
    );
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
    assert!(!Intent::Unreadable.admits_adoption_promotion());
    assert!(!Intent::On.admits_adoption_promotion());
    assert!(!Intent::Off.admits_adoption_promotion());
}
