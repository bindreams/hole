//! The order a pf cover is released and engaged in, as whole operations over the `PfOps` and `EngageOps` doubles: a
//! restore, then the token's drop, then the record's clear; and a token dropped for the record an engage replaced.
//! A child of `macos_tests`, which owns the doubles. The cover lock makes each of these a sequence, so each test is
//! one order of one operation.

use super::*;

// release_all_with ====================================================================================================

#[skuld::test]
fn a_release_restores_then_drops_then_clears_each_cover_by_its_token() {
    let mut ops = RecordingPfOps::default();

    let result = release_all_with(
        StateFile::Present(transient_state()),
        StateFile::Present(standing_state()),
        &mut ops,
    )
    .into_result();

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(
        ops.log,
        vec![
            "reload_default",
            "drop_token",
            "clear_transient",
            "load_ruleset",
            "drop_token",
            "clear_standing"
        ]
    );
    assert_eq!(ops.dropped, vec!["111".to_owned(), "222".to_owned()]);
    assert_eq!(ops.cleared, vec![Some("111".to_owned()), Some("222".to_owned())]);
}

/// A release is the escape: a record naming a token pf will not drop (one it no longer holds fails `-X` on every retry)
/// must still go, or the next release meets the same failure. The refcount leak is warned, not reported.
#[skuld::test]
fn a_token_that_will_not_drop_is_warned_and_its_record_still_clears() {
    let mut ops = RecordingPfOps {
        fail_drop_token: true,
        ..Default::default()
    };

    let result = release_all_with(
        StateFile::Present(transient_state()),
        StateFile::Present(standing_state()),
        &mut ops,
    )
    .into_result();

    assert!(result.is_ok(), "the host is restored: {result:?}");
    assert_eq!(ops.dropped, vec!["111".to_owned(), "222".to_owned()]);
    assert_eq!(ops.cleared, vec![Some("111".to_owned()), Some("222".to_owned())]);
}

/// The escape lets the host out of pf whatever the restore did, so the token goes; the record stays, because it is the
/// only evidence of the block the restore failed to lift. The retry drops a dead token, fails, and clears anyway.
#[skuld::test]
fn a_failed_restore_still_drops_the_token_and_keeps_the_record() {
    let mut ops = RecordingPfOps {
        fail_reload_default: true,
        fail_load_ruleset: true,
        ..Default::default()
    };

    let result = release_all_with(
        StateFile::Present(transient_state()),
        StateFile::Present(standing_state()),
        &mut ops,
    )
    .into_result();

    assert!(result.is_err());
    assert_eq!(ops.dropped, vec!["111".to_owned(), "222".to_owned()]);
    assert!(
        !ops.log.contains(&"clear_transient") && !ops.log.contains(&"clear_standing"),
        "{:?}",
        ops.log
    );
}

#[skuld::test]
fn a_clear_that_errors_after_the_drop_is_logged_and_the_release_still_reports_ok() {
    let mut ops = RecordingPfOps {
        fail_clear_transient: true,
        fail_clear_standing: true,
        ..Default::default()
    };

    let result = release_all_with(
        StateFile::Present(transient_state()),
        StateFile::Present(standing_state()),
        &mut ops,
    )
    .into_result();

    assert!(result.is_ok(), "the clear is bookkeeping: {result:?}");
    assert_eq!(
        ops.dropped,
        vec!["111".to_owned(), "222".to_owned()],
        "the tokens were dropped before the clears that failed"
    );
}

/// A record that could not be read is left in place, so the release did not finish: a false success is the one wrong
/// answer. The clear comes after the drop, so the drop has happened by the time `Kept` arrives.
#[skuld::test]
fn a_cover_record_that_could_not_be_read_is_an_error_not_a_success() {
    let mut ops = RecordingPfOps {
        cleared_as: Some(Cleared::Kept),
        ..Default::default()
    };

    let result = release_all_with(
        StateFile::Present(transient_state()),
        StateFile::Present(standing_state()),
        &mut ops,
    )
    .into_result();

    assert!(result.is_err(), "a record still stands over a host that may be blocked");
    assert!(
        ops.log.contains(&"load_ruleset"),
        "the standing cover is still attempted after the transient one: {:?}",
        ops.log
    );
    assert_eq!(ops.dropped, vec!["111".to_owned(), "222".to_owned()]);
}

/// An unreadable record names no token to drop, but the host is restored all the same: it is a cover to clear. The
/// record stays and the release says so, whatever a later read of it finds: a clear keyed to "no token" over a record
/// that has become readable would report a record that names a held token as gone.
#[skuld::test]
fn a_release_over_records_that_could_not_be_read_restores_the_host_and_reports_them() {
    let mut ops = RecordingPfOps::default();

    let result = release_all_with(unreadable(), unreadable(), &mut ops).into_result();

    assert!(result.is_err());
    assert_eq!(ops.log, vec!["reload_default", "reload_default"]);
}

// disengage_with ======================================================================================================

#[skuld::test]
fn a_disengage_restores_then_drops_then_clears() {
    let mut ops = RecordingPfOps::default();

    disengage_with(Some("111"), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "drop_token", "clear_transient"]);
    assert_eq!(ops.cleared, vec![Some("111".to_owned())]);
    assert_eq!(ops.dropped, vec!["111".to_owned()]);
}

#[skuld::test]
fn a_disengage_whose_restore_fails_drops_nothing_and_clears_nothing() {
    let mut ops = RecordingPfOps {
        fail_reload_default: true,
        ..Default::default()
    };

    disengage_with(Some("111"), false, &mut ops);

    assert_eq!(
        ops.log,
        vec!["reload_default"],
        "the record is the only evidence of the block, and its token goes with it"
    );
}

#[skuld::test]
fn an_adopting_disengage_skips_the_restore_but_still_drops_and_clears() {
    let mut ops = RecordingPfOps::default();

    disengage_with(Some("111"), true, &mut ops);

    assert_eq!(ops.log, vec!["drop_token", "clear_transient"]);
}

#[skuld::test]
fn a_disengage_with_no_token_on_record_drops_nothing() {
    let mut ops = RecordingPfOps::default();

    disengage_with(None, false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "clear_transient"]);
    assert_eq!(ops.cleared, vec![None]);
}

#[skuld::test]
fn a_disengage_whose_token_will_not_drop_keeps_its_record() {
    let mut ops = RecordingPfOps {
        fail_drop_token: true,
        ..Default::default()
    };

    disengage_with(Some("111"), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "drop_token"]);
}

// disengage_lockdown_with =============================================================================================

#[skuld::test]
fn a_lockdown_disengage_drops_before_it_clears_by_the_token_it_dropped() {
    let mut ops = RecordingPfOps::default();

    disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops).unwrap();

    assert_eq!(ops.log, vec!["load_ruleset", "drop_token", "clear_standing"]);
    assert_eq!(ops.cleared, vec![Some("222".to_owned())]);
}

/// Fail-loud, unlike `release_all_with`: a caller who asked to be let out is told the refcount could not be released,
/// once. The record goes with that answer, so the retry finds nothing to release instead of the same failure.
#[skuld::test]
fn a_lockdown_disengage_that_cannot_drop_its_token_says_so_and_clears_the_record() {
    let mut ops = RecordingPfOps {
        fail_drop_token: true,
        ..Default::default()
    };

    let result = disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops);

    assert!(result.unwrap_err().to_string().contains("mock drop_token failure"));
    assert_eq!(ops.log, vec!["load_ruleset", "drop_token", "clear_standing"]);
}

/// An entry that could not be read is not the "no token" case: a clear keyed to "no token" that re-reads the record as
/// a live one would call it not ours and report success, with its token held and the record kept.
#[skuld::test]
fn a_lockdown_disengage_over_a_record_it_cannot_read_restores_the_host_and_reports_it() {
    let mut ops = RecordingPfOps::default();

    let result = disengage_lockdown_with(CoverPresence::Recorded, unreadable(), &mut ops);

    assert!(result.is_err(), "{result:?}");
    assert_eq!(ops.log, vec!["reload_default"]);
}

/// The two escapes over one record, from every outcome of the restore and of `pfctl -X`: the token is dropped whatever
/// the restore did, and the record is cleared exactly when the restore held. A failed drop is `release_all`'s warning
/// and `disengage_lockdown`'s one error.
#[skuld::test]
fn an_escape_drops_the_token_whatever_the_restore_did_and_clears_only_after_a_good_restore() {
    for restore_ok in [true, false] {
        for drop_ok in [true, false] {
            let double = || RecordingPfOps {
                fail_load_ruleset: !restore_ok,
                fail_reload_default: !restore_ok,
                fail_drop_token: !drop_ok,
                ..Default::default()
            };
            let case = format!("restore ok: {restore_ok}, drop ok: {drop_ok}");

            let mut release = double();
            let released = release_all_with(
                StateFile::<state::FailClosedState>::Absent,
                StateFile::Present(standing_state()),
                &mut release,
            )
            .into_result();
            let mut disengage = double();
            let disengaged = disengage_lockdown_with(
                CoverPresence::Recorded,
                StateFile::Present(standing_state()),
                &mut disengage,
            );

            for (escape, ops) in [("release_all", &release), ("disengage_lockdown", &disengage)] {
                assert_eq!(ops.dropped, vec!["222".to_owned()], "{escape}, {case}");
                let cleared = if restore_ok {
                    vec![Some("222".to_owned())]
                } else {
                    vec![]
                };
                assert_eq!(ops.cleared, cleared, "{escape}, {case}");
            }
            assert_eq!(released.is_ok(), restore_ok, "release_all, {case}");
            assert_eq!(disengaged.is_ok(), restore_ok && drop_ok, "disengage_lockdown, {case}");
        }
    }
}

// engage_with: the token a record write displaced =====================================================================

/// A release whose `pfctl -X` failed left its record; the engage that overwrites it took the only record that names
/// the token.
#[skuld::test]
fn an_engage_drops_the_token_its_record_replaced() {
    let mut ops = RecordingEngageOps {
        displaced: Some("old".into()),
        ..recording_engage_ops()
    };

    engage_with(v4(), None, &mut ops).unwrap();

    assert_eq!(ops.dropped, vec!["old".to_owned()]);
    let at = |call: &str| ops.log.iter().position(|c| *c == call).unwrap();
    assert!(at("save_transient") < at("drop_token") && at("drop_token") < at("load_ruleset"));
}

#[skuld::test]
fn an_engage_that_replaced_a_record_naming_its_own_token_drops_nothing() {
    let mut ops = RecordingEngageOps {
        displaced: Some("424242".into()),
        ..recording_engage_ops()
    };

    engage_with(v4(), None, &mut ops).unwrap();

    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
}

#[skuld::test]
fn an_engage_whose_displaced_token_will_not_drop_still_engages() {
    let mut ops = RecordingEngageOps {
        displaced: Some("old".into()),
        fail_drop_token: true,
        ..recording_engage_ops()
    };

    let result = engage_with(v4(), None, &mut ops);

    assert_eq!(result.unwrap(), "424242");
    assert!(ops.log.contains(&"load_ruleset"), "{:?}", ops.log);
}

/// The write that failed replaced nothing, so the old record's token is still its to drop.
#[skuld::test]
fn an_engage_whose_save_fails_drops_only_its_own_token() {
    let mut ops = RecordingEngageOps {
        displaced: Some("old".into()),
        fail_save_transient: true,
        ..recording_engage_ops()
    };

    assert!(engage_with(v4(), None, &mut ops).is_err());

    assert_eq!(ops.dropped, vec!["424242".to_owned()]);
}

#[skuld::test]
fn only_a_token_other_than_the_new_one_is_dropped_for_a_replaced_record() {
    let drops = |displaced: Option<&str>, new: &str| {
        let mut dropped = Vec::new();
        drop_displaced(displaced, new, |old| {
            dropped.push(old.to_owned());
            Ok(())
        });
        dropped
    };

    assert_eq!(drops(None, "7"), Vec::<String>::new());
    assert_eq!(drops(Some("7"), "7"), Vec::<String>::new());
    assert_eq!(drops(Some("6"), "7"), vec!["6".to_owned()]);
}

/// The standing engage's record write returns the same displaced token: a live record, a newer one with its token
/// salvaged, and nothing.
#[skuld::test]
fn a_baseline_persisted_over_a_record_names_the_token_it_replaced() {
    let cases: [(&str, Option<&str>, Option<&str>); 3] = [
        ("no record", None, None),
        (
            "a live record",
            Some(r#"{"version":1,"pf_token":"old","main_snapshot":"","nat_snapshot":""}"#),
            Some("old"),
        ),
        (
            "a newer record",
            Some(r#"{"version":2,"pf_token":"future","main_snapshot":"","nat_snapshot":""}"#),
            Some("future"),
        ),
    ];
    for (what, existing, expected) in cases {
        let tmp = tempfile::tempdir().unwrap();
        if let Some(existing) = existing {
            std::fs::write(tmp.path().join(lockdown_state::STATE_FILE_NAME), existing).unwrap();
        }

        let (_, displaced) = persist_baseline(
            "new",
            tmp.path(),
            None,
            CoverPresence::Absent,
            String::new(),
            String::new(),
        )
        .unwrap();

        assert_eq!(displaced.as_deref(), expected, "{what}");
    }
}

// recover_cover_with ==================================================================================================

#[skuld::test]
fn a_record_that_could_not_be_read_still_drives_a_restore_of_the_host() {
    let mut ops = RecordingRecoverOps::default();

    recover_cover_with(unreadable(), false, &mut ops);

    assert_eq!(ops.restores, vec![(None, false)]);
}
