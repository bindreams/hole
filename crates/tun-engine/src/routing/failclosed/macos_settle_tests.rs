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

/// The warning for a token that will not drop says what that costs, and what it costs depends on the restore: with
/// the host's rules restored the refcount blocks nothing, with a failed restore the block is still loaded.
#[skuld::test]
fn the_warning_for_a_token_that_will_not_drop_follows_whether_the_restore_held() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let warning = |restore_ok: bool| {
        let writer = garter::test_utils::WaitableWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        {
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
            let mut ops = RecordingPfOps {
                fail_reload_default: !restore_ok,
                fail_drop_token: true,
                ..Default::default()
            };
            let _ = release_all_with(StateFile::Present(transient_state()), StateFile::Absent, &mut ops);
        }
        writer.snapshot()
    };

    let held = warning(true);
    assert!(held.contains("blocks nothing"), "{held}");
    let failed = warning(false);
    assert!(failed.contains("pfctl -X failed releasing"), "{failed}");
    assert!(
        !failed.contains("blocks nothing"),
        "the block is still loaded: {failed}"
    );
    assert!(failed.contains("are not restored"), "{failed}");
}

/// The record is the release's last step. A write that fails after a restore that held leaves a record over a host
/// that is open, so the answer is that cover's error, not a success.
#[skuld::test]
fn a_clear_that_errors_after_a_good_restore_is_the_covers_error() {
    for (name, transient, standing) in [("transient", true, false), ("standing", false, true)] {
        let mut ops = RecordingPfOps {
            fail_clear_transient: transient,
            fail_clear_standing: standing,
            ..Default::default()
        };

        let result = release_all_with(
            StateFile::Present(transient_state()),
            StateFile::Present(standing_state()),
            &mut ops,
        )
        .into_result();

        let error = result.expect_err(name).to_string();
        assert!(error.contains(&format!("mock clear_{name} failure")), "{name}: {error}");
        assert_eq!(
            ops.log.last(),
            Some(&"clear_standing"),
            "{name}: the other cover is still attempted"
        );
    }
}

/// The clear's error reaches a toast, so it names the io kind and never a path.
#[skuld::test]
fn a_clear_that_cannot_write_tells_the_caller_its_kind_and_no_path() {
    let tmp = tempfile::tempdir().unwrap();
    let state = util::dir::testing::state_dir_linked_to_a_system_folder(tmp.path());
    let kind = match pf_record::clear_if_token::<state::FailClosedState>(&state, Some("1")).unwrap_err() {
        util::versioned_file::StoreError::Io(e) => e.kind(),
        other => panic!("expected an I/O refusal, got {other:?}"),
    };
    let mut ops = RealPfOps { state_dir: &state };

    let transient = ops.clear_transient(Some("1")).unwrap_err().to_string();
    let standing = ops.clear_standing(Some("1")).unwrap_err().to_string();

    assert_eq!(
        transient,
        format!("route setup failed: failclosed-state could not be written ({kind})")
    );
    assert_eq!(
        standing,
        format!("route setup failed: lockdown-pf-state could not be written ({kind})")
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

    disengage_with(Ok(Some("111")), false, &mut ops);

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

    disengage_with(Ok(Some("111")), false, &mut ops);

    assert_eq!(
        ops.log,
        vec!["reload_default"],
        "the record is the only evidence of the block, and its token goes with it"
    );
}

#[skuld::test]
fn an_adopting_disengage_skips_the_restore_but_still_drops_and_clears() {
    let mut ops = RecordingPfOps::default();

    disengage_with(Ok(Some("111")), true, &mut ops);

    assert_eq!(ops.log, vec!["drop_token", "clear_transient"]);
}

#[skuld::test]
fn a_disengage_with_no_token_on_record_drops_nothing() {
    let mut ops = RecordingPfOps::default();

    disengage_with(Ok(None), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "clear_transient"]);
    assert_eq!(ops.cleared, vec![None]);
}

#[skuld::test]
fn a_disengage_whose_token_will_not_drop_still_clears_its_record() {
    let mut ops = RecordingPfOps {
        fail_drop_token: true,
        ..Default::default()
    };

    disengage_with(Ok(Some("111")), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "drop_token", "clear_transient"]);
}

// disengage_lockdown_with =============================================================================================

#[skuld::test]
fn a_lockdown_disengage_drops_before_it_clears_by_the_token_it_dropped() {
    let mut ops = RecordingPfOps::default();

    disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops).unwrap();

    assert_eq!(ops.log, vec!["load_ruleset", "drop_token", "clear_standing"]);
    assert_eq!(ops.cleared, vec![Some("222".to_owned())]);
}

/// A refcount pf will not drop blocks nothing, so it is for the log and never the release's error: reporting it would
/// fail the attempt that let the user out.
#[skuld::test]
fn a_lockdown_disengage_whose_token_will_not_drop_is_still_a_clean_release() {
    let mut ops = RecordingPfOps {
        fail_drop_token: true,
        ..Default::default()
    };

    let result = disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops);

    assert!(result.is_ok(), "{result:?}");
    assert_eq!(ops.log, vec!["load_ruleset", "drop_token", "clear_standing"]);
}

/// The same write failure as `release_all`'s: a record left over a restored host is the error, after the token went.
#[skuld::test]
fn a_lockdown_disengage_whose_record_cannot_be_cleared_is_an_error() {
    let mut ops = RecordingPfOps {
        fail_clear_standing: true,
        ..Default::default()
    };

    let result = disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops);

    assert!(result.unwrap_err().to_string().contains("mock clear_standing failure"));
    assert_eq!(ops.log, vec!["load_ruleset", "drop_token", "clear_standing"]);
}

/// The retry of a failed restore meets a token the first attempt already dropped: its `-X` fails and the release
/// still succeeds, once, with the record gone.
#[skuld::test]
fn the_retry_of_a_failed_lockdown_disengage_succeeds_over_the_token_it_already_dropped() {
    let mut first = RecordingPfOps {
        fail_load_ruleset: true,
        ..Default::default()
    };
    let failed = disengage_lockdown_with(
        CoverPresence::Recorded,
        StateFile::Present(standing_state()),
        &mut first,
    );
    assert!(failed.is_err());
    assert_eq!(
        first.cleared,
        Vec::<Option<String>>::new(),
        "the record waits for the retry"
    );

    let mut retry = RecordingPfOps {
        fail_drop_token: true,
        ..Default::default()
    };
    let retried = disengage_lockdown_with(
        CoverPresence::Recorded,
        StateFile::Present(standing_state()),
        &mut retry,
    );

    assert!(retried.is_ok(), "{retried:?}");
    assert_eq!(retry.cleared, vec![Some("222".to_owned())]);
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

/// The callers that release a cover, over one record, from every outcome of the restore and of `pfctl -X`. The record
/// is cleared exactly when the restore held, and a failed drop changes nothing. The token is dropped after a good
/// restore by all of them; after a failed one by the escapes only, since a failed restore must not keep pf enabled over
/// the host, while `recover_cover` and the transient guard keep it with the record for the next sweep.
#[skuld::test]
fn a_release_clears_its_record_by_its_restore_alone_and_drops_the_token_by_its_callers_rule() {
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
            let mut recover = double();
            recover_cover_with(StateFile::Present(recorded_cover("111")), false, &mut recover);
            let mut guard = double();
            disengage_with(Ok(Some("111")), false, &mut guard);

            for (caller, ops, token, drops_after_a_failed_restore) in [
                ("release_all", &release, "222", true),
                ("disengage_lockdown", &disengage, "222", true),
                ("recover_cover", &recover, "111", false),
                ("transient guard", &guard, "111", false),
            ] {
                let dropped = if restore_ok || drops_after_a_failed_restore {
                    vec![token.to_owned()]
                } else {
                    vec![]
                };
                assert_eq!(ops.dropped, dropped, "{caller}, {case}");
                let cleared = if restore_ok {
                    vec![Some(token.to_owned())]
                } else {
                    vec![]
                };
                assert_eq!(ops.cleared, cleared, "{caller}, {case}");
            }
            assert_eq!(released.is_ok(), restore_ok, "release_all, {case}");
            assert_eq!(disengaged.is_ok(), restore_ok, "disengage_lockdown, {case}");
        }
    }
}

// engage_with: the token a record write displaced =====================================================================

/// A release whose restore failed left its record; the engage that overwrites it took the only record that names the
/// token.
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
    let mut ops = RecordingPfOps::default();

    recover_cover_with(unreadable(), false, &mut ops);

    assert_eq!(
        ops.log,
        vec!["reload_default"],
        "restored; no token to drop, no record to clear"
    );
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
    assert!(
        ops.cleared.is_empty(),
        "an unread record is never cleared: {:?}",
        ops.cleared
    );
}

/// A record naming a token pf no longer holds (a reboot reset it) fails `pfctl -X` on every sweep. The sweep clears the
/// record all the same, or it would meet the same failure on every start.
#[skuld::test]
fn a_sweep_clears_a_transient_record_naming_a_token_pf_no_longer_holds() {
    let mut ops = RecordingPfOps {
        fail_drop_token: true,
        ..Default::default()
    };

    recover_cover_with(StateFile::Present(recorded_cover("111")), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "drop_token", "clear_transient"]);
}
