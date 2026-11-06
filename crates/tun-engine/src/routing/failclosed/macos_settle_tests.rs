//! The order a pf cover is released and engaged in, as whole operations over the `PfOps` and `EngageOps` doubles: a
//! restore, then the record's clear, then the token's drop (a failed restore touches neither); and a token dropped for
//! the record an engage replaced. A record names only a token Hole holds, so `pfctl -X` never runs while a record
//! names its token.
//! A child of `macos_tests`, which owns the doubles. The cover lock makes each of these a sequence, so each test is
//! one order of one operation.

use super::*;

// release_all_with ====================================================================================================

#[skuld::test]
fn a_release_restores_then_clears_then_drops_each_cover_by_its_token() {
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
            "clear_transient",
            "drop_token",
            "load_ruleset",
            "clear_standing",
            "drop_token"
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

/// A restore that failed leaves the cover in force: the record stays, the evidence of the block, and so does the token
/// it names. Nothing is forgotten and nothing is dropped, whichever caller releases.
#[skuld::test]
fn a_failed_restore_keeps_the_record_and_the_token() {
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
    assert_eq!(ops.log, vec!["reload_default", "load_ruleset", "reload_default"]);
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
    assert!(ops.cleared.is_empty(), "{:?}", ops.cleared);
}

/// A clear that found another token's record (an engage displaced this one, and dropped it) or none leaves a token
/// that is not Hole's to drop: pf may have handed its value to another app.
#[skuld::test]
fn a_clear_that_found_another_record_drops_nothing() {
    let mut ops = RecordingPfOps {
        cleared_as: Some(Cleared::Gone),
        ..Default::default()
    };

    disengage_with(Ok(Some("111")), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "clear_transient"]);
}

/// A token that will not drop is logged with what was being released, and is not the release's error.
#[skuld::test]
fn a_token_that_will_not_drop_is_logged_with_what_was_being_released() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

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
            fail_drop_token: true,
            ..Default::default()
        };
        let result = release_all_with(StateFile::Present(transient_state()), StateFile::Absent, &mut ops).into_result();
        assert!(result.is_ok(), "{result:?}");
    }

    let log = writer.snapshot();
    assert!(
        log.contains("pfctl -X failed releasing the transient failclosed-state pf refcount"),
        "{log}"
    );
}

/// The advice an escape adds to a failed restore, and where it ends: it names what fixes the restore that ran.
const FIX_PF_CONF: &str = "; the block is still in place. Fix /etc/pf.conf and unblock again, or run `sudo pfctl -d`";
const TURN_PF_OFF: &str = "; the block is still in place. Run `sudo pfctl -d` to turn pf off";

/// A restore that reloaded `/etc/pf.conf` and failed is the error the user reads: the restore's own words, then the
/// fix for `/etc/pf.conf`. Every escape path that reloads it says so, the standing cover's included.
#[skuld::test]
fn an_escape_whose_default_reload_failed_says_to_fix_pf_conf() {
    let standing_without_baseline = lockdown_state::LockdownPfState {
        main_snapshot_captured: false,
        ..standing_state()
    };
    for (name, transient, standing) in [
        (
            "release_all, transient",
            StateFile::Present(transient_state()),
            StateFile::Absent,
        ),
        (
            "release_all, standing without a baseline",
            StateFile::Absent,
            StateFile::Present(standing_without_baseline),
        ),
        (
            "release_all, standing unusable",
            StateFile::Absent,
            StateFile::Unusable { pf_token: None },
        ),
        (
            "release_all, standing unreadable",
            StateFile::Absent,
            StateFile::Unreadable,
        ),
    ] {
        let mut ops = RecordingPfOps {
            fail_reload_default: true,
            ..Default::default()
        };

        let text = release_all_with(transient, standing, &mut ops)
            .into_result()
            .expect_err("the restore failed")
            .to_string();

        assert!(text.contains("mock reload_default failure"), "{name}: {text}");
        assert!(text.ends_with(FIX_PF_CONF), "{name}: {text}");
    }
}

/// A standing cover whose snapshot and fallback both failed is repaired by `/etc/pf.conf`: the fallback is the last
/// restore that ran.
#[skuld::test]
fn a_standing_release_whose_snapshot_and_fallback_failed_says_to_fix_pf_conf() {
    let mut ops = RecordingPfOps {
        fail_load_ruleset: true,
        fail_reload_default: true,
        ..Default::default()
    };

    let text = release_all_with(StateFile::Absent, StateFile::Present(standing_state()), &mut ops)
        .into_result()
        .expect_err("both restores failed")
        .to_string();

    assert!(text.contains("mock load_ruleset failure"), "{text}");
    assert!(text.ends_with(FIX_PF_CONF), "{text}");
}

/// A lockdown disengage that loads the captured snapshot and fails is not repaired by `/etc/pf.conf`, so the advice
/// does not name it.
#[skuld::test]
fn a_lockdown_disengage_whose_snapshot_failed_does_not_send_the_user_to_pf_conf() {
    let mut ops = RecordingPfOps {
        fail_load_ruleset: true,
        ..Default::default()
    };

    let text = disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops)
        .expect_err("the snapshot did not load")
        .to_string();

    assert!(text.contains("mock load_ruleset failure"), "{text}");
    assert!(text.ends_with(TURN_PF_OFF), "{text}");
    assert!(!text.contains("/etc/pf.conf"), "{text}");
}

/// A lockdown disengage with no snapshot to load reloads `/etc/pf.conf`, and says to fix it.
#[skuld::test]
fn a_lockdown_disengage_whose_default_reload_failed_says_to_fix_pf_conf() {
    let mut ops = RecordingPfOps {
        fail_reload_default: true,
        ..Default::default()
    };

    let text = disengage_lockdown_with(CoverPresence::Live, StateFile::Absent, &mut ops)
        .expect_err("the reload failed")
        .to_string();

    assert!(text.contains("mock reload_default failure"), "{text}");
    assert!(text.ends_with(FIX_PF_CONF), "{text}");
}

/// The advice goes with a restore that failed and nothing else: a clear that fails after a good restore is its own
/// error.
#[skuld::test]
fn an_escape_whose_clear_failed_after_a_good_restore_carries_no_restore_advice() {
    let mut ops = RecordingPfOps {
        fail_clear_standing: true,
        ..Default::default()
    };

    let text = disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops)
        .expect_err("the clear failed")
        .to_string();

    assert!(text.contains("mock clear_standing failure"), "{text}");
    assert!(!text.contains("pfctl -d"), "{text}");
}

/// A release that is not an escape (the transient guard's `Drop`, `recover_cover`, the engage back-out) returns the
/// restore's error as it came: nobody reads advice there.
#[skuld::test]
fn a_release_returns_a_failed_restore_unchanged() {
    for kind in [CoverKind::Transient, CoverKind::Lockdown] {
        let mut ops = RecordingPfOps::default();
        let restore = Err(RoutingError::RouteSetup("the restore's own words".into()));

        let text = release(&mut ops, kind, Ok(Some("111")), restore)
            .expect_err("the restore failed")
            .to_string();

        assert_eq!(text, "route setup failed: the restore's own words", "{kind:?}");
    }
}

/// The advice is built from the error's redacted text, so a restore error that carries a path (the one variant that
/// does) does not put it in the user's text.
#[skuld::test]
fn the_advice_carries_no_path() {
    for source in [RestoreSource::DefaultRuleset, RestoreSource::CapturedSnapshot] {
        let named = RoutingError::StateUnreadable {
            path: PathBuf::from("/Users/someone/private/x.json"),
        };

        let text = source.advise(named).to_string();

        assert!(!text.contains("someone"), "{source:?}: {text}");
    }
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
        let expected = match name {
            "transient" => vec![
                "reload_default",
                "clear_transient",
                "load_ruleset",
                "clear_standing",
                "drop_token",
            ],
            _ => vec![
                "reload_default",
                "clear_transient",
                "drop_token",
                "load_ruleset",
                "clear_standing",
            ],
        };
        assert_eq!(
            ops.log, expected,
            "{name}: the cover whose record stands keeps its token, and the other is still attempted"
        );
    }
}

/// The clear's error reaches a toast, so it names the operation that failed and the io kind, never a path.
#[skuld::test]
fn a_clear_that_fails_tells_the_caller_which_operation_and_its_kind_and_no_path() {
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
        format!("route setup failed: failclosed-state could not be cleared ({kind})")
    );
    assert_eq!(
        standing,
        format!("route setup failed: lockdown-pf-state could not be cleared ({kind})")
    );
}

/// A record that could not be read is left in place, so the release did not finish: a false success is the one wrong
/// answer. It still stands, so it may name the token, which is therefore not dropped.
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
    assert!(ops.dropped.is_empty(), "{:?}", ops.dropped);
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
fn a_disengage_restores_then_clears_then_drops() {
    let mut ops = RecordingPfOps::default();

    disengage_with(Ok(Some("111")), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "clear_transient", "drop_token"]);
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
fn an_adopting_disengage_skips_the_restore_but_still_clears_and_drops() {
    let mut ops = RecordingPfOps::default();

    disengage_with(Ok(Some("111")), true, &mut ops);

    assert_eq!(ops.log, vec!["clear_transient", "drop_token"]);
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

    assert_eq!(ops.log, vec!["reload_default", "clear_transient", "drop_token"]);
}

// disengage_lockdown_with =============================================================================================

#[skuld::test]
fn a_lockdown_disengage_clears_by_the_token_and_then_drops_it() {
    let mut ops = RecordingPfOps::default();

    disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops).unwrap();

    assert_eq!(ops.log, vec!["load_ruleset", "clear_standing", "drop_token"]);
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
    assert_eq!(ops.log, vec!["load_ruleset", "clear_standing", "drop_token"]);
}

/// The same write failure as `release_all`'s: a record left over a restored host is the error, and the token it names
/// is kept with it.
#[skuld::test]
fn a_lockdown_disengage_whose_record_cannot_be_cleared_is_an_error() {
    let mut ops = RecordingPfOps {
        fail_clear_standing: true,
        ..Default::default()
    };

    let result = disengage_lockdown_with(CoverPresence::Recorded, StateFile::Present(standing_state()), &mut ops);

    assert!(result.unwrap_err().to_string().contains("mock clear_standing failure"));
    assert_eq!(ops.log, vec!["load_ruleset", "clear_standing"]);
}

/// A failed restore leaves record and token, so the retry meets the same record and releases it once: one clear, one
/// drop.
#[skuld::test]
fn the_retry_of_a_failed_lockdown_disengage_releases_the_record_and_token_it_kept() {
    let tmp = tempfile::tempdir().unwrap();
    pf_record::swap(tmp.path(), &standing_state(), None).unwrap();
    let mut first = RecordingPfOps {
        fail_load_ruleset: true,
        ..RecordingPfOps::over_records(tmp.path())
    };
    let failed = disengage_lockdown_with(CoverPresence::Recorded, pf_record::read(tmp.path()), &mut first);
    assert!(failed.is_err());
    assert_eq!(first.log, vec!["load_ruleset"]);
    assert_eq!(
        pf_record::read::<lockdown_state::LockdownPfState>(tmp.path()),
        StateFile::Present(standing_state()),
        "the record waits for the retry, naming the token still held"
    );

    let mut retry = RecordingPfOps::over_records(tmp.path());
    let retried = disengage_lockdown_with(CoverPresence::Recorded, pf_record::read(tmp.path()), &mut retry);

    assert!(retried.is_ok(), "{retried:?}");
    assert_eq!(retry.log, vec!["load_ruleset", "clear_standing", "drop_token"]);
    assert_eq!(retry.dropped, vec!["222".to_owned()]);
    assert_eq!(
        pf_record::read::<lockdown_state::LockdownPfState>(tmp.path()),
        StateFile::Absent
    );
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

/// The callers that release a cover, over a real record, from every outcome of the restore, of the record write the
/// release makes (the clear after a good restore) and of `pfctl -X`. The double reads the record whenever `-X` runs and
/// fails the test if it still names the token.
///
/// After a good restore the record is cleared and the token dropped once it was. A failed restore keeps record and
/// token together and issues no `-X`, for every caller; a clear that fails drops nothing.
#[skuld::test]
fn a_release_never_drops_a_token_a_record_still_names() {
    /// How a record stands after the release, relative to the token it was seeded with.
    fn standing_of<R: PfRecord>(file: StateFile<R>, token: &str) -> &'static str {
        match file {
            StateFile::Absent => "gone",
            StateFile::Present(record) if record.pf_token() == token => "unchanged",
            StateFile::Present(_) => "another token",
            StateFile::Unusable { .. } => "unusable",
            StateFile::Unreadable => "unreadable",
        }
    }

    struct Caller {
        name: &'static str,
        standing: bool,
        /// Runs the caller over the seeded record; `Some(ok)` when it reports one.
        run: fn(&Path, &mut RecordingPfOps) -> Option<bool>,
    }
    let callers = [
        Caller {
            name: "release_all",
            standing: true,
            run: |dir, ops| {
                let released = release_all_with(StateFile::Absent, pf_record::read(dir), ops).into_result();
                Some(released.is_ok())
            },
        },
        Caller {
            name: "disengage_lockdown",
            standing: true,
            run: |dir, ops| Some(disengage_lockdown_with(CoverPresence::Recorded, pf_record::read(dir), ops).is_ok()),
        },
        Caller {
            name: "recover_cover",
            standing: false,
            run: |dir, ops| {
                recover_cover_with(pf_record::read(dir), false, ops);
                None
            },
        },
        Caller {
            name: "transient guard",
            standing: false,
            run: |_, ops| {
                disengage_with(Ok(Some("111")), false, ops);
                None
            },
        },
    ];
    for caller in callers {
        let token = if caller.standing { "222" } else { "111" };
        for restore_ok in [true, false] {
            for write_ok in [true, false] {
                for drop_ok in [true, false] {
                    let case = format!(
                        "{}, restore ok: {restore_ok}, write ok: {write_ok}, drop ok: {drop_ok}",
                        caller.name
                    );
                    let tmp = tempfile::tempdir().unwrap();
                    let dir = tmp.path();
                    match caller.standing {
                        true => pf_record::swap(dir, &standing_state(), None).map(|_| ()),
                        false => pf_record::swap(dir, &transient_state(), None).map(|_| ()),
                    }
                    .unwrap();
                    let mut ops = RecordingPfOps {
                        fail_load_ruleset: !restore_ok,
                        fail_reload_default: !restore_ok,
                        fail_clear_transient: !write_ok,
                        fail_clear_standing: !write_ok,
                        fail_drop_token: !drop_ok,
                        ..RecordingPfOps::over_records(dir)
                    };

                    let reported = (caller.run)(dir, &mut ops);

                    let (record, dropped) = match (restore_ok, write_ok) {
                        (true, true) => ("gone", true),
                        _ => ("unchanged", false),
                    };
                    let now = match caller.standing {
                        true => standing_of(pf_record::read::<lockdown_state::LockdownPfState>(dir), token),
                        false => standing_of(pf_record::read::<state::FailClosedState>(dir), token),
                    };
                    assert_eq!(now, record, "{case}: the record, after {:?}", ops.log);
                    if !restore_ok {
                        assert!(
                            ops.cleared.is_empty(),
                            "{case}: a failed restore clears nothing: {:?}",
                            ops.log
                        );
                    }
                    let expected_drops = if dropped { vec![token.to_owned()] } else { vec![] };
                    assert_eq!(ops.dropped, expected_drops, "{case}: {:?}", ops.log);
                    if let Some(ok) = reported {
                        assert_eq!(ok, restore_ok && write_ok, "{case}");
                    }
                }
            }
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

    assert_eq!(ops.log, vec!["reload_default", "clear_transient", "drop_token"]);
}

// Records that name no token, and the token a displaced record no longer names ========================================

/// Every state a record can be in that yields no token to drop, and that a clear removes, is disclosed as a leaked
/// refcount: the file was Hole's evidence of a cover and its token is unrecoverable. A record that is absent, readable,
/// or unusable with a salvageable token is not.
#[skuld::test]
fn every_removed_record_that_named_no_token_is_disclosed_as_one_that_leaks_a_refcount() {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let disclosed = |bytes: Option<&str>| {
        let tmp = tempfile::tempdir().unwrap();
        if let Some(bytes) = bytes {
            std::fs::write(tmp.path().join(state::STATE_FILE_NAME), bytes).unwrap();
        }
        let writer = garter::test_utils::WaitableWriter::new();
        let subscriber = tracing_subscriber::registry().with(
            tracing_subscriber::fmt::layer()
                .with_writer(writer.clone())
                .with_ansi(false)
                .with_filter(tracing_subscriber::filter::LevelFilter::WARN),
        );
        {
            let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
            let mut ops = RecordingPfOps::over_records(tmp.path());
            recover_cover_with(pf_record::read(tmp.path()), false, &mut ops);
        }
        writer.snapshot().contains("no pf token could be read")
    };

    for (what, bytes) in [
        ("an obsolete record", r#"{"version":0,"pf_was_enabled":false}"#),
        ("a newer record", r#"{"version":2,"pf_was_enabled":false}"#),
        ("a corrupt record", r#"{"version":1,"pf_was_enabled":false}"#),
        ("bytes that are not json", "{not json"),
        (
            "an empty token",
            r#"{"version":2,"pf_token":"","pf_was_enabled":false}"#,
        ),
    ] {
        assert!(disclosed(Some(bytes)), "{what}");
    }
    for (what, bytes) in [
        ("no record", None),
        (
            "a live record",
            Some(r#"{"version":1,"pf_token":"7","pf_was_enabled":false}"#),
        ),
        (
            "a newer record that names its token",
            Some(r#"{"version":2,"pf_token":"7","pf_was_enabled":false}"#),
        ),
    ] {
        assert!(!disclosed(bytes), "{what}");
    }
}

/// The guard of a cover a later engage displaced: the engage dropped that token, pf may have handed its value on, and
/// the record names the newer one. The guard restores and finds a record that is not its own.
#[skuld::test]
fn a_guard_whose_record_a_later_engage_replaced_drops_nothing_and_leaves_the_newer_record() {
    let tmp = tempfile::tempdir().unwrap();
    pf_record::swap(tmp.path(), &recorded_cover("222"), None).unwrap();
    let mut ops = RecordingPfOps::over_records(tmp.path());

    disengage_with(Ok(Some("111")), false, &mut ops);

    assert_eq!(ops.log, vec!["reload_default", "clear_transient"]);
    assert_eq!(
        pf_record::read::<state::FailClosedState>(tmp.path()),
        StateFile::Present(recorded_cover("222"))
    );
}

/// A record this release cannot read still names its token in its bytes. A restore that failed leaves those bytes as
/// they are and drops nothing: the retry finds the token where it was.
#[skuld::test]
fn a_failed_restore_over_an_unusable_record_leaves_its_bytes_and_drops_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let newer = r#"{"version":2,"pf_token":"9","main_snapshot":"","nat_snapshot":"","main_snapshot_captured":true}"#;
    let path = tmp.path().join(lockdown_state::STATE_FILE_NAME);
    std::fs::write(&path, newer).unwrap();
    let mut ops = RecordingPfOps {
        fail_reload_default: true,
        ..RecordingPfOps::over_records(tmp.path())
    };

    let result = disengage_lockdown_with(CoverPresence::Recorded, pf_record::read(tmp.path()), &mut ops);

    assert!(result.is_err());
    assert_eq!(ops.log, vec!["reload_default"]);
    assert_eq!(std::fs::read_to_string(&path).unwrap(), newer);
}
