use super::*;
use util::versioned_file::UnreadableKind;

use tracing_subscriber::layer::{Layer, SubscriberExt};

use crate::test_support::log_capture::VecWriter;
use crate::test_support::reap_child::EchoChild;

/// Capture this crate's log records at `INFO` and above for the duration of
/// `body`. The reap's per-record line is the only place the four-state
/// observation is visible, so it has to be read, not inferred.
fn captured(body: impl FnOnce()) -> String {
    let writer = VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::INFO),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        body();
    }
    writer.snapshot_string()
}

fn state_file_exists(dir: &Path) -> bool {
    dir.join(plugin_state::STATE_FILE_NAME).exists()
}

#[skuld::test]
fn the_reap_kills_the_recorded_process() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = EchoChild::spawn();
    plugin_state::append_record(dir.path(), child.record(), None).unwrap();

    reap_recorded_plugins(dir.path());

    assert!(!child.echoes(), "the recorded process must not answer after the reap");
    assert!(
        !state_file_exists(dir.path()),
        "a reap that accounted for every record must clear the state file"
    );
    let status = child.release_and_wait();
    assert!(
        !status.success(),
        "the child's clean path is exactly exit(0), so a non-success status is reachable only by the kill; got {status:?}"
    );
}

#[skuld::test]
fn the_reap_spares_a_recycled_pid() {
    // A genuinely recycled pid is "same pid, different start token", and the
    // OS cannot be made to hand one back without a timing bet or an unbounded
    // spawn loop. Flipping one bit of the token is that state exactly.
    let dir = tempfile::tempdir().unwrap();
    let mut child = EchoChild::spawn();
    let mut record = child.record();
    record.token ^= 1;
    plugin_state::append_record(dir.path(), record, None).unwrap();

    let log = captured(|| reap_recorded_plugins(dir.path()));

    assert!(
        child.echoes(),
        "a recycled pid must survive the reap: the child stopped answering"
    );
    assert!(
        !state_file_exists(dir.path()),
        "a reap that accounted for every record must clear the state file"
    );
    let pid = child.pid();
    assert!(
        log.contains("observation=\"recycled\"") && log.contains(&pid.to_string()),
        "the reap must record the recycled observation for pid {pid}; got:\n{log}"
    );
}

#[skuld::test]
fn an_unrestorable_record_is_not_killed() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = EchoChild::spawn();
    let mut record = child.record();
    record.platform = cosca::identity::Platform::Other("plan9".into());
    plugin_state::append_record(dir.path(), record, None).unwrap();

    let log = captured(|| reap_recorded_plugins(dir.path()));

    assert!(
        child.echoes(),
        "a record that does not restore names no killable process: the child stopped answering"
    );
    let pid = child.pid();
    assert!(
        log.contains("plan9") && log.contains(&pid.to_string()),
        "the rejected record must be reported for pid {pid}; got:\n{log}"
    );
}

// Dispositions: only a reap that accounted for every record may delete the file =======================================

/// A normal, deletable state file, so a "kept vs cleared" assertion
/// discriminates. Returns the record it holds.
fn seed_state_file(dir: &Path) -> cosca::identity::ProcessIdRecord {
    let record = cosca::identity::ProcessId::current()
        .to_record()
        .expect("persist this process's identity");
    plugin_state::append_record(dir, record.clone(), None).unwrap();
    assert!(state_file_exists(dir), "the fixture must start with a state file");
    record
}

#[skuld::test]
fn an_unreadable_state_file_is_kept_for_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    seed_state_file(dir.path());

    reap_loaded(
        Loaded::Unreadable {
            error: std::io::Error::from(std::io::ErrorKind::PermissionDenied),
            kind: UnreadableKind::File,
        },
        dir.path(),
    );

    assert!(
        state_file_exists(dir.path()),
        "an unreadable state file must survive for the next start"
    );
}

#[skuld::test]
fn reap_keeps_a_record_it_cannot_read() {
    // A newer or corrupt record may name live plugins nobody here can interpret: it is never deleted, and the reap says
    // so at error level.
    let cases: [(&str, &[u8]); 2] = [("newer", br#"{"version":3,"plugins":[]}"#), ("corrupt", b"not json")];
    for (what, bytes) in cases {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(plugin_state::STATE_FILE_NAME), bytes).unwrap();

        let log = captured(|| reap_recorded_plugins(dir.path()));

        assert_eq!(
            std::fs::read(dir.path().join(plugin_state::STATE_FILE_NAME)).unwrap(),
            bytes,
            "{what}: the record was changed"
        );
        assert!(
            log.contains("ERROR") && log.contains("keeping it"),
            "{what}: the reap must say it kept the record; got:
{log}"
        );
    }
}

#[skuld::test]
fn reap_clears_an_obsolete_record() {
    // Version 1 holds `{pid, start_time_unix_ms}` objects, which can no longer name a process.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(plugin_state::STATE_FILE_NAME),
        br#"{"version":1,"plugins":[{"pid":1234,"start_time_unix_ms":1700000000000}]}"#,
    )
    .unwrap();

    reap_recorded_plugins(dir.path());

    assert!(
        !state_file_exists(dir.path()),
        "an obsolete record names no process: it is cleared"
    );
}

#[skuld::test]
fn an_absent_state_file_leaves_the_directory_untouched() {
    let dir = tempfile::tempdir().unwrap();

    reap_loaded(Loaded::Absent, dir.path());

    assert!(
        !state_file_exists(dir.path()),
        "the Absent arm must not write a state file"
    );
}

/// The real restore, for the tests that only inject the kill.
fn real_restore(record: &cosca::identity::ProcessIdRecord) -> Result<cosca::identity::ProcessId, cosca::error::Error> {
    cosca::identity::ProcessId::try_from(record)
}

fn unassessable() -> cosca::error::Error {
    cosca::error::Error::Unassessable {
        detail: "injected".into(),
        source: None,
    }
}

fn record_error(kind: cosca::error::RecordErrorKind) -> cosca::error::Error {
    cosca::error::Error::IdentityRecord {
        kind,
        detail: "injected".into(),
        source: None,
    }
}

#[skuld::test]
fn a_failed_kill_keeps_the_file() {
    // cosca returns `Err` only for a target it could not open or assess — i.e.
    // exactly when it may still be running — which a test cannot manufacture
    // for its own child, so the kill is injected.
    let dir = tempfile::tempdir().unwrap();
    let record = seed_state_file(dir.path());
    let state = plugin_state::PluginState { plugins: vec![record] };

    reap_loaded_with(
        Loaded::Current { value: state, found: 2 },
        dir.path(),
        real_restore,
        |_| Err(unassessable()),
    );

    assert!(
        state_file_exists(dir.path()),
        "a record whose kill failed is not accounted for, so the file must be kept"
    );
}

#[skuld::test]
fn an_unreadable_boot_session_keeps_the_file_where_a_foreign_record_clears_it() {
    // `ScopeUnreadable` is the one record error that is not about the record's
    // contents: this host's own boot session could not be read, and cosca raises
    // it BEFORE validating the record, so a perfectly restorable record lands
    // here. Folding it in with the permanently-foreign kinds deletes the file and
    // leaks a live plugin untraceably. Only Linux can raise it for real, so the
    // restore is injected; the foreign-platform kind is the control.
    for (kind, keep) in [
        (cosca::error::RecordErrorKind::ScopeUnreadable, true),
        (cosca::error::RecordErrorKind::ForeignPlatform, false),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let record = seed_state_file(dir.path());
        let state = plugin_state::PluginState { plugins: vec![record] };

        reap_loaded_with(
            Loaded::Current { value: state, found: 2 },
            dir.path(),
            |_| Err(record_error(kind)),
            |_| panic!("a record that did not restore must never reach the kill"),
        );

        assert_eq!(
            state_file_exists(dir.path()),
            keep,
            "{kind:?} must {} the state file",
            if keep { "keep" } else { "clear" }
        );
    }
}

#[skuld::test]
fn an_accounted_record_after_an_unaccounted_one_still_keeps_the_file() {
    // The flag accumulates across the whole loop. Tracking only the LAST
    // record's outcome passes every single-record test while silently dropping
    // the guarantee for a multi-plugin chain — so the unaccounted record comes
    // FIRST and the accounted one after it.
    let dir = tempfile::tempdir().unwrap();
    let template = seed_state_file(dir.path());
    let unaccounted = cosca::identity::ProcessIdRecord { pid: 4242, ..template };
    let accounted = cosca::identity::ProcessIdRecord {
        pid: 4243,
        ..unaccounted.clone()
    };
    let state = plugin_state::PluginState {
        plugins: vec![unaccounted, accounted],
    };

    let killed = std::sync::Mutex::new(Vec::new());
    reap_loaded_with(
        Loaded::Current { value: state, found: 2 },
        dir.path(),
        real_restore,
        |id| {
            killed.lock().unwrap().push(id.pid());
            if id.pid() == 4242 {
                Err(unassessable())
            } else {
                Ok(())
            }
        },
    );

    assert_eq!(
        *killed.lock().unwrap(),
        vec![4242, 4243],
        "every record must be processed, not just up to the first failure"
    );
    assert!(
        state_file_exists(dir.path()),
        "one unaccounted record keeps the file however many accounted ones follow it"
    );
}

// Concurrent writers ==================================================================================================

/// An inert record that names no process on any host.
fn synthetic_record(pid: u32) -> cosca::identity::ProcessIdRecord {
    cosca::identity::ProcessIdRecord {
        version: cosca::identity::RECORD_VERSION,
        platform: cosca::identity::Platform::Windows,
        pid,
        token: u64::from(pid),
        boot_id: None,
        pid_ns: None,
    }
}

fn recorded(dir: &Path) -> Vec<cosca::identity::ProcessIdRecord> {
    match plugin_state::load(dir) {
        Loaded::Current { value, .. } => value.plugins,
        other => panic!("expected a current record, got {other:?}"),
    }
}

#[skuld::test]
fn a_record_appended_while_the_reap_kills_survives_the_removal() {
    // A plugin attempt that was aborted can still be appending its record while the next stop reaps. The append lands
    // between the reap's load and its removal; the removal must take only what the reap accounted for. The append
    // inside the kill is also the proof that the kill runs outside the record's lock: it would not return otherwise.
    let dir = tempfile::tempdir().unwrap();
    let reaped = seed_state_file(dir.path());
    let late = synthetic_record(7777);
    let state = plugin_state::PluginState { plugins: vec![reaped] };

    reap_loaded_with(
        Loaded::Current { value: state, found: 2 },
        dir.path(),
        real_restore,
        |_| {
            plugin_state::append_record(dir.path(), late.clone(), None).unwrap();
            Ok(())
        },
    );

    assert_eq!(recorded(dir.path()), vec![late]);
}

#[skuld::test]
fn an_obsolete_file_rewritten_by_an_append_is_not_cleared() {
    // The reap classified the file as obsolete; before it acts, an append rewrites it with a live record.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(plugin_state::STATE_FILE_NAME),
        br#"{"version":1,"plugins":[]}"#,
    )
    .unwrap();
    let classified = plugin_state::load(dir.path());
    assert!(matches!(classified, Loaded::Obsolete { .. }), "guard: {classified:?}");
    let appended = synthetic_record(8888);
    plugin_state::append_record(dir.path(), appended.clone(), None).unwrap();

    reap_loaded(classified, dir.path());

    assert_eq!(recorded(dir.path()), vec![appended]);
}

#[skuld::test]
fn a_reap_that_cannot_account_for_a_record_keeps_that_record_and_removes_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    // Records that restore on every host (the fixture's own identity) but name no live process; the kill is injected.
    let template = cosca::identity::ProcessId::current()
        .to_record()
        .expect("persist this process's identity");
    let unaccounted = cosca::identity::ProcessIdRecord {
        pid: 4242,
        ..template.clone()
    };
    let accounted = cosca::identity::ProcessIdRecord { pid: 4243, ..template };
    plugin_state::append_record(dir.path(), unaccounted.clone(), None).unwrap();
    plugin_state::append_record(dir.path(), accounted.clone(), None).unwrap();
    let state = plugin_state::PluginState {
        plugins: vec![unaccounted.clone(), accounted],
    };

    reap_loaded_with(
        Loaded::Current { value: state, found: 2 },
        dir.path(),
        real_restore,
        |id| {
            if id.pid() == 4242 {
                Err(unassessable())
            } else {
                Ok(())
            }
        },
    );

    assert_eq!(
        recorded(dir.path()),
        vec![unaccounted],
        "the next start retries only the record this reap could not settle"
    );
}

// The blocking reap's join ============================================================================================

/// The `JoinError`s a blocking task's join can report, produced by real tasks: one aborted before it ran, one that
/// panicked.
async fn join_errors() -> (tokio::task::JoinError, tokio::task::JoinError) {
    let aborted = tokio::spawn(std::future::pending::<()>());
    aborted.abort();
    let panicked = tokio::spawn(async {
        if true {
            panic!("injected panic in the reap task");
        }
    });
    (
        aborted.await.expect_err("an aborted task"),
        panicked.await.expect_err("a panicked task"),
    )
}

#[skuld::test]
async fn a_cancelled_blocking_reap_is_run_inline() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = EchoChild::spawn();
    plugin_state::append_record(dir.path(), child.record(), None).unwrap();
    let (cancelled, _) = join_errors().await;

    let log = captured(|| settle_blocking_reap(Err(cancelled), dir.path()));

    assert!(!child.echoes(), "the recorded process must be reaped, not left running");
    assert!(!log.contains("panicked"), "a cancel is not a panic; got:\n{log}");
    child.release_and_wait();
}

#[skuld::test]
async fn a_panicked_blocking_reap_is_logged_as_a_panic_and_not_rerun() {
    let dir = tempfile::tempdir().unwrap();
    let mut child = EchoChild::spawn();
    plugin_state::append_record(dir.path(), child.record(), None).unwrap();
    let (_, panicked) = join_errors().await;

    let log = captured(|| settle_blocking_reap(Err(panicked), dir.path()));

    assert!(log.contains("panicked"), "got:\n{log}");
    assert!(child.echoes(), "a reap that panicked is not retried inline");
    child.release_and_wait();
}

#[skuld::test]
async fn a_blocking_reap_that_joined_cleanly_logs_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let log = captured(|| settle_blocking_reap(Ok(()), dir.path()));
    assert!(log.is_empty(), "got:\n{log}");
}
