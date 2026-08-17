use super::*;

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
        plugin_state::Loaded::Unreadable(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        dir.path(),
    );

    assert!(
        state_file_exists(dir.path()),
        "an unreadable state file must survive for the next start"
    );
}

#[skuld::test]
fn an_unusable_state_file_is_cleared() {
    let dir = tempfile::tempdir().unwrap();
    seed_state_file(dir.path());

    reap_loaded(plugin_state::Loaded::Unusable, dir.path());

    assert!(
        !state_file_exists(dir.path()),
        "an unusable state file must be cleared: nothing in it can name a process"
    );
}

#[skuld::test]
fn an_absent_state_file_leaves_the_directory_untouched() {
    let dir = tempfile::tempdir().unwrap();

    reap_loaded(plugin_state::Loaded::Absent, dir.path());

    assert!(
        !state_file_exists(dir.path()),
        "the Absent arm must not write a state file"
    );
}

#[skuld::test]
fn a_failed_kill_keeps_the_file() {
    // cosca returns `Err` only for a target it could not open or assess — i.e.
    // exactly when it may still be running — which a test cannot manufacture
    // for its own child, so the kill is injected.
    let dir = tempfile::tempdir().unwrap();
    let record = seed_state_file(dir.path());
    let state = plugin_state::PluginState {
        version: plugin_state::SCHEMA_VERSION,
        plugins: vec![record],
    };

    reap_loaded_with(plugin_state::Loaded::State(state), dir.path(), |_| {
        Err(cosca::error::Error::Unassessable {
            detail: "injected".into(),
            source: None,
        })
    });

    assert!(
        state_file_exists(dir.path()),
        "a record whose kill failed is not accounted for, so the file must be kept"
    );
}
