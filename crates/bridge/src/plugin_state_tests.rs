use super::*;
use util::dir::testing::{plant_link, SystemScratch};
use util::versioned_file::{CannotRead, Change, DefaultPlacement, UnreadableKind};

use cosca::identity::{Platform, ProcessId, ProcessIdRecord, RECORD_VERSION};

/// A record with a chosen pid and token. Inert data whose invariants are
/// checked only on the way back, so a `Windows` record is constructible and
/// serializable on every host.
fn synthetic(pid: u32, token: u64) -> ProcessIdRecord {
    ProcessIdRecord {
        version: RECORD_VERSION,
        platform: Platform::Windows,
        pid,
        token,
        boot_id: None,
        pid_ns: None,
    }
}

/// A current-schema file holding `state`, written without going through `append_record`.
fn seed(dir: &Path, state: PluginState) {
    file(dir)
        .update(&DefaultPlacement::default(), |_| (Change::Store(state), ()))
        .unwrap();
}

fn state_path(dir: &Path) -> std::path::PathBuf {
    dir.join(STATE_FILE_NAME)
}

fn plugins_of(loaded: Loaded<PluginState>) -> Vec<ProcessIdRecord> {
    let Loaded::Current { value, .. } = loaded else {
        panic!("expected a current-schema record, got {loaded:?}");
    };
    value.plugins
}

#[skuld::test]
fn seed_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let state = PluginState {
        plugins: vec![synthetic(1234, 1000), synthetic(5678, 2000)],
    };
    seed(dir.path(), state.clone());
    assert_eq!(plugins_of(load(dir.path())), state.plugins);
}

#[skuld::test]
fn round_trip_preserves_a_record() {
    let dir = tempfile::tempdir().unwrap();
    let record = ProcessId::current()
        .to_record()
        .expect("persist this process's identity");

    append_record(dir.path(), record.clone(), None).unwrap();

    assert_eq!(plugins_of(load(dir.path())), vec![record]);
}

#[skuld::test]
fn append_preserves_prior_records() {
    let dir = tempfile::tempdir().unwrap();
    let r1 = synthetic(100, 1000);
    let r2 = synthetic(200, 2000);

    append_record(dir.path(), r1.clone(), None).unwrap();
    append_record(dir.path(), r2.clone(), None).unwrap();

    assert_eq!(plugins_of(load(dir.path())), vec![r1, r2]);
}

#[skuld::test]
fn append_record_creates_file_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    let r = synthetic(42, 999);
    append_record(dir.path(), r.clone(), None).unwrap();

    assert_eq!(plugins_of(load(dir.path())), vec![r]);
}

#[skuld::test]
fn append_creates_a_missing_dir() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("a").join("b");
    append_record(&nested, synthetic(1, 1), None).unwrap();
    assert!(state_path(&nested).exists());
}

#[skuld::test]
fn absent_file_loads_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(load(dir.path()), Loaded::Absent));
}

#[skuld::test]
fn corrupt_json_loads_as_corrupt() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(state_path(dir.path()), b"not json").unwrap();
    assert!(matches!(load(dir.path()), Loaded::Corrupt { .. }));
}

#[skuld::test]
fn a_version_1_file_loads_as_obsolete() {
    // An empty `plugins` array parses at any version, so this reaches the floor and not the shape check.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(state_path(dir.path()), br#"{"version":1,"plugins":[]}"#).unwrap();
    assert!(matches!(load(dir.path()), Loaded::Obsolete { found: 1, .. }));
}

#[skuld::test]
fn a_v1_record_shape_loads_as_obsolete() {
    // The real predecessor file: its records are not `ProcessIdRecord`s, and the floor decides before the shape does.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        state_path(dir.path()),
        br#"{"version":1,"plugins":[{"pid":1234,"start_time_unix_ms":1700000000000}]}"#,
    )
    .unwrap();
    assert!(matches!(load(dir.path()), Loaded::Obsolete { found: 1, .. }));
}

#[skuld::test]
fn a_newer_file_loads_as_newer() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(state_path(dir.path()), br#"{"version":3,"plugins":[]}"#).unwrap();
    assert!(matches!(load(dir.path()), Loaded::Newer { found: Some(3), .. }));
}

#[skuld::test]
fn a_file_with_an_unknown_field_still_reads() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": 2,
        "plugins": [],
        "extra": true,
    });
    std::fs::write(state_path(dir.path()), json.to_string()).unwrap();
    assert!(plugins_of(load(dir.path())).is_empty());
}

#[skuld::test]
fn wire_form_pins_the_token_as_a_decimal_string() {
    // cosca serializes `token` as a string on purpose: a Windows creation
    // FILETIME is ~1.3e17, past the 2^53 a double-precision JSON consumer can
    // represent, and a silently-rounded token is the aliasing `ProcessId`
    // exists to prevent. The file's version is written by the framing.
    let dir = tempfile::tempdir().unwrap();
    append_record(
        dir.path(),
        ProcessIdRecord {
            version: 1,
            platform: Platform::Windows,
            pid: 1234,
            token: 133_700_000_000_000_000,
            boot_id: None,
            pid_ns: None,
        },
        None,
    )
    .unwrap();

    let text = std::fs::read_to_string(state_path(dir.path())).unwrap();
    assert!(text.contains(r#""version": 2"#), "{text}");
    assert!(text.contains(r#""token": "133700000000000000""#), "{text}");
}

#[skuld::test]
fn a_reap_that_accounts_for_every_record_removes_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let record = synthetic(1, 1);
    seed(
        dir.path(),
        PluginState {
            plugins: vec![record.clone()],
        },
    );
    assert!(state_path(dir.path()).exists());
    assert_eq!(remove_accounted(dir.path(), &[record]).unwrap(), UpdateOutcome::Removed);
    assert!(!state_path(dir.path()).exists());
}

#[skuld::test]
fn remove_accounted_over_an_absent_file_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(
        remove_accounted(dir.path(), &[synthetic(1, 1)]).unwrap(),
        UpdateOutcome::Unchanged
    );
    assert!(!state_path(dir.path()).exists());
}

#[skuld::test]
fn remove_accounted_refuses_a_state_dir_that_is_a_users_link_to_a_system_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let state = util::dir::testing::state_dir_linked_to_a_system_folder(tmp.path());

    let err = remove_accounted(&state, &[synthetic(1, 1)]).unwrap_err();

    let StoreError::Io(err) = err else {
        panic!("expected an I/O refusal, got {err:?}");
    };
    assert_eq!(util::dir::Refusal::from_error(&err), Some(&util::dir::Refusal::Symlink));
}

// The reap and the appends ============================================================================================

fn plugins_in(dir: &Path) -> Vec<ProcessIdRecord> {
    plugins_of(load(dir))
}

#[skuld::test]
fn a_reap_removes_only_the_records_it_accounted_for() {
    // The reap loaded the file, then an append landed; the removal takes what the reap settled and nothing else.
    let dir = tempfile::tempdir().unwrap();
    let (reaped, late) = (synthetic(1, 1), synthetic(2, 2));
    append_record(dir.path(), reaped.clone(), None).unwrap();
    let seen = plugins_in(dir.path());
    append_record(dir.path(), late.clone(), None).unwrap();

    remove_accounted(dir.path(), &seen).unwrap();

    assert_eq!(plugins_in(dir.path()), vec![late]);
}

#[skuld::test]
fn an_append_then_a_removal_keeps_the_appended_record() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, r2) = (synthetic(1, 1), synthetic(2, 2));
    append_record(dir.path(), r1.clone(), None).unwrap();
    append_record(dir.path(), r2.clone(), None).unwrap();
    remove_accounted(dir.path(), &[r1]).unwrap();
    assert_eq!(plugins_in(dir.path()), vec![r2]);
}

#[skuld::test]
fn a_removal_then_an_append_does_not_resurrect_the_removed_record() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, r2) = (synthetic(1, 1), synthetic(2, 2));
    append_record(dir.path(), r1.clone(), None).unwrap();
    remove_accounted(dir.path(), &[r1]).unwrap();
    assert!(!state_path(dir.path()).exists(), "the file goes when no record remains");
    append_record(dir.path(), r2.clone(), None).unwrap();
    assert_eq!(plugins_in(dir.path()), vec![r2]);
}

#[skuld::test]
fn remove_accounted_drops_exactly_the_accounted_records() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, r2, r3) = (synthetic(1, 1), synthetic(2, 2), synthetic(3, 3));
    for r in [&r1, &r2, &r3] {
        append_record(dir.path(), r.clone(), None).unwrap();
    }
    remove_accounted(dir.path(), &[r1, r3.clone()]).unwrap();
    assert_eq!(plugins_in(dir.path()), vec![r2.clone()]);

    // A record the file does not hold is not an error and removes nothing.
    remove_accounted(dir.path(), &[r3]).unwrap();
    assert_eq!(plugins_in(dir.path()), vec![r2]);
}

#[skuld::test]
fn an_append_racing_the_reap_is_not_lost() {
    // The reaper and every appender are released together; whatever the order, the reaped record is gone and every
    // appended one is there.
    const APPENDERS: u32 = 8;
    let dir = tempfile::tempdir().unwrap();
    let reaped = synthetic(1000, 1000);
    append_record(dir.path(), reaped.clone(), None).unwrap();
    let barrier = std::sync::Barrier::new(APPENDERS as usize + 1);

    std::thread::scope(|scope| {
        scope.spawn(|| {
            barrier.wait();
            remove_accounted(dir.path(), std::slice::from_ref(&reaped)).unwrap();
        });
        for n in 0..APPENDERS {
            let (barrier, dir) = (&barrier, dir.path());
            scope.spawn(move || {
                barrier.wait();
                append_record(dir, synthetic(n, u64::from(n)), None).unwrap();
            });
        }
    });

    let mut pids: Vec<u32> = plugins_in(dir.path()).iter().map(|r| r.pid).collect();
    pids.sort_unstable();
    assert_eq!(pids, (0..APPENDERS).collect::<Vec<_>>());
}

/// The owner of `path` itself.
#[cfg(unix)]
fn owner_ids(path: &Path) -> (u32, u32) {
    use std::os::unix::fs::MetadataExt;
    let meta = std::fs::symlink_metadata(path).unwrap();
    (meta.uid(), meta.gid())
}

/// Discriminates on a root lane, where `own` gives the file to another user; unprivileged the file and the writer
/// share an owner, so the test is vacuous there.
#[cfg(unix)]
#[skuld::test]
fn a_reap_rewrite_keeps_the_files_owner_and_leaves_the_directory_alone() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, r2) = (synthetic(1, 1), synthetic(2, 2));
    append_record(dir.path(), r1.clone(), None).unwrap();
    append_record(dir.path(), r2.clone(), None).unwrap();
    util::dir::testing::own(&state_path(dir.path()));
    let (file_before, dir_before) = (owner_ids(&state_path(dir.path())), owner_ids(dir.path()));

    remove_accounted(dir.path(), &[r1]).unwrap();

    assert_eq!(plugins_in(dir.path()), vec![r2]);
    assert_eq!(owner_ids(&state_path(dir.path())), file_before);
    assert_eq!(owner_ids(dir.path()), dir_before);
}

#[cfg(unix)]
#[skuld::test]
fn an_append_leaves_the_file_owned_by_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    append_record(dir.path(), synthetic(1, 1), None).unwrap();
    // SAFETY: geteuid and getegid take no arguments and cannot fail.
    let writer = unsafe { (libc::geteuid(), libc::getegid()) };
    assert_eq!(owner_ids(&state_path(dir.path())), writer);
}

// A record this release cannot read ===================================================================================

/// A directory at the state-file path. Reading a directory fails with `IsADirectory` on Unix and
/// `PermissionDenied` on Windows, neither of which is `NotFound`, so a read that fails is reached on every platform
/// with no permission games and no race.
fn plant_unreadable(dir: &Path) {
    std::fs::create_dir_all(state_path(dir)).unwrap();
}

#[skuld::test]
fn a_present_but_unreadable_file_loads_as_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    plant_unreadable(dir.path());
    let Loaded::Unreadable { kind, .. } = load(dir.path()) else {
        panic!("a directory at the name must not read");
    };
    assert_eq!(kind, UnreadableKind::NotAFile);
}

/// How a record this release cannot read got to the name, and what the append must say about it.
struct Unreadable {
    what: &'static str,
    plant: fn(&Path),
    /// The bytes that must survive, or `None` for the planted directory.
    bytes: Option<&'static [u8]>,
}

const UNREADABLE: [Unreadable; 3] = [
    Unreadable {
        what: "newer",
        plant: |dir| std::fs::write(state_path(dir), br#"{"version":3,"plugins":[]}"#).unwrap(),
        bytes: Some(br#"{"version":3,"plugins":[]}"#),
    },
    Unreadable {
        what: "corrupt",
        plant: |dir| std::fs::write(state_path(dir), b"not json").unwrap(),
        bytes: Some(b"not json"),
    },
    Unreadable {
        what: "a failed read",
        plant: plant_unreadable,
        bytes: None,
    },
];

/// Every record this release cannot read blocks a connect, and names the file it blocks on.
#[skuld::test]
fn a_record_this_release_cannot_read_blocks_a_connect() {
    for Unreadable { what, plant, .. } in UNREADABLE {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path());
        assert_eq!(blocking(dir.path()), Some(state_path(dir.path())), "{what}");
    }
}

#[skuld::test]
fn a_record_this_release_reads_or_drops_or_lacks_does_not_block_a_connect() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(blocking(dir.path()), None, "no record");

    seed(
        dir.path(),
        PluginState {
            plugins: vec![synthetic(1, 1)],
        },
    );
    assert_eq!(blocking(dir.path()), None, "a current record");

    std::fs::write(
        state_path(dir.path()),
        br#"{"version":1,"plugins":[{"pid":1,"start_time_unix_ms":1}]}"#,
    )
    .unwrap();
    assert_eq!(blocking(dir.path()), None, "an obsolete record is dropped on purpose");
}

#[skuld::test]
fn append_over_an_unreadable_record_is_refused() {
    // Rewriting with a single record would drop the plugins the file tracks. Each case keeps what it held.
    for Unreadable { what, plant, bytes } in UNREADABLE {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path());

        let err = append_record(dir.path(), synthetic(2, 2), None).expect_err(what);

        match (what, &err) {
            ("a failed read", StoreError::ReadFailed { .. }) => {}
            ("newer", StoreError::Unreadable { cause, .. }) => assert_eq!(*cause, CannotRead::Newer),
            ("corrupt", StoreError::Unreadable { cause, .. }) => assert_eq!(*cause, CannotRead::Corrupt),
            _ => panic!("{what}: unexpected refusal {err:?}"),
        }
        match bytes {
            Some(bytes) => assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), bytes, "{what}"),
            None => assert!(
                state_path(dir.path()).is_dir(),
                "{what}: the planted directory was replaced"
            ),
        }
    }
}

#[skuld::test]
fn append_over_absent_and_obsolete_starts_a_fresh_record() {
    let absent = tempfile::tempdir().unwrap();
    append_record(absent.path(), synthetic(1, 1), None).unwrap();
    assert_eq!(plugins_of(load(absent.path())), vec![synthetic(1, 1)]);

    let obsolete = tempfile::tempdir().unwrap();
    std::fs::write(
        state_path(obsolete.path()),
        br#"{"version":1,"plugins":[{"pid":1234,"start_time_unix_ms":1700000000000}]}"#,
    )
    .unwrap();
    append_record(obsolete.path(), synthetic(2, 2), None).unwrap();
    assert_eq!(
        plugins_of(load(obsolete.path())),
        vec![synthetic(2, 2)],
        "an obsolete record names nothing, so the append starts fresh"
    );
}

#[skuld::test]
fn a_reap_keeps_a_record_it_cannot_read() {
    for Unreadable { what, plant, bytes } in UNREADABLE {
        let dir = tempfile::tempdir().unwrap();
        plant(dir.path());

        assert_eq!(
            remove_accounted(dir.path(), &[synthetic(1, 1)]).unwrap(),
            UpdateOutcome::Unchanged,
            "{what}"
        );
        match bytes {
            Some(bytes) => assert_eq!(std::fs::read(state_path(dir.path())).unwrap(), bytes, "{what}"),
            None => assert!(
                state_path(dir.path()).is_dir(),
                "{what}: the planted directory was replaced"
            ),
        }
    }
}

#[skuld::test]
fn remove_accounted_leaves_a_file_it_cannot_read_alone() {
    let dir = tempfile::tempdir().unwrap();
    plant_unreadable(dir.path());
    assert_eq!(
        remove_accounted(dir.path(), &[synthetic(1, 1)]).unwrap(),
        UpdateOutcome::Unchanged
    );
    assert!(state_path(dir.path()).exists());
}

#[skuld::test]
fn a_reap_that_has_nothing_to_edit_does_not_move_the_generation() {
    // An absent file and each unreadable one: the reap has no record to remove, so it writes nothing and a reader
    // that compares generations sees no write.
    let mut cases = vec![("absent", tempfile::tempdir().unwrap())];
    for u in &UNREADABLE {
        let dir = tempfile::tempdir().unwrap();
        (u.plant)(dir.path());
        cases.push((u.what, dir));
    }
    for (what, dir) in cases {
        let dir = dir.path();
        let before = file(dir).observe().generation;

        remove_accounted(dir, &[synthetic(1, 1)]).unwrap();

        assert_eq!(file(dir).observe().generation, before, "{what}");
    }
}

#[skuld::test]
fn clear_obsolete_removes_only_an_obsolete_record() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        state_path(dir.path()),
        br#"{"version":1,"plugins":[{"pid":1234,"start_time_unix_ms":1700000000000}]}"#,
    )
    .unwrap();
    assert_eq!(clear_obsolete(dir.path()).unwrap(), UpdateOutcome::Removed);
    assert!(!state_path(dir.path()).exists());

    // A file that has become current since the caller looked is not obsolete.
    append_record(dir.path(), synthetic(1, 1), None).unwrap();
    assert_eq!(clear_obsolete(dir.path()).unwrap(), UpdateOutcome::Unchanged);
    assert_eq!(plugins_in(dir.path()), vec![synthetic(1, 1)]);

    let absent = tempfile::tempdir().unwrap();
    assert_eq!(clear_obsolete(absent.path()).unwrap(), UpdateOutcome::Unchanged);
}

#[skuld::test]
fn append_refuses_a_link_to_a_folder_the_system_owns_and_writes_nothing_there() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let link = tmp.path().join("state");
    plant_link(scratch.root(), &link);
    let written = scratch.root().join(STATE_FILE_NAME);
    let before = written.exists();

    assert!(append_record(&link, synthetic(1, 1), None).is_err());

    assert_eq!(
        written.exists(),
        before,
        "a state file was written in the system's folder"
    );
}

// Swallowed outcomes are logged =======================================================================================

/// Capture this crate's log at `DEBUG` and above while `body` runs.
fn captured(body: impl FnOnce()) -> String {
    use tracing_subscriber::layer::{Layer, SubscriberExt};

    let writer = crate::test_support::log_capture::VecWriter::new();
    let subscriber = tracing_subscriber::registry().with(
        tracing_subscriber::fmt::layer()
            .with_writer(writer.clone())
            .with_ansi(false)
            .with_filter(tracing_subscriber::filter::LevelFilter::DEBUG),
    );
    {
        let _guard = garter::tracing_test::set_default_in_current_thread(subscriber);
        body();
    }
    writer.snapshot_string()
}

#[skuld::test]
fn clear_obsolete_reports_a_file_it_could_not_read_and_keeps_it() {
    // A directory where the file belongs: the read fails with something other than "not found", so the file is
    // neither classified nor discarded.
    let dir = tempfile::tempdir().unwrap();
    plant_unreadable(dir.path());

    let log = captured(|| {
        clear_obsolete(dir.path()).unwrap();
    });

    assert!(state_path(dir.path()).exists(), "an unreadable file is kept");
    assert!(
        log.contains("WARN") && log.contains("could not be read"),
        "the read failure must not vanish: {log}"
    );
}

#[skuld::test]
fn remove_accounted_logs_the_error_of_a_failed_read() {
    let dir = tempfile::tempdir().unwrap();
    plant_unreadable(dir.path());

    let log = captured(|| {
        remove_accounted(dir.path(), &[synthetic(1, 1)]).unwrap();
    });

    assert!(
        log.lines()
            .any(|l| l.contains("WARN") && l.contains("nothing to remove") && l.contains("error=")),
        "the I/O error must reach the log, not just the fact of a failed read: {log}"
    );
}

#[skuld::test]
fn remove_accounted_says_why_it_removed_nothing_from_a_file_that_is_gone_or_unusable() {
    let absent = tempfile::tempdir().unwrap();
    let log = captured(|| {
        remove_accounted(absent.path(), &[synthetic(1, 1)]).unwrap();
    });
    assert!(log.contains("DEBUG") && log.contains("no plugin state file"), "{log}");

    // Each unusable file gets its own warning, worded by what is wrong with it.
    for (what, expected) in [
        ("newer", "newer"),
        ("corrupt", "corrupt"),
        ("a failed read", "unreadable"),
    ] {
        let unusable = tempfile::tempdir().unwrap();
        let case = UNREADABLE.iter().find(|u| u.what == what).unwrap();
        (case.plant)(unusable.path());
        let log = captured(|| {
            remove_accounted(unusable.path(), &[synthetic(1, 1)]).unwrap();
        });
        assert!(
            log.lines()
                .any(|l| l.contains("WARN") && l.contains("nothing to remove") && l.contains(expected)),
            "{what}: {log}"
        );
    }
}
