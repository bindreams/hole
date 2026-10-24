use super::*;

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

#[skuld::test]
fn save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let state = PluginState {
        version: SCHEMA_VERSION,
        plugins: vec![synthetic(1234, 1000), synthetic(5678, 2000)],
    };
    save_with(dir.path(), &state, None, None, &RealOwnership).unwrap();
    let Loaded::State(loaded) = load(dir.path()) else {
        panic!("saved state must load as State");
    };
    assert_eq!(loaded, state);
}

#[skuld::test]
fn round_trip_preserves_a_record() {
    let dir = tempfile::tempdir().unwrap();
    let record = ProcessId::current()
        .to_record()
        .expect("persist this process's identity");

    append_record(dir.path(), record.clone(), None).unwrap();

    let Loaded::State(loaded) = load(dir.path()) else {
        panic!("an appended record must load as State");
    };
    assert_eq!(loaded.plugins, vec![record]);
}

#[skuld::test]
fn append_preserves_prior_records() {
    let dir = tempfile::tempdir().unwrap();
    let r1 = synthetic(100, 1000);
    let r2 = synthetic(200, 2000);

    append_record(dir.path(), r1.clone(), None).unwrap();
    append_record(dir.path(), r2.clone(), None).unwrap();

    let Loaded::State(loaded) = load(dir.path()) else {
        panic!("appended records must load as State");
    };
    assert_eq!(loaded.plugins, vec![r1, r2]);
}

#[skuld::test]
fn append_record_creates_file_if_missing() {
    let dir = tempfile::tempdir().unwrap();
    let r = synthetic(42, 999);
    append_record(dir.path(), r.clone(), None).unwrap();

    let Loaded::State(loaded) = load(dir.path()) else {
        panic!("the first append must create a loadable file");
    };
    assert_eq!(loaded.plugins, vec![r]);
}

#[skuld::test]
fn absent_file_loads_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(load(dir.path()), Loaded::Absent));
}

#[skuld::test]
fn corrupt_json_loads_as_unusable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), b"not json").unwrap();
    assert!(matches!(load(dir.path()), Loaded::Unusable));
}

#[skuld::test]
fn a_wrong_version_file_loads_as_unusable() {
    // An empty `plugins` array parses at any version, so this is the only
    // fixture that reaches the version guard: delete the guard and `load`
    // answers `State`.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), br#"{"version":1,"plugins":[]}"#).unwrap();
    assert!(matches!(load(dir.path()), Loaded::Unusable));
}

#[skuld::test]
fn a_v1_record_shape_loads_as_unusable() {
    // The real predecessor file. A `{pid, start_time_unix_ms}` object is not a
    // `ProcessIdRecord`, so this fails deserialization BEFORE the version
    // comparison — it covers the parse arm, not the guard above.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join(STATE_FILE_NAME),
        br#"{"version":1,"plugins":[{"pid":1234,"start_time_unix_ms":1700000000000}]}"#,
    )
    .unwrap();
    assert!(matches!(load(dir.path()), Loaded::Unusable));
}

#[skuld::test]
fn unknown_field_loads_as_unusable() {
    let dir = tempfile::tempdir().unwrap();
    let json = serde_json::json!({
        "version": SCHEMA_VERSION,
        "plugins": [],
        "extra": true,
    });
    std::fs::write(dir.path().join(STATE_FILE_NAME), json.to_string()).unwrap();
    assert!(matches!(load(dir.path()), Loaded::Unusable));
}

#[skuld::test]
fn wire_form_pins_the_token_as_a_decimal_string() {
    // cosca serializes `token` as a string on purpose: a Windows creation
    // FILETIME is ~1.3e17, past the 2^53 a double-precision JSON consumer can
    // represent, and a silently-rounded token is the aliasing `ProcessId`
    // exists to prevent. `save` and `to_string` share one `Serialize` impl, so
    // pinning the compact string pins the file's encoding too.
    let state = PluginState {
        version: SCHEMA_VERSION,
        plugins: vec![ProcessIdRecord {
            version: 1,
            platform: Platform::Windows,
            pid: 1234,
            token: 133_700_000_000_000_000,
            boot_id: None,
            pid_ns: None,
        }],
    };
    assert_eq!(
        serde_json::to_string(&state).unwrap(),
        r#"{"version":2,"plugins":[{"v":1,"platform":"windows","pid":1234,"token":"133700000000000000"}]}"#
    );
}

#[skuld::test]
fn remove_file_removes_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let state = PluginState {
        version: SCHEMA_VERSION,
        plugins: vec![synthetic(1, 1)],
    };
    save_with(dir.path(), &state, None, None, &RealOwnership).unwrap();
    assert!(dir.path().join(STATE_FILE_NAME).exists());
    remove_file(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn remove_file_tolerates_a_missing_file() {
    let dir = tempfile::tempdir().unwrap();
    remove_file(dir.path()).unwrap();
}

#[skuld::test]
fn save_creates_missing_dir() {
    let parent = tempfile::tempdir().unwrap();
    let nested = parent.path().join("a").join("b");
    let state = PluginState {
        version: SCHEMA_VERSION,
        plugins: vec![],
    };
    save_with(&nested, &state, None, None, &RealOwnership).unwrap();
    assert!(nested.join(STATE_FILE_NAME).exists());
}

// A present file that could not be read ===============================================================================

/// A directory at the state-file path. `std::fs::read` of a directory fails
/// with `IsADirectory` on Unix and `PermissionDenied` on Windows, neither of
/// which is `NotFound`, so the arm is reached on every platform with no
/// permission games and no race.
fn unreadable_fixture(dir: &std::path::Path) {
    let path = dir.join(STATE_FILE_NAME);
    std::fs::create_dir_all(&path).unwrap();
    std::fs::read(&path).expect_err("reading a directory must fail");
}

#[skuld::test]
fn a_present_but_unreadable_file_loads_as_unreadable() {
    // This fixture proves the classification only. It must not be reused for a
    // "the file survived" assertion: `clear` is `remove_file`, which fails on
    // a directory anyway, so that would hold in both worlds.
    let dir = tempfile::tempdir().unwrap();
    unreadable_fixture(dir.path());
    assert!(matches!(load(dir.path()), Loaded::Unreadable(_)));
}

#[skuld::test]
fn an_unreadable_append_writes_nothing_and_reports_the_error() {
    // A transient failure on the second plugin's append must not rewrite the
    // file with one record and leave the first untracked.
    //
    // Both assertions read values that move: over a healthy, writable file,
    // folding `Unreadable` into the fresh-state arm answers `Ok` and rewrites
    // the file to `second` alone. The error's message, not its `ErrorKind` —
    // reading a directory and renaming onto one report the same kind, so a kind
    // comparison cannot separate the read's error from a downstream write's.
    let dir = tempfile::tempdir().unwrap();
    let first = synthetic(1, 1);
    let second = synthetic(2, 2);
    append_record(dir.path(), first.clone(), None).unwrap();

    let err = append_loaded(
        Loaded::Unreadable(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "injected")),
        dir.path(),
        second,
        None,
    )
    .expect_err("append must report the read failure");

    assert!(
        err.to_string().contains("injected"),
        "the append must surface the READ's error, not a downstream write's; got: {err}"
    );
    let Loaded::State(loaded) = load(dir.path()) else {
        panic!("the seeded state file must still load as State");
    };
    assert_eq!(
        loaded.plugins,
        vec![first],
        "a failed read must write nothing: the prior record was dropped"
    );
}

// Concurrent writers ==================================================================================================

fn loaded_plugins(dir: &std::path::Path) -> Vec<ProcessIdRecord> {
    match load(dir) {
        Loaded::State(s) => s.plugins,
        other => panic!("expected a loadable state, got {other:?}"),
    }
}

#[skuld::test]
fn append_holds_the_plugin_lock_across_load_and_save() {
    let dir = tempfile::tempdir().unwrap();
    let mut held_inside = false;
    append_record_with(dir.path(), synthetic(1, 1), None, || {
        held_inside = lock_is_held();
    })
    .unwrap();
    assert!(
        held_inside,
        "the load, the push and the save must be one critical section"
    );
    assert!(!lock_is_held(), "the lock is released on return");
}

#[skuld::test]
fn remove_accounted_holds_the_plugin_lock_while_rewriting() {
    let dir = tempfile::tempdir().unwrap();
    append_record(dir.path(), synthetic(1, 1), None).unwrap();
    let mut held_inside = false;
    remove_accounted_with(dir.path(), &[synthetic(1, 1)], None, &RealOwnership, || {
        held_inside = lock_is_held();
    })
    .unwrap();
    assert!(held_inside);
    assert!(!lock_is_held());
}

#[skuld::test]
fn an_append_then_a_removal_keeps_the_appended_record() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, r2) = (synthetic(1, 1), synthetic(2, 2));
    append_record(dir.path(), r1.clone(), None).unwrap();
    append_record(dir.path(), r2.clone(), None).unwrap();
    remove_accounted(dir.path(), &[r1], None).unwrap();
    assert_eq!(loaded_plugins(dir.path()), vec![r2]);
}

#[skuld::test]
fn a_removal_then_an_append_does_not_resurrect_the_removed_record() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, r2) = (synthetic(1, 1), synthetic(2, 2));
    append_record(dir.path(), r1.clone(), None).unwrap();
    remove_accounted(dir.path(), &[r1], None).unwrap();
    assert!(
        !dir.path().join(STATE_FILE_NAME).exists(),
        "the file goes when no record remains"
    );
    append_record(dir.path(), r2.clone(), None).unwrap();
    assert_eq!(loaded_plugins(dir.path()), vec![r2]);
}

#[skuld::test]
fn remove_accounted_drops_exactly_the_accounted_records() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, r2, r3) = (synthetic(1, 1), synthetic(2, 2), synthetic(3, 3));
    for r in [&r1, &r2, &r3] {
        append_record(dir.path(), r.clone(), None).unwrap();
    }
    remove_accounted(dir.path(), &[r1, r3.clone()], None).unwrap();
    assert_eq!(loaded_plugins(dir.path()), vec![r2.clone()]);

    // A record the file does not hold is not an error and removes nothing.
    remove_accounted(dir.path(), &[r3], None).unwrap();
    assert_eq!(loaded_plugins(dir.path()), vec![r2]);
}

#[skuld::test]
fn remove_accounted_over_an_absent_file_is_a_no_op() {
    let dir = tempfile::tempdir().unwrap();
    remove_accounted(dir.path(), &[synthetic(1, 1)], None).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn remove_accounted_leaves_a_file_it_cannot_read_alone() {
    let dir = tempfile::tempdir().unwrap();
    unreadable_fixture(dir.path());
    remove_accounted(dir.path(), &[synthetic(1, 1)], None).expect_err("an unreadable file cannot be edited");
    assert!(dir.path().join(STATE_FILE_NAME).exists());
}

#[skuld::test]
fn clear_if_unusable_clears_only_an_unusable_file() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(STATE_FILE_NAME), b"{not json").unwrap();
    clear_if_unusable(dir.path()).unwrap();
    assert!(!dir.path().join(STATE_FILE_NAME).exists());

    append_record(dir.path(), synthetic(1, 1), None).unwrap();
    clear_if_unusable(dir.path()).unwrap();
    assert_eq!(
        loaded_plugins(dir.path()),
        vec![synthetic(1, 1)],
        "a file that has become usable since the caller looked is not worthless"
    );

    let absent = tempfile::tempdir().unwrap();
    clear_if_unusable(absent.path()).unwrap();
}

#[skuld::test]
fn load_holds_the_plugin_lock_while_reading() {
    let dir = tempfile::tempdir().unwrap();
    let mut held_inside = false;
    let _ = load_with(dir.path(), || {
        held_inside = lock_is_held();
    });
    assert!(
        held_inside,
        "a read must not interleave with an append's rename-replace"
    );
    assert!(!lock_is_held(), "the lock is released on return");
}

// Rewrite ownership ===================================================================================================

type Owner = Option<(u32, u32)>;

/// Answers `existing` for the state file's owner and records every chown, plus
/// the file's bytes at the moment its owner was read.
struct Recording {
    existing: Option<(u32, u32)>,
    chowns: std::cell::RefCell<Vec<(std::path::PathBuf, Owner)>>,
    bytes_when_read: std::cell::RefCell<Option<Vec<u8>>>,
}

impl Recording {
    fn new(existing: Option<(u32, u32)>) -> Self {
        Self {
            existing,
            chowns: Default::default(),
            bytes_when_read: Default::default(),
        }
    }

    fn state_file_chowns(&self, dir: &std::path::Path) -> Vec<Option<(u32, u32)>> {
        let file = dir.join(STATE_FILE_NAME);
        self.chowns
            .borrow()
            .iter()
            .filter(|(p, _)| *p == file)
            .map(|(_, o)| *o)
            .collect()
    }
}

impl Ownership for Recording {
    fn owner_of(&self, path: &std::path::Path) -> Option<(u32, u32)> {
        *self.bytes_when_read.borrow_mut() = std::fs::read(path).ok();
        self.existing
    }

    fn chown(&self, path: &std::path::Path, owner: Option<(u32, u32)>) {
        self.chowns.borrow_mut().push((path.to_path_buf(), owner));
    }
}

fn two_records(dir: &std::path::Path) -> (ProcessIdRecord, ProcessIdRecord) {
    let (r1, r2) = (synthetic(1, 1), synthetic(2, 2));
    append_record(dir, r1.clone(), None).unwrap();
    append_record(dir, r2.clone(), None).unwrap();
    (r1, r2)
}

#[skuld::test]
fn a_rewrite_without_a_requested_owner_keeps_the_files_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, _) = two_records(dir.path());
    let rec = Recording::new(Some((501, 20)));
    remove_accounted_with(dir.path(), &[r1], None, &rec, || {}).unwrap();
    assert_eq!(rec.state_file_chowns(dir.path()), vec![Some((501, 20))]);
}

#[skuld::test]
fn an_append_with_no_requested_owner_leaves_the_file_owned_by_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let (_, _) = two_records(dir.path());
    let rec = Recording::new(Some((501, 20)));
    append_loaded_with(load(dir.path()), dir.path(), synthetic(3, 3), None, &rec).unwrap();
    assert_eq!(rec.state_file_chowns(dir.path()), vec![None]);
    assert!(
        rec.bytes_when_read.borrow().is_none(),
        "an append must not look up the replaced file's owner"
    );
}

#[skuld::test]
fn the_files_owner_is_read_before_the_rewrite_replaces_it() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, _) = two_records(dir.path());
    let before = std::fs::read(dir.path().join(STATE_FILE_NAME)).unwrap();
    let rec = Recording::new(Some((501, 20)));
    remove_accounted_with(dir.path(), &[r1], None, &rec, || {}).unwrap();
    assert_eq!(rec.bytes_when_read.borrow().as_deref(), Some(before.as_slice()));
}

#[skuld::test]
fn a_requested_owner_wins_over_the_files_owner() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, _) = two_records(dir.path());
    let rec = Recording::new(Some((501, 20)));
    remove_accounted_with(dir.path(), &[r1], Some((7, 8)), &rec, || {}).unwrap();
    assert_eq!(rec.state_file_chowns(dir.path()), vec![Some((7, 8))]);
}

#[skuld::test]
fn a_file_with_no_known_owner_and_no_request_is_not_chowned_to_anyone() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, _) = two_records(dir.path());
    let rec = Recording::new(None);
    remove_accounted_with(dir.path(), &[r1], None, &rec, || {}).unwrap();
    assert_eq!(rec.state_file_chowns(dir.path()), vec![None]);
}

#[skuld::test]
fn only_the_requested_owner_reaches_the_state_dir() {
    let dir = tempfile::tempdir().unwrap();
    let (r1, _) = two_records(dir.path());
    let rec = Recording::new(Some((501, 20)));
    remove_accounted_with(dir.path(), &[r1], None, &rec, || {}).unwrap();
    let dir_chowns: Vec<_> = rec
        .chowns
        .borrow()
        .iter()
        .filter(|(p, _)| p == dir.path())
        .map(|(_, o)| *o)
        .collect();
    assert_eq!(
        dir_chowns,
        vec![None],
        "the directory is not handed to the file's owner"
    );
}
