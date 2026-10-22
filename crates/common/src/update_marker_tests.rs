use super::*;
use util::dir::testing::{plant_link, user_dir, SystemScratch};

/// A marker naming a chosen pid. Synthetic, so a test can pick the pid it
/// discriminates on; inert data, so a `Windows` record builds on every host.
fn info(pid: u32) -> MarkerInfo {
    MarkerInfo {
        version: MARKER_VERSION,
        driver: cosca::identity::ProcessIdRecord {
            version: cosca::identity::RECORD_VERSION,
            platform: cosca::identity::Platform::Windows,
            pid,
            token: 133_700_000_000_000_000,
            boot_id: None,
            pid_ns: None,
        },
    }
}

/// The marker's payload, or a failure naming which arm answered instead.
fn present(dir: &std::path::Path) -> MarkerInfo {
    match read(dir) {
        Marker::Present(info) => info,
        other => panic!("expected a readable marker, got {other:?}"),
    }
}

#[skuld::test]
fn absent_reads_as_absent() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(read(dir.path()), Marker::Absent));
    assert!(!is_present(dir.path()));
}

#[skuld::test]
fn valid_reads_as_present() {
    let dir = tempfile::tempdir().unwrap();
    let info = info(4242);
    write(dir.path(), &info, None).unwrap();

    let Marker::Present(got) = read(dir.path()) else {
        panic!("a marker written at the current version must read as Present");
    };
    assert_eq!(got, info);
    assert!(is_present(dir.path()));

    clear(dir.path()).unwrap();
    assert!(matches!(read(dir.path()), Marker::Absent));
    // clear is idempotent (remove-by-name, not parse-then-clear).
    clear(dir.path()).unwrap();
}

#[skuld::test]
fn an_unparseable_marker_reads_as_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(MARKER_FILE), b"not json").unwrap();
    assert!(matches!(read(dir.path()), Marker::Unreadable));
}

#[skuld::test]
fn is_present_is_true_for_an_unreadable_marker() {
    // Presence derived from a successful parse answers `false` here, which is
    // the fail-open the post-sweep re-check exists to catch.
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(MARKER_FILE), b"not json").unwrap();
    assert!(is_present(dir.path()));
}

#[cfg(windows)]
#[skuld::test]
fn a_marker_held_open_against_readers_reads_as_unreadable() {
    // The case the post-sweep refusal exists for: a holder keeps the marker open
    // denying read, so the open fails while the file is plainly there. Windows-only
    // — the unix equivalent is a permission denial, which root defeats.
    // Pins the unprivileged reader: one holding backup rights reads through the
    // holder and gets `Present`, which is also a claim.
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), &info(7), None).unwrap();
    let _held = std::fs::OpenOptions::new()
        .read(true)
        // Deny every other opener, this process included.
        .share_mode(0)
        .open(dir.path().join(MARKER_FILE))
        .unwrap();
    let (got, present, raw_steps, log) = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let log = CapturedLog::new();
                let _guard = log.install();
                let _unprivileged = restricted_reader::Impersonation::begin();
                let got = read(dir.path());
                (got, is_present(dir.path()), raw_steps(dir.path()), log.contents())
            })
            .join()
            .unwrap()
    });
    assert!(
        matches!(got, Marker::Unreadable),
        "a regular file that exists but cannot be opened is still a claim; read answered {got:?}
raw steps: {raw_steps}
log:
{log}"
    );
    assert!(present);
}

// The unprivileged reader ---------------------------------------------------------------------------------------------

#[cfg(windows)]
mod restricted_reader {
    use windows::core::Owned;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::Security::{
        CreateRestrictedToken, DuplicateTokenEx, SecurityImpersonation, TokenImpersonation, DISABLE_MAX_PRIVILEGE,
        TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_IMPERSONATE, TOKEN_QUERY,
    };
    use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken, SetThreadToken};

    /// The calling thread runs as a copy of the process token with every privilege removed, until dropped.
    /// Thread-scoped: the process token, and every other thread, are untouched.
    pub(super) struct Impersonation;

    impl Impersonation {
        /// Panics if the token cannot be built or applied: a test of the unprivileged reader has no meaning without it.
        pub(super) fn begin() -> Self {
            // SAFETY: every out-pointer names a live local; each handle is owned and closed on drop.
            unsafe {
                let mut process = HANDLE::default();
                OpenProcessToken(
                    GetCurrentProcess(),
                    TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
                    &mut process,
                )
                .expect("OpenProcessToken");
                let process = Owned::new(process);

                let mut restricted = HANDLE::default();
                CreateRestrictedToken(*process, DISABLE_MAX_PRIVILEGE, None, None, None, &mut restricted)
                    .expect("CreateRestrictedToken");
                let restricted = Owned::new(restricted);

                let mut impersonation = HANDLE::default();
                DuplicateTokenEx(
                    *restricted,
                    TOKEN_IMPERSONATE | TOKEN_QUERY,
                    None,
                    SecurityImpersonation,
                    TokenImpersonation,
                    &mut impersonation,
                )
                .expect("DuplicateTokenEx");
                let impersonation = Owned::new(impersonation);

                // The thread keeps its own reference to the token; closing ours afterwards is fine.
                SetThreadToken(None, Some(*impersonation)).expect("SetThreadToken");
            }
            Self
        }
    }

    impl Drop for Impersonation {
        fn drop(&mut self) {
            // SAFETY: a null token stops this thread impersonating.
            let reverted = unsafe { SetThreadToken(None, None) };
            // A failed revert leaves the thread restricted; a panic in drop during unwinding aborts, so only report.
            debug_assert!(reverted.is_ok(), "SetThreadToken(NULL) failed: {reverted:?}");
        }
    }
}

// Diagnostics for the held-open test ----------------------------------------------------------------------------------

#[cfg(windows)]
mod held_diagnostics {
    use super::*;

    /// What each OS step under [`read`] answers for the marker, for a failed assertion to show which one it was.
    pub(super) fn raw_steps(log_dir: &std::path::Path) -> String {
        let dir = match ReadDir::open(log_dir) {
            Ok(dir) => dir,
            Err(e) => return format!("ReadDir::open: {e:?}"),
        };
        let read = dir.read(MARKER_FILE.as_ref()).map(|bytes| bytes.len());
        format!("read: {read:?}; kind_of: {:?}", dir.kind_of(MARKER_FILE.as_ref()))
    }

    /// The module's tracing output for one test, so a failed assertion can name the branch that answered.
    #[derive(Clone)]
    pub(super) struct CapturedLog(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl CapturedLog {
        pub(super) fn new() -> Self {
            Self(Default::default())
        }

        pub(super) fn install(&self) -> tracing::subscriber::DefaultGuard {
            let subscriber = tracing_subscriber::fmt()
                .with_writer(self.clone())
                .with_ansi(false)
                .with_max_level(tracing::Level::TRACE)
                .finish();
            garter::tracing_test::set_default_in_current_thread(subscriber)
        }

        pub(super) fn contents(&self) -> String {
            String::from_utf8_lossy(&self.0.lock().unwrap()).into_owned()
        }
    }

    impl std::io::Write for CapturedLog {
        fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLog;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }
}

#[cfg(windows)]
use held_diagnostics::{raw_steps, CapturedLog};

#[skuld::test]
fn a_directory_at_the_marker_path_reads_as_indeterminate() {
    // A directory is not a marker: it claims no cutover, so reporting one asserts
    // something never observed — and permanently, since `clear`'s remove_file fails
    // on a directory every time, leaving no sweep able to retract it.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(MARKER_FILE)).unwrap();
    assert!(
        matches!(read(dir.path()), Marker::Indeterminate),
        "a non-file at the marker path is not a cutover claim"
    );
    assert!(!is_present(dir.path()));
}

/// A log dir whose marker path can be neither opened nor probed for existence.
/// Chosen so the OS refuses to resolve the path at all — no permission surgery,
/// so it is deterministic and not defeated by running as root.
fn unprobeable_log_dir(base: &std::path::Path) -> std::path::PathBuf {
    #[cfg(windows)]
    {
        // `*` is not a legal Windows path character: both calls fail
        // ERROR_INVALID_NAME, never ERROR_FILE_NOT_FOUND.
        base.join("in*valid")
    }
    #[cfg(not(windows))]
    {
        // A regular file standing in for the marker's parent dir: ENOTDIR.
        let file = base.join("not-a-dir");
        std::fs::write(&file, b"x").unwrap();
        file
    }
}

#[skuld::test]
fn a_marker_path_that_cannot_be_probed_reads_as_indeterminate() {
    let base = tempfile::tempdir().unwrap();
    let dir = unprobeable_log_dir(base.path());
    assert!(
        matches!(read(&dir), Marker::Indeterminate),
        "a failed read is not evidence a marker exists"
    );
}

#[skuld::test]
fn is_present_is_false_for_an_indeterminate_marker() {
    // Answering `true` here is permanently unretractable: `clear` is an io call
    // on the same path and fails under the same condition, so the claim would
    // outlive every sweep.
    let base = tempfile::tempdir().unwrap();
    let dir = unprobeable_log_dir(base.path());
    assert!(!is_present(&dir));
}

#[skuld::test]
fn an_unknown_version_marker_reads_as_unreadable() {
    let dir = tempfile::tempdir().unwrap();
    // The CURRENT shape with an unknown version, so it parses and the version
    // guard is what rejects it. A body of the OTHER schema's field set would be
    // refused by `deny_unknown_fields` first and would test nothing.
    let future = serde_json::json!({
        "version": 99,
        "driver": {"v": 1, "platform": "windows", "pid": 7, "token": "133700000000000000"},
    });
    std::fs::write(dir.path().join(MARKER_FILE), serde_json::to_vec(&future).unwrap()).unwrap();
    assert!(matches!(read(dir.path()), Marker::Unreadable));
    // But clear still removes it (remove-by-name), proving clear does NOT route
    // through read() — a schema bump must never strand the marker.
    clear(dir.path()).unwrap();
    assert!(!dir.path().join(MARKER_FILE).exists());
}

#[cfg(unix)]
#[skuld::test]
fn marker_mode_is_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), &info(1), None).unwrap();
    let mode = std::fs::metadata(dir.path().join(MARKER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644, "root bridge must write a GUI-readable marker");
}

#[skuld::test]
fn write_new_is_an_atomic_single_occupancy_claim() {
    let dir = tempfile::tempdir().unwrap();
    let first = info(1);
    // First claim wins and the full content is readable (never a partial file).
    write_new(dir.path(), &first, None).unwrap();
    assert_eq!(present(dir.path()), first);

    // A second claim loses with AlreadyExists (the race-free 409 guard) and does
    // not overwrite the first claim's content.
    let other = info(9999);
    let err = write_new(dir.path(), &other, None).unwrap_err();
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(present(dir.path()).driver.pid, 1);

    // No leftover temp file from either the win or the lost claim.
    let leftover = std::fs::read_dir(dir.path())
        .unwrap()
        .filter_map(|e| e.ok())
        .any(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
    assert!(!leftover, "no stray .tmp after write_new");

    // After a clear, the claim is available again.
    clear(dir.path()).unwrap();
    write_new(dir.path(), &other, None).unwrap();
    assert_eq!(present(dir.path()).driver.pid, 9999);
}

#[cfg(unix)]
#[skuld::test]
fn write_new_marker_mode_is_world_readable() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    write_new(dir.path(), &info(1), None).unwrap();
    let mode = std::fs::metadata(dir.path().join(MARKER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644, "the claimed marker must be GUI-readable too");
}

// The cross-uid proof that `owner` reaches the PUBLISHED marker inode (through
// rename for `write` and hard_link for `write_new`) needs real root to give the
// file to another uid; a self-chown here would be vacuous (the temp is already
// self-owned). It rides the root lane in
// `crates/hole/tests/elevated_ownership_privileged.rs`.

#[skuld::test]
fn stamp_driver_replaces_the_driver_and_leaves_a_readable_marker() {
    // "the version was preserved" is not asserted: with two fields left and
    // every other version unreadable, `version == MARKER_VERSION` is the only
    // value the file can carry, so it cannot distinguish preserved from
    // recomputed. Re-readability can: a stamp that wrote a wrong version or a
    // malformed body reads `Unreadable`.
    let dir = tempfile::tempdir().unwrap();
    write(dir.path(), &info(111), None).unwrap();

    let stamped = info(222).driver;
    stamp_driver(dir.path(), &stamped).unwrap();

    let Marker::Present(got) = read(dir.path()) else {
        panic!("a stamped marker must stay readable");
    };
    assert_eq!(got.driver, stamped);
}

#[skuld::test]
fn wire_form_v3() {
    // This file crosses a privilege boundary and a version boundary; its bytes
    // are a contract. `staged_marker` writes compact JSON, so the file's bytes
    // and this string are the same thing.
    assert_eq!(
        serde_json::to_string(&info(4242)).unwrap(),
        r#"{"version":3,"driver":{"v":1,"platform":"windows","pid":4242,"token":"133700000000000000"}}"#
    );
}

#[skuld::test]
fn a_v2_marker_reads_as_unreadable() {
    // Rejected through the `deny_unknown_fields` PARSE arm, not the version
    // guard: the v2 field set is unknown to the v3 shape. The guard keeps its
    // own test, `an_unknown_version_marker_reads_as_unreadable`.
    let dir = tempfile::tempdir().unwrap();
    let v2 = serde_json::json!({
        "version": 2,
        "from_version": "0.4.0",
        "to_version": "0.5.0",
        "driver_pid": 7,
        "started_at_unix": 1,
        "driver_start_unix_ms": 1_700_000_000_123u64,
    });
    std::fs::write(dir.path().join(MARKER_FILE), serde_json::to_vec(&v2).unwrap()).unwrap();
    assert!(matches!(read(dir.path()), Marker::Unreadable));
}

#[skuld::test]
fn stamp_driver_errs_when_the_marker_is_absent() {
    // Pins [`stamp_driver`]'s contract: nothing but `Present` may be stamped.
    let dir = tempfile::tempdir().unwrap();
    let result = stamp_driver(dir.path(), &info(1).driver);
    assert!(
        result.is_err(),
        "a marker that could not be read must fail the stamp, not be warned past"
    );
}

#[skuld::test]
fn service_log_dir_matches_log_collector_constants() {
    // Pins the dedup: the resolver must equal the dirs the GUI's log_collector
    // hardcodes (so the GUI reads the same place the bridge writes).
    let d = service_log_dir();
    #[cfg(target_os = "windows")]
    assert!(d.ends_with("hole\\logs") || d.ends_with("hole/logs"), "{d:?}");
    #[cfg(target_os = "macos")]
    assert_eq!(d, std::path::PathBuf::from("/var/log/hole"));
}

// The log directory is the user's to swap =============================================================================

/// `root/logs` as a link to the folder the system owns, and where the marker this test must never see written or
/// removed would be in it: the system's folder is shared, so what it held before is what it must hold after.
fn log_dir_linked_to_the_system(
    root: &std::path::Path,
    scratch: &SystemScratch,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let logs = root.join("logs");
    plant_link(scratch.root(), &logs);
    (logs, scratch.root().join(MARKER_FILE))
}

fn listing(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

#[skuld::test]
fn writing_through_a_link_to_a_folder_the_system_owns_is_refused_and_writes_nothing_there() {
    let root = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let (logs, marker) = log_dir_linked_to_the_system(root.path(), &scratch);
    let before = marker.exists();

    assert!(write(&logs, &info(1), None).is_err());
    assert!(write_new(&logs, &info(2), None).is_err());

    assert_eq!(marker.exists(), before, "a marker was written in the system's folder");
}

#[skuld::test]
fn clearing_through_a_link_to_a_folder_the_system_owns_removes_nothing_there() {
    let root = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let (logs, marker) = log_dir_linked_to_the_system(root.path(), &scratch);
    let before = marker.exists();

    assert!(clear(&logs).is_err());
    assert!(stamp_driver(&logs, &info(1).driver).is_err());

    assert_eq!(marker.exists(), before, "a marker was removed from the system's folder");
}

#[skuld::test]
fn writing_below_a_link_to_a_folder_the_system_owns_creates_nothing_there() {
    let root = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let link = root.path().join("hole");
    plant_link(scratch.root(), &link);

    assert!(write(&link.join(scratch.name()).join("logs"), &info(1), None).is_err());

    assert!(!scratch.path().exists(), "something was made in the system's folder");
}

#[skuld::test]
fn writing_and_clearing_through_a_users_link_to_the_users_folder_work() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    user_dir(&real);
    let logs = root.path().join("logs");
    plant_link(&real, &logs);

    write(&logs, &info(1), None).unwrap();
    assert_eq!(present(&real).driver.pid, 1);
    clear(&logs).unwrap();

    assert!(listing(&real).is_empty());
}

#[skuld::test]
fn write_creates_the_log_dir_when_it_is_missing() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("hole").join("logs");

    write(&logs, &info(1), None).unwrap();

    assert_eq!(present(&logs).driver.pid, 1);
    assert_eq!(listing(&logs), [MARKER_FILE], "no temp left behind");
}

#[skuld::test]
fn clear_of_a_log_dir_that_is_not_there_is_ok_and_makes_nothing() {
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().join("not-there");

    clear(&missing).unwrap();

    assert!(!missing.exists());
}

#[skuld::test]
fn clear_does_not_remove_a_directory_at_the_marker_path() {
    // `read` calls it indeterminate and says no sweep can retract a claim it never made; removing the directory
    // would be a different act.
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join(MARKER_FILE)).unwrap();

    assert!(clear(dir.path()).is_err());

    assert!(dir.path().join(MARKER_FILE).is_dir());
}

#[cfg(unix)]
#[skuld::test]
fn the_marker_goes_to_the_owner_by_either_publisher_when_the_os_allows() {
    use std::os::unix::fs::MetadataExt;

    let dir = tempfile::tempdir().unwrap();
    let foreign = dir.path().metadata().unwrap().uid() + 2;
    let scratch = dir.path().join("scratch");
    std::fs::write(&scratch, b"").unwrap();
    let allowed = std::os::unix::fs::chown(&scratch, Some(foreign), None).is_ok();
    let owner = Some((foreign, foreign));
    let owner_of_marker = || std::fs::metadata(dir.path().join(MARKER_FILE)).unwrap().uid();
    // The directory is the owner's too, as the bridge makes it before writing; a root-owned one is refused.
    std::os::unix::fs::chown(dir.path(), Some(foreign), None).ok();

    write(dir.path(), &info(1), owner).unwrap();
    assert_eq!(owner_of_marker() == foreign, allowed, "write");

    clear(dir.path()).unwrap();
    write_new(dir.path(), &info(2), owner).unwrap();
    assert_eq!(owner_of_marker() == foreign, allowed, "write_new");
}

// A name the user planted ---------------------------------------------------------------------------------------------
//
// The bridge reads the marker as root or SYSTEM in a log directory the user may own.

fn marker_reader() -> util::dir::testing::Reader<'static> {
    util::dir::testing::Reader {
        file: MARKER_FILE,
        write_valid: &|dir| write(dir, &info(4242), None).unwrap(),
        reads_it: &|dir| matches!(read(dir), Marker::Present(_)),
    }
}

#[skuld::test]
fn a_symlink_at_the_marker_is_not_read_through() {
    let tmp = tempfile::tempdir().unwrap();

    util::dir::testing::planted_name_is_not_read(
        tmp.path(),
        util::dir::testing::PlantedName::SymlinkToFile,
        &marker_reader(),
    )
    .unwrap();
}

#[skuld::test]
fn a_symlink_at_the_marker_claims_no_cutover() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    std::fs::create_dir(&real).unwrap();
    write(&real, &info(4242), None).unwrap();
    let state = tmp.path().join("state");
    std::fs::create_dir(&state).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(real.join(MARKER_FILE), state.join(MARKER_FILE)).unwrap();
    #[cfg(windows)]
    std::os::windows::fs::symlink_file(real.join(MARKER_FILE), state.join(MARKER_FILE)).unwrap();

    assert!(matches!(read(&state), Marker::Indeterminate), "{:?}", read(&state));
    assert!(!is_present(&state));
}

// The GUI reads the marker as the user, in a folder it may only be able to read from.
#[cfg(windows)]
#[skuld::test]
fn a_marker_in_a_folder_nobody_may_add_to_is_still_read() {
    let tmp = tempfile::tempdir().unwrap();
    write(tmp.path(), &info(4242), None).unwrap();
    let _denied = util::dir::testing::AddDenied::to(tmp.path());

    assert_eq!(present(tmp.path()), info(4242));
}

#[cfg(unix)]
#[skuld::test]
fn a_fifo_at_the_marker_claims_no_cutover_and_is_not_waited_for() {
    let tmp = tempfile::tempdir().unwrap();
    util::dir::testing::planted_name_is_not_read(tmp.path(), util::dir::testing::PlantedName::Fifo, &marker_reader())
        .unwrap();

    // The directory `planted_name_is_not_read` read holds the FIFO.
    let state = tmp.path().join("state");
    assert!(matches!(read(&state), Marker::Indeterminate), "{:?}", read(&state));
    assert!(!is_present(&state));
}
