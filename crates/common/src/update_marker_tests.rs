use super::*;
use util::dir::testing::{plant_link, runner_is_the_system, user_dir, SystemScratch};
use util::versioned_file::CreateOutcome;

/// A marker naming a chosen pid. Synthetic, so a test can pick the pid it
/// discriminates on; inert data, so a `Windows` record builds on every host.
fn info(pid: u32) -> MarkerInfo {
    MarkerInfo {
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
    assert_eq!(claim(dir.path(), &info, None).unwrap(), CreateOutcome::Created);

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
    let dir = tempfile::tempdir().unwrap();
    claim(dir.path(), &info(7), None).unwrap();
    let _held = util::dir::testing::held_without_sharing(&dir.path().join(MARKER_FILE));
    let (got, present) = util::dir::testing::as_unprivileged_thread(|| (read(dir.path()), is_present(dir.path())));
    assert!(
        matches!(got, Marker::Unreadable),
        "a regular file that exists but cannot be opened is still a claim; read answered {got:?}"
    );
    assert!(present);
}

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
    // The CURRENT shape with an unknown version, so the version guard is what
    // rejects it, not a parse failure.
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

#[skuld::test]
fn claim_is_an_atomic_single_occupancy_claim() {
    let dir = tempfile::tempdir().unwrap();
    let first = info(1);
    // First claim wins and the full content is readable (never a partial file).
    assert_eq!(claim(dir.path(), &first, None).unwrap(), CreateOutcome::Created);
    assert_eq!(present(dir.path()), first);

    // A second claim loses (the race-free 409 guard) and does not overwrite the
    // first claim's content.
    let other = info(9999);
    assert_eq!(claim(dir.path(), &other, None).unwrap(), CreateOutcome::Taken);
    assert_eq!(present(dir.path()).driver.pid, 1);

    // No leftover temp file from either the win or the lost claim.
    assert_eq!(listing(dir.path()), [MARKER_FILE], "no stray temp after a claim");

    // After a clear, the claim is available again.
    clear(dir.path()).unwrap();
    assert_eq!(claim(dir.path(), &other, None).unwrap(), CreateOutcome::Created);
    assert_eq!(present(dir.path()).driver.pid, 9999);
}

#[skuld::test]
fn claim_over_any_existing_file_is_taken() {
    let newer = br#"{"version":99,"driver":{}}"#.as_slice();
    for existing in [b"not json".as_slice(), newer] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MARKER_FILE), existing).unwrap();

        assert_eq!(claim(dir.path(), &info(1), None).unwrap(), CreateOutcome::Taken);

        assert_eq!(std::fs::read(dir.path().join(MARKER_FILE)).unwrap(), existing);
    }
}

#[skuld::test]
fn clear_removes_a_marker_it_cannot_read() {
    let newer = br#"{"version":99,"driver":{}}"#.as_slice();
    for unreadable in [b"not json".as_slice(), newer] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MARKER_FILE), unreadable).unwrap();
        assert!(is_present(dir.path()), "guard: it is a claim before the clear");

        clear(dir.path()).unwrap();

        assert!(listing(dir.path()).is_empty());
    }
}

#[skuld::test]
fn a_marker_with_a_second_name_is_an_unreadable_claim() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    let state = tmp.path().join("state");
    std::fs::create_dir(&real).unwrap();
    std::fs::create_dir(&state).unwrap();
    claim(&real, &info(4242), None).unwrap();
    std::fs::hard_link(real.join(MARKER_FILE), state.join(MARKER_FILE)).unwrap();

    // The system refuses a file it owns that has a second name; a user reads its own.
    match runner_is_the_system() {
        true => {
            assert!(matches!(read(&state), Marker::Unreadable), "{:?}", read(&state));
            assert!(is_present(&state), "a refused name is still a cutover claim");
        }
        false => assert_eq!(present(&state), info(4242)),
    }
}

/// Only a regular file that is there and could not be read is a claim: a directory that did not open, a name that is not
/// a file, and a name that could not be examined establish no cutover.
#[skuld::test]
fn a_failed_read_is_a_claim_only_when_the_name_is_known_to_hold_a_file() {
    let unreadable = |kind| Loaded::Unreadable {
        error: io::Error::from(io::ErrorKind::PermissionDenied),
        kind,
    };

    assert!(matches!(
        marker_of(unreadable(UnreadableKind::File)),
        Marker::Unreadable
    ));
    for kind in [
        UnreadableKind::Directory,
        UnreadableKind::NotAFile,
        UnreadableKind::Unprobed,
    ] {
        assert!(
            matches!(marker_of(unreadable(kind)), Marker::Indeterminate),
            "{kind:?} is not a claim"
        );
    }
}

/// A regular file whose read fails is a claim (`UnreadableKind::File`), as opposed to a name that is not a file.
/// A runner that ignores mode bits (root) reads it, so the case states both outcomes.
#[cfg(unix)]
#[skuld::test]
fn a_regular_marker_file_that_cannot_be_read_is_an_unreadable_claim() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    claim(dir.path(), &info(4242), None).unwrap();
    let path = dir.path().join(MARKER_FILE);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

    match std::fs::File::open(&path) {
        Err(_) => {
            assert!(matches!(read(dir.path()), Marker::Unreadable), "{:?}", read(dir.path()));
            assert!(
                is_present(dir.path()),
                "a file that is there and unreadable is a cutover claim"
            );
        }
        Ok(_) => assert_eq!(present(dir.path()), info(4242)),
    }
}

#[skuld::test]
fn a_marker_written_by_the_previous_release_reads_present() {
    let dir = tempfile::tempdir().unwrap();
    let previous = r#"{"version":3,"driver":{"v":1,"platform":"windows","pid":4242,"token":"133700000000000000"}}"#;
    std::fs::write(dir.path().join(MARKER_FILE), previous).unwrap();

    assert_eq!(present(dir.path()), info(4242));
}

#[cfg(unix)]
#[skuld::test]
fn claim_writes_mode_0644() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    claim(dir.path(), &info(1), None).unwrap();
    let mode = std::fs::metadata(dir.path().join(MARKER_FILE))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(mode & 0o777, 0o644, "root bridge must write a GUI-readable marker");
}

// The cross-uid proof that `owner` reaches the PUBLISHED marker inode (through the rename of `claim`) needs real
// root to give the file to another uid; a self-chown here would be vacuous (the temp is already self-owned). It
// rides the root lane in `crates/hole/tests/elevated_ownership_privileged.rs`.

#[skuld::test]
fn stamp_driver_replaces_the_driver_and_leaves_a_readable_marker() {
    // Re-readability pins the version: a stamp that wrote a wrong version or a
    // malformed body reads `Unreadable`.
    let dir = tempfile::tempdir().unwrap();
    claim(dir.path(), &info(111), None).unwrap();

    let stamped = info(222).driver;
    stamp_driver(dir.path(), &stamped).unwrap();

    let Marker::Present(got) = read(dir.path()) else {
        panic!("a stamped marker must stay readable");
    };
    assert_eq!(got.driver, stamped);
}

#[skuld::test]
fn wire_form_v3() {
    // This file crosses a privilege boundary and a version boundary; its keys are a contract with the previous
    // release, which declares `deny_unknown_fields`: exactly `version` and `driver`.
    let dir = tempfile::tempdir().unwrap();
    claim(dir.path(), &info(4242), None).unwrap();

    let bytes = std::fs::read(dir.path().join(MARKER_FILE)).unwrap();
    let on_disk: serde_json::Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(
        on_disk,
        serde_json::json!({
            "version": 3,
            "driver": {"v": 1, "platform": "windows", "pid": 4242, "token": "133700000000000000"},
        })
    );
}

#[skuld::test]
fn a_v2_marker_reads_as_unreadable() {
    // At the schema's floor: a version this release deliberately does not read.
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
fn stamp_driver_refuses_anything_but_a_present_marker() {
    // Pins [`stamp_driver`]'s contract: nothing but `Present` may be stamped, and a refusal leaves the file as it was.
    let newer = br#"{"version":99,"driver":{}}"#.as_slice();
    let absent = tempfile::tempdir().unwrap();
    let refused = stamp_driver(absent.path(), &info(1).driver).expect_err("an absent marker must fail the stamp");
    assert!(
        refused.get_ref().is_some_and(|e| e.is::<NoMarkerToStamp>()),
        "the refusal is the typed one: {refused:?}"
    );
    assert!(listing(absent.path()).is_empty(), "the stamp must not create a marker");

    for unreadable in [b"not json".as_slice(), newer] {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join(MARKER_FILE), unreadable).unwrap();

        let refused = stamp_driver(dir.path(), &info(1).driver)
            .expect_err("a marker that could not be read must fail the stamp, not be warned past");
        assert!(
            refused.get_ref().is_some_and(|e| e.is::<NoMarkerToStamp>()),
            "the refusal is the typed one: {refused:?}"
        );

        assert_eq!(std::fs::read(dir.path().join(MARKER_FILE)).unwrap(), unreadable);
        assert_eq!(listing(dir.path()), [MARKER_FILE]);
    }
}

#[skuld::test]
fn service_log_dir_matches_log_collector_constants() {
    // Pins each platform's service log directory.
    let d = service_log_dir();
    #[cfg(target_os = "windows")]
    assert!(d.ends_with("hole\\logs") || d.ends_with("hole/logs"), "{d:?}");
    #[cfg(target_os = "macos")]
    assert_eq!(d, std::path::PathBuf::from("/var/log/hole"));
}

/// The MSI's bridge actions pass `--log-dir` to the CLI so its log lands where
/// the service writes its own: the directory the wxs names must be
/// `service_log_dir()`, or a failed install's log is somewhere nobody looks.
/// `[CommonAppDataFolder]` is `%ProgramData%` with a trailing backslash.
#[cfg(target_os = "windows")]
#[skuld::test]
fn the_msi_bridge_actions_log_to_the_service_log_dir() {
    const WXS: &str = include_str!("../../../msi-installer/src/msi_installer/hole.wxs");
    const OPEN: &str = "--log-dir &quot;";
    let program_data = std::env::var("ProgramData").expect("ProgramData is set on every Windows host");

    let mut found = 0;
    for (at, _) in WXS.match_indices(OPEN) {
        let rest = &WXS[at + OPEN.len()..];
        let literal = &rest[..rest.find("&quot;").expect("the quoted --log-dir closes")];
        let dir = literal.replace("[CommonAppDataFolder]", &format!("{program_data}\\"));
        assert_eq!(
            std::path::Path::new(&dir),
            service_log_dir(),
            "the wxs names {literal:?}"
        );
        found += 1;
    }
    // install, release-covers, uninstall, and the rollback's install.
    assert_eq!(found, 4, "the bridge actions that carry --log-dir");
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
fn claiming_through_a_link_to_a_folder_the_system_owns_is_refused_and_writes_nothing_there() {
    let root = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let (logs, marker) = log_dir_linked_to_the_system(root.path(), &scratch);
    let before = marker.exists();

    assert!(claim(&logs, &info(1), None).is_err());

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
fn claiming_below_a_link_to_a_folder_the_system_owns_creates_nothing_there() {
    let root = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let link = root.path().join("hole");
    plant_link(scratch.root(), &link);

    assert!(claim(&link.join(scratch.name()).join("logs"), &info(1), None).is_err());

    assert!(!scratch.path().exists(), "something was made in the system's folder");
}

#[skuld::test]
fn claiming_and_clearing_through_a_users_link_to_the_users_folder_work() {
    let root = tempfile::tempdir().unwrap();
    let real = root.path().join("real");
    user_dir(&real);
    let logs = root.path().join("logs");
    plant_link(&real, &logs);

    claim(&logs, &info(1), None).unwrap();
    assert_eq!(present(&real).driver.pid, 1);
    clear(&logs).unwrap();

    assert!(listing(&real).is_empty());
}

#[skuld::test]
fn claim_creates_the_log_dir_when_it_is_missing() {
    let root = tempfile::tempdir().unwrap();
    let logs = root.path().join("hole").join("logs");

    claim(&logs, &info(1), None).unwrap();

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
fn the_marker_goes_to_the_owner_when_the_os_allows() {
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

    claim(dir.path(), &info(1), owner).unwrap();
    assert_eq!(owner_of_marker() == foreign, allowed);
}

// A name the user planted ---------------------------------------------------------------------------------------------
//
// The bridge reads the marker as root or SYSTEM in a log directory the user may own.

fn marker_reader() -> util::dir::testing::Reader<'static> {
    util::dir::testing::Reader {
        file: MARKER_FILE,
        write_valid: &|dir| {
            claim(dir, &info(4242), None).unwrap();
        },
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
    claim(&real, &info(4242), None).unwrap();
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
    claim(tmp.path(), &info(4242), None).unwrap();
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
