use crate::embedded::{runtime_dir, EmbeddedBinary};

const TEST_DATA: &[u8] = b"#!/bin/sh\necho hello\n";

#[skuld::test]
fn runtime_dir_is_public() {
    // Compile-time guard: runtime_dir is pub so main() can source the crash
    // marker dir. A regression to private fails to compile here.
    let _f: fn() -> anyhow::Result<std::path::PathBuf> = runtime_dir;
}

fn test_sha256(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

#[skuld::test]
fn cold_start_extracts_and_verifies() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let verified = binary.prepare_in(dir.path()).unwrap();
    assert!(verified.fs_path().exists());
}

#[skuld::test]
fn warm_start_reuses_existing() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let v1 = binary.prepare_in(dir.path()).unwrap();
    let fs_path1 = v1.fs_path().to_path_buf();
    drop(v1);
    let v2 = binary.prepare_in(dir.path()).unwrap();
    assert_eq!(v2.fs_path(), fs_path1);
}

#[skuld::test]
fn hash_mismatch_re_extracts() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    let v1 = binary.prepare_in(dir.path()).unwrap();
    let fs_path = v1.fs_path().to_path_buf();
    drop(v1);
    // Make writable before tampering (file was extracted with 0o500 on Unix)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fs_path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }
    std::fs::write(&fs_path, b"tampered content").unwrap();
    let v2 = binary.prepare_in(dir.path()).unwrap();
    let content = std::fs::read(v2.fs_path()).unwrap();
    assert_eq!(content, TEST_DATA);
}

#[skuld::test]
fn wrong_embedded_hash_fails() {
    let dir = tempfile::tempdir().unwrap();
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: [0u8; 32],
    };
    let result = binary.prepare_in(dir.path());
    assert!(result.is_err());
}

// Opening what is hashed ==============================================================================================

fn test_binary() -> EmbeddedBinary {
    EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    }
}

/// A file another process holds open for writing is not one that can be pinned: a warm start replaces it, as it does
/// a file that is not these bytes. (A writer that shares delete is replaced under; the writer keeps what is now an
/// unnamed file.) No instance of galoshes is such a writer: instances take turns, see `prepare_in`.
#[cfg(windows)]
#[skuld::test]
fn a_file_another_process_holds_open_for_writing_is_replaced() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test-bin");
    std::fs::write(&path, TEST_DATA).unwrap();
    let _writer = std::fs::OpenOptions::new().write(true).open(&path).unwrap();

    let verified = test_binary().prepare_in(dir.path()).unwrap();

    assert_eq!(std::fs::read(verified.fs_path()).unwrap(), TEST_DATA);
}

/// A foreign holder that does not let the name be replaced is an error with its cause, not a start on a file that is
/// not pinned.
#[cfg(windows)]
#[skuld::test]
fn a_holder_that_denies_replacing_the_file_fails_the_start_with_its_cause() {
    use std::os::windows::fs::OpenOptionsExt;
    // FILE_SHARE_READ | FILE_SHARE_WRITE: no FILE_SHARE_DELETE.
    const SHARE_READ_WRITE: u32 = 0x1 | 0x2;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("test-bin");
    std::fs::write(&path, TEST_DATA).unwrap();
    let _writer = std::fs::OpenOptions::new()
        .write(true)
        .share_mode(SHARE_READ_WRITE)
        .open(&path)
        .unwrap();

    let err = test_binary()
        .prepare_in(dir.path())
        .err()
        .expect("a held file is not pinned");

    let chain = format!("{err:#}");
    assert!(chain.contains("failed to extract"), "{chain}");
}

/// Instances take turns through a lock file beside the binary. A directory planted at its name is refused by the lock's
/// own open rules, which only a start that takes the lock can show.
#[skuld::test]
fn the_start_takes_a_lock_named_for_the_binary() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::create_dir(dir.path().join("test-bin.lock")).unwrap();

    let err = test_binary()
        .prepare_in(dir.path())
        .err()
        .expect("the lock cannot be taken");

    assert!(
        util::error::find::<file_lock::Refused>(err.as_ref()).is_some(),
        "{err:#}"
    );
}

/// Instances starting together in one folder all end up holding the one binary: each is either the instance whose
/// extraction wins or finds that file verified.
#[skuld::test]
fn instances_starting_together_all_get_the_binary() {
    const INSTANCES: usize = 4;
    let dir = tempfile::tempdir().unwrap();
    let start = std::sync::Barrier::new(INSTANCES);

    let results: Vec<_> = std::thread::scope(|scope| {
        let starts: Vec<_> = (0..INSTANCES)
            .map(|_| {
                scope.spawn(|| {
                    start.wait();
                    test_binary().prepare_in(dir.path())
                })
            })
            .collect();
        starts.into_iter().map(|start| start.join().unwrap()).collect()
    });

    for result in results {
        let verified = result.unwrap_or_else(|err| panic!("an instance failed to start: {err:#}"));
        assert_eq!(std::fs::read(verified.fs_path()).unwrap(), TEST_DATA);
    }
}

/// A FIFO at the name must be replaced, not read: a read by path blocks forever on one nobody writes to.
#[cfg(unix)]
#[skuld::test]
fn a_fifo_at_the_name_is_replaced_not_read() {
    use std::os::unix::fs::FileTypeExt;
    let dir = tempfile::tempdir().unwrap();
    let name = std::ffi::CString::new(dir.path().join("test-bin").to_str().unwrap()).unwrap();
    // SAFETY: `name` is a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);

    let verified = test_binary().prepare_in(dir.path()).unwrap();

    let kind = std::fs::symlink_metadata(verified.fs_path()).unwrap().file_type();
    assert!(!kind.is_fifo() && kind.is_file(), "{kind:?}");
}

/// A link at the name is not followed, even to a file with the right bytes: the name is replaced by a regular file.
#[cfg(unix)]
#[skuld::test]
fn a_symlink_at_the_name_is_replaced_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    let decoy = elsewhere.path().join("decoy");
    std::fs::write(&decoy, TEST_DATA).unwrap();
    std::os::unix::fs::symlink(&decoy, dir.path().join("test-bin")).unwrap();

    let verified = test_binary().prepare_in(dir.path()).unwrap();

    assert!(std::fs::symlink_metadata(verified.fs_path()).unwrap().is_file());
    assert_eq!(std::fs::read(&decoy).unwrap(), TEST_DATA, "the decoy is untouched");
}

/// A file with the right bytes that another principal can still write to is not what is run: the writer can change
/// it between the hash and the exec through the very handle the hash used. It is replaced by a file only we can write.
#[cfg(unix)]
#[skuld::test]
fn a_file_others_can_write_is_replaced() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("test-bin");
    std::fs::write(&target, TEST_DATA).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o666)).unwrap();

    let verified = test_binary().prepare_in(dir.path()).unwrap();

    let mode = std::fs::metadata(verified.fs_path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o022, 0, "mode {mode:o}");
}

/// The handle `prepare_in` keeps pins the file's own name: a swap of that name while the binary is held is refused.
#[cfg(windows)]
#[skuld::test]
fn a_held_binary_cannot_be_replaced_or_deleted() {
    let dir = tempfile::tempdir().unwrap();
    let verified = test_binary().prepare_in(dir.path()).unwrap();
    let other = dir.path().join("other");
    std::fs::write(&other, b"replacement").unwrap();

    assert!(
        std::fs::rename(&other, verified.fs_path()).is_err(),
        "replace by rename"
    );
    assert!(std::fs::remove_file(verified.fs_path()).is_err(), "delete");
    assert!(std::fs::write(verified.fs_path(), b"x").is_err(), "write");
    assert_eq!(std::fs::read(verified.fs_path()).unwrap(), TEST_DATA);
}

/// Linux execs the descriptor the hash was read through, so a swap of the name after `prepare_in` runs nothing else.
#[cfg(target_os = "linux")]
#[skuld::test]
fn exec_path_is_the_hashed_inode_after_the_name_is_swapped() {
    let dir = tempfile::tempdir().unwrap();
    let verified = test_binary().prepare_in(dir.path()).unwrap();
    let other = dir.path().join("other");
    std::fs::write(&other, b"replacement").unwrap();
    std::fs::rename(&other, verified.fs_path()).unwrap();

    assert_eq!(std::fs::read(verified.exec_path()).unwrap(), TEST_DATA);
}

/// A file that has the right bytes but cannot be run (no exec bit) is replaced: a warm start that took it would fail
/// to spawn on every start after.
#[cfg(unix)]
#[skuld::test]
fn a_file_without_the_exec_bit_is_replaced() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let target = dir.path().join("test-bin");
    std::fs::write(&target, TEST_DATA).unwrap();
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600)).unwrap();

    let verified = test_binary().prepare_in(dir.path()).unwrap();

    let mode = std::fs::metadata(verified.fs_path()).unwrap().permissions().mode();
    assert_eq!(mode & 0o100, 0o100, "mode {mode:o}");
}

/// What is run is the file whose real path was pinned, whatever a link on the way to it is made to mean afterwards: a
/// junction retargeted to a folder holding other bytes under the same name changes nothing.
#[cfg(windows)]
#[skuld::test]
fn exec_path_is_the_pinned_file_after_a_junction_on_the_path_is_retargeted() {
    use util::dir::testing::{plant_link, user_dir};
    let root = tempfile::tempdir().unwrap();
    let hashed = root.path().join("hashed");
    let decoy = root.path().join("decoy");
    user_dir(&hashed);
    user_dir(&decoy);
    std::fs::write(decoy.join("test-bin"), b"other bytes").unwrap();
    let link = root.path().join("link");
    plant_link(&hashed, &link);

    let verified = test_binary().prepare_in(&link).unwrap();
    std::fs::remove_dir(&link).unwrap();
    plant_link(&decoy, &link);

    assert_eq!(std::fs::read(verified.exec_path()).unwrap(), TEST_DATA);
}

// Resolution ==========================================================================================================

/// One directory per principal: a run as root never shares a path with the user's.
#[cfg(unix)]
#[skuld::test]
fn resolve_prefers_xdg_runtime_dir_and_names_the_principal() {
    use crate::embedded::resolve;
    let xdg = std::path::Path::new("/run/user/1000");
    let home = std::path::Path::new("/home/x");
    assert_eq!(
        resolve(Some(xdg), || Some(home.to_path_buf()), 1000).unwrap(),
        std::path::PathBuf::from("/run/user/1000/galoshes-1000")
    );
    // `sudo -E` leaves the user's XDG_RUNTIME_DIR in place: root still gets a directory of its own.
    assert_eq!(
        resolve(Some(xdg), || Some(home.to_path_buf()), 0).unwrap(),
        std::path::PathBuf::from("/run/user/1000/galoshes-0")
    );
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn resolve_linux_falls_back_to_home_cache() {
    use crate::embedded::resolve;
    let path = resolve(None, || Some("/home/x".into()), 1000).unwrap();
    assert_eq!(path, std::path::PathBuf::from("/home/x/.cache/galoshes-1000"));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn resolve_macos_falls_back_to_library_caches() {
    use crate::embedded::resolve;
    let path = resolve(None, || Some("/Users/x".into()), 501).unwrap();
    assert_eq!(path, std::path::PathBuf::from("/Users/x/Library/Caches/galoshes-501"));
}

/// The default root is the running account's home, never `$HOME`, which names whoever launched the process.
#[cfg(unix)]
#[skuld::test]
fn the_default_root_is_the_effective_users_account_home() {
    use std::os::unix::fs::MetadataExt;
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let home = crate::embedded::account_home(euid).unwrap();
    assert!(home.is_absolute(), "{home:?}");
    if euid != 0 {
        assert_eq!(std::fs::metadata(&home).unwrap().uid(), euid);
    } else if cfg!(target_os = "macos") {
        assert_eq!(home, std::path::PathBuf::from("/var/root"));
    }
}

/// A uid no account holds (containers run with `--user <n>`, OpenShift assigns one): the launcher's `$HOME` is the home.
#[cfg(unix)]
#[skuld::test]
fn a_uid_with_no_account_falls_back_to_home() {
    use crate::embedded::{account_home, default_home};
    // Far above any range an account database allocates from.
    const NO_ACCOUNT: u32 = 2_999_999_977;
    assert_eq!(account_home(NO_ACCOUNT), None, "the test's uid must have no account");
    assert_eq!(
        default_home(NO_ACCOUNT, Some("/from/env".into())),
        Some(std::path::PathBuf::from("/from/env"))
    );
    assert_eq!(default_home(NO_ACCOUNT, None), None);
}

/// An account holds a home: `$HOME`, which `sudo -E` leaves at the invoking user's, is not consulted.
#[cfg(unix)]
#[skuld::test]
fn an_account_home_wins_over_home() {
    use crate::embedded::{account_home, default_home};
    // SAFETY: geteuid takes no arguments and cannot fail.
    let euid = unsafe { libc::geteuid() };
    let account = account_home(euid).expect("the running user has an account");
    assert_eq!(default_home(euid, Some("/from/env".into())), Some(account));
}

/// The home is looked up only when `XDG_RUNTIME_DIR` leaves the choice to it.
#[cfg(unix)]
#[skuld::test]
fn the_home_is_not_looked_up_when_xdg_runtime_dir_decides() {
    use crate::embedded::resolve;
    let path = resolve(
        Some(std::path::Path::new("/run/user/1000")),
        || panic!("home looked up although XDG_RUNTIME_DIR decided"),
        1000,
    )
    .unwrap();
    assert_eq!(path, std::path::PathBuf::from("/run/user/1000/galoshes-1000"));
}

/// A home that is not UTF-8 is still the home: it reaches the path as the bytes it is.
#[cfg(unix)]
#[skuld::test]
fn a_home_that_is_not_utf8_is_kept_as_it_is() {
    use crate::embedded::resolve;
    use std::os::unix::ffi::OsStrExt;
    let home = std::path::Path::new(std::ffi::OsStr::from_bytes(b"/home/\xff"));
    let path = resolve(None, || Some(home.to_path_buf()), 1000).unwrap();
    assert!(path.starts_with(home), "{path:?}");
}

#[cfg(unix)]
#[skuld::test]
fn resolve_bails_when_nothing_resolves() {
    use crate::embedded::resolve;
    let err = resolve(None, || None, 1000).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("XDG_RUNTIME_DIR"),
        "error should name XDG_RUNTIME_DIR: {msg}"
    );
    assert!(
        msg.contains("home directory"),
        "error should name the home directory: {msg}"
    );
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn resolve_windows_prefers_xdg_runtime_dir() {
    use crate::embedded::resolve;
    let path = resolve(
        Some(std::path::Path::new(r"C:\run")),
        Some(std::path::Path::new(r"C:\Users\x\AppData\Local")),
    )
    .unwrap();
    assert_eq!(path, std::path::PathBuf::from(r"C:\run\galoshes"));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn resolve_windows_falls_back_to_localappdata() {
    use crate::embedded::resolve;
    let path = resolve(None, Some(std::path::Path::new(r"C:\Users\x\AppData\Local"))).unwrap();
    assert_eq!(path, std::path::PathBuf::from(r"C:\Users\x\AppData\Local\galoshes"));
}

#[cfg(target_os = "windows")]
#[skuld::test]
fn resolve_windows_bails_when_nothing_resolves() {
    use crate::embedded::resolve;
    let err = resolve(None, None).unwrap_err();
    let msg = format!("{err}");
    assert!(
        msg.contains("XDG_RUNTIME_DIR"),
        "error should name XDG_RUNTIME_DIR: {msg}"
    );
    assert!(msg.contains("LOCALAPPDATA"), "error should name LOCALAPPDATA: {msg}");
}

// Noexec predicate ====================================================================================================

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_passes_on_zero_flag() {
    assert!(!crate::embedded::check_noexec_linux(0));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_detects_st_noexec() {
    assert!(crate::embedded::check_noexec_linux(libc::ST_NOEXEC));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_ignores_st_rdonly() {
    // ST_RDONLY set, ST_NOEXEC clear → not noexec
    assert!(!crate::embedded::check_noexec_linux(libc::ST_RDONLY));
}

#[cfg(target_os = "linux")]
#[skuld::test]
fn check_noexec_linux_detects_st_noexec_combined_with_other_flags() {
    assert!(crate::embedded::check_noexec_linux(libc::ST_NOEXEC | libc::ST_RDONLY));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_passes_on_zero_flag() {
    assert!(!crate::embedded::check_noexec_macos(0));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_detects_mnt_noexec() {
    assert!(crate::embedded::check_noexec_macos(libc::MNT_NOEXEC as u32));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_ignores_mnt_rdonly() {
    assert!(!crate::embedded::check_noexec_macos(libc::MNT_RDONLY as u32));
}

#[cfg(target_os = "macos")]
#[skuld::test]
fn check_noexec_macos_detects_mnt_noexec_combined_with_other_flags() {
    let combined = (libc::MNT_NOEXEC as u32) | (libc::MNT_RDONLY as u32);
    assert!(crate::embedded::check_noexec_macos(combined));
}

// Crash handler =======================================================================================================

/// The folder is made by the extraction's own `prepare`, `0o700`, not by the crash handler with the umask's mode: on
/// macOS a folder group- or other-writable fails the seal on every later start.
#[cfg(unix)]
#[skuld::test]
fn the_crash_handler_leaves_the_folder_the_extraction_made() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("galoshes-1000");

    crate::embedded::attach_crash_handler(&dir);

    let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700, "{dir:?} is {mode:o}");
    let binary = EmbeddedBinary {
        name: "test-bin",
        data: TEST_DATA,
        sha256: test_sha256(TEST_DATA),
    };
    binary.prepare_in(&dir).expect("the extraction uses the folder");
}
