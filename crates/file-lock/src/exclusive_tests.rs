use super::*;
use std::io;
use std::path::Path;
use std::sync::mpsc;
use util::dir::testing::{plant_link, user_dir, SystemScratch};

// try_acquire =========================================================================================================

#[skuld::test]
fn try_acquire_succeeds_on_an_unheld_path() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    let guard = Exclusive::try_acquire(&path, None).unwrap();
    assert!(guard.is_some(), "an unheld path must acquire on the first try");
}

#[skuld::test]
fn try_acquire_creates_the_file_if_absent() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    assert!(!path.exists());
    let _guard = Exclusive::try_acquire(&path, None).unwrap().unwrap();
    assert!(path.exists());
}

#[skuld::test]
fn try_acquire_reports_contention_without_blocking_or_erroring() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    let _first = Exclusive::try_acquire(&path, None).unwrap().unwrap();
    // flock is per open file description, so a second open in this process contends.
    let second = Exclusive::try_acquire(&path, None).unwrap();
    assert!(
        second.is_none(),
        "a second try_acquire against an already-held path must report contention, not error or succeed"
    );
}

#[skuld::test]
fn dropping_the_first_guard_frees_the_path_for_a_later_try_acquire() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    let first = Exclusive::try_acquire(&path, None).unwrap().unwrap();
    drop(first);
    let second = Exclusive::try_acquire(&path, None).unwrap();
    assert!(second.is_some(), "releasing the first guard must free the path");
}

#[skuld::test]
#[cfg(unix)]
fn the_lock_file_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    let _guard = Exclusive::try_acquire(&path, None).unwrap().unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "the lock file must be 0600 regardless of umask");
}

/// `Some(owner)` that no unprivileged process owns a file as, and the uid a process would need to be to own one.
#[cfg(unix)]
fn foreign_owner_and_caller() -> ((u32, u32), u32) {
    // SAFETY: getuid takes no arguments and cannot fail.
    let mine = unsafe { libc::getuid() };
    ((mine + 2, mine + 2), mine + 1)
}

#[skuld::test]
#[cfg(unix)]
fn both_entries_hand_the_owner_to_the_vet() {
    use std::os::unix::fs::MetadataExt;
    // The file is ours but the pretend caller is not its owner and the expected
    // owner is someone else: the vet must refuse, and leave the file alone.
    let (owner, pretend) = foreign_owner_and_caller();
    let tmp = tempfile::tempdir().unwrap();

    for entry in ["try_acquire_as", "acquire_as"] {
        let path = tmp.path().join(entry);
        std::fs::write(&path, b"").unwrap();
        let before = std::fs::metadata(&path).unwrap();

        let err = match entry {
            "try_acquire_as" => Exclusive::try_acquire_as(&path, Some(owner), pretend).map(|_| ()),
            _ => Exclusive::acquire_as(&path, Some(owner), pretend).map(|_| ()),
        }
        .expect_err(entry);

        assert!(Refused::from_error(&err).is_some(), "{entry}: {err}");
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!((after.uid(), after.mode()), (before.uid(), before.mode()), "{entry}");
    }
}

#[skuld::test]
#[cfg(unix)]
fn both_entries_hand_the_owner_to_the_fchown() {
    use std::os::unix::fs::MetadataExt;
    // An existing file of our own passes the vet under any `owner`, so a foreign
    // owner is visible only at `fchown`: `EPERM` unprivileged, applied as root;
    // `None` would do neither. The expectation is what the OS says about the
    // same chown on a scratch file, not what the code under test returns.
    let ((foreign, _), _) = foreign_owner_and_caller();
    let tmp = tempfile::tempdir().unwrap();
    let scratch = tmp.path().join("scratch");
    std::fs::write(&scratch, b"").unwrap();
    let chown_allowed = std::os::unix::fs::chown(&scratch, Some(foreign), Some(foreign)).is_ok();

    for entry in ["try_acquire", "acquire"] {
        let path = tmp.path().join(entry);
        std::fs::write(&path, b"").unwrap();

        let result = match entry {
            "try_acquire" => Exclusive::try_acquire(&path, Some((foreign, foreign))).map(|guard| guard.is_some()),
            _ => Exclusive::acquire(&path, Some((foreign, foreign))).map(|_| true),
        };

        match result {
            Ok(acquired) => {
                assert!(
                    chown_allowed,
                    "{entry}: acquired, but the OS would have refused the chown"
                );
                assert!(acquired, "{entry}");
                assert_eq!(
                    std::fs::metadata(&path).unwrap().uid(),
                    foreign,
                    "{entry}: owner not applied"
                );
            }
            Err(err) => {
                assert!(!chown_allowed, "{entry}: failed although the chown is allowed: {err}");
                assert!(
                    Refused::from_error(&err).is_none(),
                    "{entry}: our own file must not be refused for a foreign owner: {err}"
                );
            }
        }
    }
}

// acquire (blocking) ==================================================================================================

/// What names the calling thread to [`wait_until_blocked`]: its kernel thread id on Linux, nothing elsewhere.
#[cfg(target_os = "linux")]
fn this_thread() -> libc::c_long {
    // SAFETY: gettid takes no arguments and cannot fail.
    unsafe { libc::syscall(libc::SYS_gettid) }
}
#[cfg(not(target_os = "linux"))]
fn this_thread() -> i64 {
    0
}

/// Returns once the kernel shows `thread` (of this process) blocked in `flock`, which is the proof that its `acquire`
/// is waiting on a lock somebody holds. The wait re-checks that, with no bound: if `acquire` returned instead,
/// `waiter` is finished and the test fails. Linux only (`/proc/<pid>/task/<tid>/syscall`); other platforms have no such
/// view, so they get only the mutual-exclusion check in the test, which sees an early return only when it happens
/// before the holder lets go.
#[cfg(target_os = "linux")]
fn wait_until_blocked(thread: libc::c_long, waiter: &std::thread::JoinHandle<()>) {
    let file = format!("/proc/self/task/{thread}/syscall");
    loop {
        assert!(!waiter.is_finished(), "acquire returned while the holder held the lock");
        let state = match std::fs::read_to_string(&file) {
            Ok(state) => state,
            // The thread ended between the check and the read.
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                panic!("acquire returned while the holder held the lock")
            }
            Err(err) => panic!("{file}: {err}"),
        };
        let syscall = state
            .split_whitespace()
            .next()
            .and_then(|n| n.parse::<libc::c_long>().ok());
        if syscall == Some(libc::SYS_flock) {
            return;
        }
        std::thread::yield_now();
    }
}
#[cfg(not(target_os = "linux"))]
fn wait_until_blocked(_thread: i64, _waiter: &std::thread::JoinHandle<()>) {}

#[skuld::test]
fn acquire_blocks_until_the_holder_releases() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    let holding = Arc::new(AtomicBool::new(true));

    // Channels, not sleeps, order the threads.
    let (holding_tx, holding_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder_holding = Arc::clone(&holding);
    let holder = std::thread::spawn(move || {
        let guard = Exclusive::try_acquire(&holder_path, None).unwrap().unwrap();
        holding_tx.send(()).unwrap();
        release_rx.recv().unwrap();
        holder_holding.store(false, Ordering::SeqCst);
        drop(guard);
    });
    holding_rx.recv().unwrap();

    let (entering_tx, entering_rx) = mpsc::channel();
    let (acquired_tx, acquired_rx) = mpsc::channel::<bool>();
    let waiter_path = path.clone();
    let waiter_holding = Arc::clone(&holding);
    let waiter = std::thread::spawn(move || {
        entering_tx.send(this_thread()).unwrap();
        let _guard = Exclusive::acquire(&waiter_path, None).unwrap();
        acquired_tx.send(waiter_holding.load(Ordering::SeqCst)).unwrap();
    });
    let waiting = entering_rx.recv().unwrap();

    assert!(
        Exclusive::try_acquire(&path, None).unwrap().is_none(),
        "the lock must be held while the waiter waits"
    );
    wait_until_blocked(waiting, &waiter);
    release_tx.send(()).unwrap();

    assert!(
        !acquired_rx.recv().unwrap(),
        "acquire returned while the holder still held the lock"
    );
    holder.join().unwrap();
    waiter.join().unwrap();
}

// Hostile lock path ===================================================================================================
//
// The lock lives in a directory another principal may write, so whatever sits at
// the lock name when we open it is attacker-chosen. Each test plants something
// there and asserts a refusal that names the path and changes nothing.

/// `Some(owner)` when `fchown` to it is observable (running as root), else `None`.
fn observable_owner() -> Option<(u32, u32)> {
    #[cfg(unix)]
    {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return Some((4242, 4242));
        }
    }
    None
}

/// Runs both entry points against `path` and returns each one's error; panics if either acquires.
fn both_entries_fail(path: &Path, owner: Option<(u32, u32)>) -> [(&'static str, io::Error); 2] {
    let attempts = [
        ("try_acquire", Exclusive::try_acquire(path, owner).map(|_| ())),
        ("acquire", Exclusive::acquire(path, owner).map(|_| ())),
    ];
    attempts.map(|(entry, result)| {
        let err = result.expect_err(&format!("{entry} must refuse {}", path.display()));
        (entry, err)
    })
}

/// Asserts both entry points refuse `path` with a [`Refused`] that carries the path
/// but whose `Display` and `Debug` do not.
fn assert_refused(path: &Path, owner: Option<(u32, u32)>) {
    let shown = path.to_string_lossy();
    for (entry, err) in both_entries_fail(path, owner) {
        let refused = Refused::from_error(&err).unwrap_or_else(|| panic!("{entry}: not a Refused: {err:?}"));
        assert_eq!(refused.path(), path, "{entry}");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{entry}");
        assert!(
            !err.to_string().contains(&*shown),
            "{entry}: Display must not carry the path, got: {err}"
        );
        assert!(
            !format!("{err:?}").contains(&*shown),
            "{entry}: Debug must not carry the path, got: {err:?}"
        );
    }
}

fn symlink(target: &Path, link: &Path) {
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(target, link);
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_file(target, link);
    // Never a skip: a host that cannot make a symlink cannot run this defense's test.
    made.expect("creating a symlink needs admin or Developer Mode on Windows; this test does not skip");
}

#[skuld::test]
fn a_lock_path_that_is_a_symlink_is_refused_and_its_target_left_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim.json");
    std::fs::write(&victim, b"not a lock file").unwrap();
    let path = tmp.path().join("target.json.lock");
    symlink(&victim, &path);

    assert_refused(&path, None);

    assert_eq!(std::fs::read(&victim).unwrap(), b"not a lock file");
}

#[skuld::test]
fn a_lock_path_that_is_a_dangling_symlink_is_refused_and_its_target_not_created() {
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim.json");
    let path = tmp.path().join("target.json.lock");
    symlink(&victim, &path);

    assert_refused(&path, None);

    assert!(
        std::fs::symlink_metadata(&victim).is_err(),
        "a privileged open must not create the file a planted symlink points at"
    );
}

#[skuld::test]
fn a_lock_path_that_is_a_second_name_for_another_file_never_changes_that_file() {
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim.json");
    std::fs::write(&victim, b"not a lock file").unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::hard_link(&victim, &path).unwrap();

    #[cfg(unix)]
    let before = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::metadata(&victim).unwrap()
    };

    match observable_owner() {
        // Not root: no owner is expected, so the file is locked where it is and not modified.
        None => {
            let _guard = Exclusive::try_acquire(&path, None)
                .unwrap()
                .expect("a file with a second name is a lock file like any other");
        }
        // Root: the victim is owned by this process but not by the expected owner, so the
        // name is replaced by a fresh file and the victim is untouched.
        Some(owner) => {
            let _guard = Exclusive::try_acquire(&path, Some(owner)).unwrap().unwrap();
            assert_ne!(
                std::fs::read(&path).unwrap(),
                b"not a lock file",
                "the lock must not be the victim"
            );
        }
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let after = std::fs::metadata(&victim).unwrap();
        assert_eq!(
            after.mode(),
            before.mode(),
            "the linked file must not be re-permissioned"
        );
        assert_eq!(
            (after.uid(), after.gid()),
            (before.uid(), before.gid()),
            "the linked file must not be chowned"
        );
    }
    assert_eq!(std::fs::read(&victim).unwrap(), b"not a lock file");
}

#[skuld::test]
#[cfg(windows)]
fn the_lock_name_cannot_be_removed_or_renamed_while_it_is_held() {
    // ERROR_SHARING_VIOLATION: the handle does not share DELETE, so the name the vet
    // looked at stays bound to the file for as long as the lock is held.
    const SHARING_VIOLATION: i32 = 32;
    let tmp = tempfile::tempdir().unwrap();
    for (case, existing) in [("created", false), ("reopened", true)] {
        let path = tmp.path().join(case);
        if existing {
            std::fs::write(&path, b"").unwrap();
        }
        let guard = Exclusive::try_acquire(&path, None).unwrap().unwrap();

        let removed = std::fs::remove_file(&path).expect_err(case);
        let renamed = std::fs::rename(&path, tmp.path().join("moved")).expect_err(case);

        assert_eq!(
            removed.raw_os_error(),
            Some(SHARING_VIOLATION),
            "{case}: remove: {removed}"
        );
        assert_eq!(
            renamed.raw_os_error(),
            Some(SHARING_VIOLATION),
            "{case}: rename: {renamed}"
        );
        assert!(path.exists(), "{case}");
        drop(guard);
        std::fs::remove_file(&path).expect("a released lock file can be removed");
    }
}

#[skuld::test]
fn a_lock_path_that_is_a_directory_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::create_dir(&path).unwrap();

    assert_refused(&path, None);

    assert!(path.is_dir(), "a refused directory must be left in place");
}

#[skuld::test]
#[cfg(unix)]
fn a_lock_path_that_is_a_socket_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("s");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();

    assert_refused(&path, None);
}

#[skuld::test]
#[cfg(unix)]
fn a_lock_path_that_is_a_fifo_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    let c_path = std::ffi::CString::new(path.to_str().unwrap()).unwrap();
    // SAFETY: `c_path` is a valid NUL-terminated string for the duration of the call.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o644) }, 0);

    assert_refused(&path, observable_owner());
}

#[skuld::test]
#[cfg(unix)]
fn a_lock_file_left_owned_by_this_process_does_not_lock_the_owner_out() {
    use std::os::unix::fs::MetadataExt;
    // As root, this file stands in for the one a bridge that died before its `fchown` left
    // behind. Unprivileged, the expected owner is the caller itself and the file is kept.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"leftover").unwrap();
    // SAFETY: getuid/getgid take no arguments and cannot fail.
    let owner = observable_owner().unwrap_or_else(|| unsafe { (libc::getuid(), libc::getgid()) });

    let guard = Exclusive::try_acquire(&path, Some(owner)).unwrap();

    assert!(guard.is_some());
    assert_eq!(std::fs::metadata(&path).unwrap().uid(), owner.0);
    if observable_owner().is_some() {
        assert_eq!(
            std::fs::read(&path).unwrap(),
            b"",
            "a root-owned leftover must be replaced"
        );
    }
}

#[skuld::test]
#[cfg(unix)]
fn an_existing_wider_lock_file_of_the_expected_owner_is_tightened_not_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
    // SAFETY: getuid/getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };

    let _guard = Exclusive::try_acquire(&path, Some((uid, gid))).unwrap().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}

#[skuld::test]
#[cfg(unix)]
fn an_existing_file_is_not_re_permissioned_when_no_owner_is_expected() {
    // Without an owner there is no proof the file is ours to change, so it is only locked.
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let _guard = Exclusive::try_acquire(&path, None).unwrap().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o666);
}

// Hostile lock directory ==============================================================================================
//
// The directory part of the path is as attacker-writable as the name: every component under the
// user's profile is theirs to replace. Nothing may be created or changed outside the directory the
// path names, and the refusal names the lock path.

#[cfg(unix)]
fn entries(dir: &Path) -> Vec<std::ffi::OsString> {
    let mut found: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name())
        .collect();
    found.sort();
    found
}

#[skuld::test]
fn a_lock_directory_that_is_a_link_to_a_folder_the_system_owns_is_refused_and_nothing_is_made_there() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let state = tmp.path().join("state");
    plant_link(scratch.root(), &state);
    let lock = format!("{}.lock", scratch.name().to_string_lossy());

    assert_refused(&state.join(&lock), observable_owner());

    assert!(
        !scratch.root().join(&lock).exists(),
        "a lock file was made in the system's folder"
    );
}

#[skuld::test]
fn a_link_among_the_parents_of_the_lock_directory_leads_nowhere_in_the_systems_folder() {
    let tmp = tempfile::tempdir().unwrap();
    let scratch = SystemScratch::new();
    let hole = tmp.path().join("hole");
    plant_link(scratch.root(), &hole);

    for path in [
        hole.join(scratch.name()).join("target.json.lock"),
        hole.join(scratch.name()).join("state").join("target.json.lock"),
    ] {
        assert_refused(&path, observable_owner());
    }

    assert!(!scratch.path().exists(), "a folder was made in the system's folder");
}

#[skuld::test]
fn a_lock_directory_reached_through_a_users_link_to_the_users_folder_is_locked() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    user_dir(&real);
    let state = tmp.path().join("state");
    plant_link(&real, &state);
    // As root the lock is given to nobody, whose folder this is; as anyone else the owner is no one.
    let owner = observable_owner().map(|_| (65534, 65534));

    let _guard = Exclusive::try_acquire(&state.join("target.json.lock"), owner)
        .unwrap()
        .expect("a link to the user's own folder is followed");

    assert!(real.join("target.json.lock").is_file());
}

#[skuld::test]
fn missing_directories_are_created_for_the_lock() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("a").join("b").join("target.json.lock");

    for entry in ["try_acquire", "acquire"] {
        let _guard = match entry {
            "try_acquire" => Exclusive::try_acquire(&path, None).unwrap().unwrap(),
            _ => Exclusive::acquire(&path, None).unwrap(),
        };
        assert!(path.is_file(), "{entry}");
    }
}

#[skuld::test]
#[cfg(unix)]
fn a_lock_directory_owned_by_a_third_party_is_refused_and_nothing_is_made_in_it() {
    // The directory is ours but the pretend caller is someone else and the expected owner a third.
    let (owner, pretend) = foreign_owner_and_caller();
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");

    for entry in ["try_acquire_as", "acquire_as"] {
        let err = match entry {
            "try_acquire_as" => Exclusive::try_acquire_as(&path, Some(owner), pretend).map(|_| ()),
            _ => Exclusive::acquire_as(&path, Some(owner), pretend).map(|_| ()),
        }
        .expect_err(entry);

        let refused = Refused::from_error(&err).unwrap_or_else(|| panic!("{entry}: not a Refused: {err:?}"));
        assert_eq!(refused.path(), path, "{entry}");
    }
    assert!(
        entries(tmp.path()).is_empty(),
        "a lock file was made in a refused directory"
    );
}
