use super::*;
use std::io;
use std::path::Path;
use std::sync::mpsc;

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
    // Same path, opened a second time within this one process — flock is
    // scoped to the open file description, not the process, so this
    // genuinely contends rather than trivially re-acquiring.
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

#[skuld::test]
#[cfg(unix)]
fn try_acquire_chowns_the_fd_to_the_given_owner() {
    // A different-owner chown is observable only as root (see
    // `observable_owner` and the hard-link test). Chowning to the caller's own
    // ids is always permitted and still exercises the `Some(owner)` path.
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    // SAFETY: getuid/getgid take no arguments and cannot fail.
    let (uid, gid) = unsafe { (libc::getuid(), libc::getgid()) };
    let guard = Exclusive::try_acquire(&path, Some((uid, gid)));
    assert!(
        guard.is_ok(),
        "chowning to the caller's own ids must succeed without privilege"
    );
}

// acquire (blocking) ==================================================================================================

#[skuld::test]
fn acquire_blocks_until_the_holder_releases() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");

    let (holding_tx, holding_rx) = mpsc::channel::<()>();
    let (release_tx, release_rx) = mpsc::channel::<()>();
    let holder_path = path.clone();
    let holder = std::thread::spawn(move || {
        let guard = Exclusive::try_acquire(&holder_path, None).unwrap().unwrap();
        holding_tx.send(()).unwrap();
        // Real rendezvous, not a sleep: blocks until the main thread signals.
        release_rx.recv().unwrap();
        drop(guard);
    });
    // Blocks until the holder thread actually holds the lock — no poll.
    holding_rx.recv().unwrap();

    let (acquired_tx, acquired_rx) = mpsc::channel::<()>();
    let waiter_path = path.clone();
    let waiter = std::thread::spawn(move || {
        // A genuine kernel-level block: this call does not return until the
        // holder thread's guard drops and releases the flock/LockFileEx lock.
        let _guard = Exclusive::acquire(&waiter_path, None).unwrap();
        acquired_tx.send(()).unwrap();
    });

    // Tell the holder to release, then wait for the waiter to observe it —
    // both rendezvous points are real channel recvs, never a sleep/poll.
    release_tx.send(()).unwrap();
    acquired_rx.recv().unwrap();

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

    both_entries_fail(&path, None);

    assert_eq!(std::fs::read(&victim).unwrap(), b"not a lock file");
}

#[skuld::test]
fn a_lock_path_that_is_a_dangling_symlink_is_refused_and_its_target_not_created() {
    let tmp = tempfile::tempdir().unwrap();
    let victim = tmp.path().join("victim.json");
    let path = tmp.path().join("target.json.lock");
    symlink(&victim, &path);

    both_entries_fail(&path, None);

    assert!(
        std::fs::symlink_metadata(&victim).is_err(),
        "a privileged open must not create the file a planted symlink points at"
    );
}

#[skuld::test]
#[cfg(windows)]
fn a_symlink_at_the_lock_path_is_a_typed_refusal_on_windows() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    symlink(&tmp.path().join("victim.json"), &path);

    assert_refused(&path, None);
}

#[skuld::test]
fn a_lock_path_that_is_a_second_name_for_another_file_is_refused_and_the_file_left_alone() {
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

    assert_refused(&path, observable_owner());

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
#[cfg(windows)]
fn a_lock_path_that_names_a_device_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    // Win32 path normalization turns a reserved device name in any directory into the device.
    assert_refused(&tmp.path().join("NUL"), None);
}

#[skuld::test]
#[cfg(unix)]
fn an_existing_wider_lock_file_of_our_own_is_tightened_not_refused() {
    use std::os::unix::fs::PermissionsExt;
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("target.json.lock");
    std::fs::write(&path, b"").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();

    let _guard = Exclusive::try_acquire(&path, None).unwrap().unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
}
