use super::*;
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
fn try_acquire_refuses_a_symlinked_path() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("elsewhere.json");
    std::fs::write(&real, b"not a lock file").unwrap();
    let link = tmp.path().join("target.json.lock");
    std::os::unix::fs::symlink(&real, &link).unwrap();

    let result = Exclusive::try_acquire(&link, None);
    assert!(
        result.is_err(),
        "a symlinked lock path must be refused (O_NOFOLLOW), never silently followed"
    );
}

#[skuld::test]
#[cfg(unix)]
fn try_acquire_chowns_the_fd_to_the_given_owner() {
    // No root locally, so a *different*-owner chown cannot be exercised here
    // (disclosed, not mocked — see the deputy's gotcha list). Chowning to the
    // caller's own current uid/gid is always permitted without privilege and
    // still exercises the `Some(owner)` code path end-to-end.
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

/// Runs `open` through both entry points and asserts each refuses `path`, naming it.
fn assert_refused(path: &Path, owner: Option<(u32, u32)>) {
    let attempts = [
        ("try_acquire", Exclusive::try_acquire(path, owner).map(|_| ())),
        ("acquire", Exclusive::acquire(path, owner).map(|_| ())),
    ];
    for (entry, result) in attempts {
        let err = result.expect_err(&format!("{entry} must refuse {}", path.display()));
        assert!(
            err.to_string().contains(&*path.to_string_lossy()),
            "{entry}: the refusal must name the path, got: {err}"
        );
    }
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
