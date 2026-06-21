//! Cross-uid ownership proofs for #572 — need real root to give a file to
//! another uid. Rides the macOS root lane (`SKULD_LABELS=tun`, sudo). NOT
//! `#[ignore]`d; an unprivileged run asserts the EPERM / self-owned direction
//! and PASSES. Covers both the bare `chown_path` primitive and the cutover
//! marker's `owner` threading reaching the published inode.

hole_test_observability::register!();
fn main() {
    skuld::run_all();
}

#[skuld::label]
const TUN: skuld::Label;

#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn chown_gives_file_to_invoking_user_under_root() {
    use std::os::unix::fs::MetadataExt;
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("f");
    std::fs::write(&f, b"x").unwrap();
    let (uid, gid) = (unsafe { libc::getuid() }, unsafe { libc::getgid() });
    if unsafe { libc::geteuid() } == 0 {
        util::ownership::chown_path(&f, uid, gid).expect("root chowns to the invoking user");
        assert_eq!(std::fs::metadata(&f).unwrap().uid(), uid);
    } else {
        assert_eq!(
            util::ownership::chown_path(&f, 0, 0).unwrap_err().raw_os_error(),
            Some(libc::EPERM)
        );
    }
}

/// `nobody`'s uid/gid — a guaranteed-present non-root account on macOS — for the
/// cross-uid proof. A FIXED non-self target so the assertion discriminates: the
/// running process never owns the published marker by accident.
#[cfg(target_os = "macos")]
fn nobody() -> (u32, u32) {
    // SAFETY: `getpwnam` with a static NUL-terminated string; the returned passwd
    // is read immediately, not retained past the next libc call.
    let pw = unsafe { libc::getpwnam(c"nobody".as_ptr()) };
    assert!(!pw.is_null(), "macOS always has a `nobody` account");
    unsafe { ((*pw).pw_uid, (*pw).pw_gid) }
}

/// The cutover-marker `owner` must land on the PUBLISHED inode for BOTH writers:
/// `write` (temp → rename) and `write_new` (temp → hard_link). Drives the real
/// `hole_common::update_marker` path to a FIXED foreign uid (`nobody`), so the
/// assertion fails if the chown is dropped or moved off the published inode.
/// Under root the chown succeeds and the marker is `nobody`-owned; unprivileged,
/// the foreign chown is EPERM (swallowed by `chown_if_some`) so the write still
/// succeeds and the marker stays self-owned — the contract holds either way.
#[cfg(target_os = "macos")]
#[skuld::test(labels = [TUN], serial = TUN)]
fn cutover_marker_is_chowned_to_owner_under_root() {
    use hole_common::update_marker::{self, MarkerInfo, MARKER_FILE, MARKER_VERSION};
    use std::os::unix::fs::MetadataExt;

    let info = |to: &str| MarkerInfo {
        version: MARKER_VERSION,
        from_version: "0.2.0".into(),
        to_version: to.into(),
        pid: std::process::id(),
        started_at_unix: 0,
    };
    let root = unsafe { libc::geteuid() } == 0;
    let (nuid, ngid) = nobody();
    let me = unsafe { libc::getuid() };

    // write (rename publish).
    let d = tempfile::tempdir().unwrap();
    update_marker::write(d.path(), &info("0.3.0"), Some((nuid, ngid))).unwrap();
    let owner = std::fs::metadata(d.path().join(MARKER_FILE)).unwrap().uid();
    if root {
        assert_eq!(owner, nuid, "root: write must chown the published marker to owner");
    } else {
        assert_eq!(
            owner, me,
            "unprivileged: foreign chown is swallowed, marker stays self-owned"
        );
    }

    // write_new (hard_link publish), via a fresh dir so the claim is unclaimed.
    let d = tempfile::tempdir().unwrap();
    update_marker::write_new(d.path(), &info("0.3.0"), Some((nuid, ngid))).unwrap();
    let owner = std::fs::metadata(d.path().join(MARKER_FILE)).unwrap().uid();
    if root {
        assert_eq!(owner, nuid, "root: write_new must chown the claimed marker to owner");
    } else {
        assert_eq!(
            owner, me,
            "unprivileged: foreign chown is swallowed, marker stays self-owned"
        );
    }
}
