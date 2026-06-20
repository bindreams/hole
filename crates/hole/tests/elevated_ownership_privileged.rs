//! Cross-uid ownership proof for #572 — needs real root to give a file to
//! another uid. Rides the macOS root lane (`SKULD_LABELS=tun`, sudo). NOT
//! `#[ignore]`d; an unprivileged run asserts the EPERM direction and PASSES.

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
