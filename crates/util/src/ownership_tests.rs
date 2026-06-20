#![cfg(target_os = "macos")]

use crate::ownership::{chown_if_some, chown_path};
use skuld::temp_dir;
use std::os::unix::fs::MetadataExt;

fn me() -> (u32, u32) {
    (unsafe { libc::getuid() }, unsafe { libc::getgid() })
}

#[skuld::test]
fn chown_path_to_self_is_a_permitted_noop(#[fixture(temp_dir)] dir: &std::path::Path) {
    let f = dir.join("f");
    std::fs::write(&f, b"x").unwrap();
    let (uid, gid) = me();
    chown_path(&f, uid, gid).expect("chown to self is permitted without root");
    let m = std::fs::metadata(&f).unwrap();
    assert_eq!((m.uid(), m.gid()), (uid, gid));
}

#[skuld::test]
fn chown_path_to_root_without_privilege_is_eperm(#[fixture(temp_dir)] dir: &std::path::Path) {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }
    let f = dir.join("f");
    std::fs::write(&f, b"x").unwrap();
    assert_eq!(chown_path(&f, 0, 0).unwrap_err().raw_os_error(), Some(libc::EPERM));
}

#[skuld::test]
fn chown_if_some_none_is_noop(#[fixture(temp_dir)] dir: &std::path::Path) {
    let f = dir.join("f");
    std::fs::write(&f, b"x").unwrap();
    let before = std::fs::metadata(&f).unwrap().uid();
    chown_if_some(&f, None);
    assert_eq!(std::fs::metadata(&f).unwrap().uid(), before);
}
