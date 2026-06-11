//! POSIX `hole`-group session gate (dev.py §5.14): grant-access adds the
//! user to the group on disk, but a login session that predates the change
//! lacks it — the GUI then cannot open the IPC socket. Check and instruct,
//! never silently fail later.

use std::collections::BTreeSet;

/// True if `hole` exists but the current session is not a member.
/// `hole_gid == None` means the group does not exist yet (nothing to check).
pub fn missing_hole_group(hole_gid: Option<u32>, current_gids: &BTreeSet<u32>) -> bool {
    hole_gid.is_some_and(|gid| !current_gids.contains(&gid))
}

/// The platform errno accessor (macOS names it `__error`, glibc
/// `__errno_location`; the crate compiles on linux for the CI archive lane).
#[cfg(target_os = "macos")]
unsafe fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__error() }
}
#[cfg(not(target_os = "macos"))]
unsafe fn errno_ptr() -> *mut libc::c_int {
    unsafe { libc::__errno_location() }
}

/// Look up the `hole` group's gid. `Ok(None)` = group absent;
/// `Err(msg)` = lookup failed transiently (macOS Directory Services) —
/// caller warns and continues (treating it as absent), never crashes.
pub fn hole_gid() -> Result<Option<u32>, String> {
    let name = std::ffi::CString::new("hole").expect("no interior NUL");
    // SAFETY: getgrnam returns a pointer into static storage or null; errno
    // distinguishes "absent" (unchanged) from "lookup error" (set).
    unsafe {
        *errno_ptr() = 0;
        let p = libc::getgrnam(name.as_ptr());
        if !p.is_null() {
            return Ok(Some((*p).gr_gid));
        }
        let errno = *errno_ptr();
        if errno == 0 {
            Ok(None)
        } else {
            Err(std::io::Error::from_raw_os_error(errno).to_string())
        }
    }
}

/// Effective + real + supplementary gids (the union dev.py builds —
/// getgroups alone can omit the primary/effective gid).
pub fn current_gids() -> BTreeSet<u32> {
    let mut gids = BTreeSet::new();
    // SAFETY: getgid/getegid never fail; getgroups with a sized buffer is
    // the documented two-call pattern.
    unsafe {
        gids.insert(libc::getgid());
        gids.insert(libc::getegid());
        let n = libc::getgroups(0, std::ptr::null_mut());
        if n > 0 {
            let mut buf = vec![0 as libc::gid_t; n as usize];
            let got = libc::getgroups(n, buf.as_mut_ptr());
            if got >= 0 {
                buf.truncate(got as usize);
                gids.extend(buf);
            }
        }
    }
    gids
}

#[cfg(test)]
#[path = "group_gate_tests.rs"]
mod group_gate_tests;
