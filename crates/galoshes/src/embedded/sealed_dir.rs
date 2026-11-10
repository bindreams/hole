//! The directory the embedded binary is extracted into, and when it may be exec'd from by name.
//!
//! The directory is the running principal's alone (`galoshes-<euid>`, see `runtime_dir`), so nothing a run as another
//! principal does leaves anything in it. galoshes can still run as root with a runtime directory under a user's profile.
//! Linux and Windows exec what was hashed (the open handle, or the real path it pins), so the directory does not matter
//! to them. macOS cannot exec a descriptor, so the exec resolves the name again and anyone who can rename an entry on
//! the way to it can swap the binary after the hash. There the directory is accepted only if no one but the running
//! user (and root) can: every component of its resolved path is owned by the running user or by root, is not writable by
//! group or other and is not on a volume that ignores ownership, and the directory itself is the running user's. Under
//! root that means a root-owned path, which is why a user's home is refused. An ACL on a component is its owner's own
//! grant and is not inspected. A directory that fails this is never repaired or moved: one planted by someone else is
//! judged as it is. One made by [`prepare`] is made `0o700` in the `mkdirat`.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use util::dir::Dir;

/// Whether the exec resolves the name again, so that the directory must be sealed.
#[cfg(unix)]
pub(super) const EXEC_BY_PATH: bool = !cfg!(target_os = "linux");

/// The extraction directory, opened once: everything done in it goes through `dir`, which no rename of a name on the
/// way to it can move.
pub(super) struct SealedDir {
    dir: Dir,
    /// The directory as exec'd from by name where that applies (resolved, and sealed), else as given.
    path: PathBuf,
}

impl SealedDir {
    pub(super) fn dir(&self) -> &Dir {
        &self.dir
    }

    pub(super) fn path(&self) -> &Path {
        &self.path
    }
}

/// Opens `given`, creating it if missing, walking it through handles. A directory that already exists is judged as it
/// is: opened if the OS lets the user, and refused where the exec resolves the name and it is not sealed. One made here
/// is made [`PRIVATE_MODE`], so no one sees it with the umask's mode first. Windows has no mode.
pub(super) fn prepare(given: &Path) -> Result<SealedDir> {
    let dir = Dir::open_with_leaf_mode(given, PRIVATE_MODE)
        .with_context(|| format!("failed to open directory {}", given.display()))?;
    let path = exec_dir(&dir, given)?;
    Ok(SealedDir { dir, path })
}

/// The mode of a directory this module makes: the running user's alone.
const PRIVATE_MODE: u32 = 0o700;

/// The directory to exec the binary from. Where the exec resolves the name again, the path the held handle resolves
/// to, which is then checked and used from here on, so a name swapped afterwards cannot lead the exec anywhere the
/// check did not see. Elsewhere the exec runs the descriptor, the directory is not trusted, and `given` is as good as
/// any.
#[cfg(unix)]
fn exec_dir(dir: &Dir, given: &Path) -> Result<PathBuf> {
    if !EXEC_BY_PATH {
        return Ok(given.to_path_buf());
    }
    let resolved = resolved_path_of(dir, given)?;
    check(&resolved, super::euid())?;
    Ok(resolved)
}

#[cfg(windows)]
fn exec_dir(_dir: &Dir, given: &Path) -> Result<PathBuf> {
    Ok(given.to_path_buf())
}

#[cfg(target_os = "macos")]
fn resolved_path_of(dir: &Dir, given: &Path) -> Result<PathBuf> {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::io::AsRawFd;

    let mut buf = [0 as libc::c_char; libc::PATH_MAX as usize];
    // SAFETY: `F_GETPATH` writes a NUL-terminated path of at most PATH_MAX bytes into `buf`.
    let rc = unsafe { libc::fcntl(dir.file().as_raw_fd(), libc::F_GETPATH, buf.as_mut_ptr()) };
    if rc == -1 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to resolve {} from its handle", given.display()));
    }
    // SAFETY: `buf` holds a NUL-terminated string after the call.
    let resolved = unsafe { std::ffi::CStr::from_ptr(buf.as_ptr()) };
    Ok(PathBuf::from(std::ffi::OsStr::from_bytes(resolved.to_bytes())))
}

/// A unix other than macOS has no handle-to-path call used here, so a name that is exec'd cannot be tied to the
/// directory that was checked. (Linux never gets here: it execs the descriptor.)
#[cfg(all(unix, not(target_os = "macos")))]
fn resolved_path_of(_dir: &Dir, given: &Path) -> Result<PathBuf> {
    anyhow::bail!(
        "cannot run the embedded binary from {}: this OS can neither exec a descriptor nor resolve a directory from its handle",
        given.display()
    )
}

/// What a component of the path must be, for the running user `euid`.
#[cfg(unix)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Position {
    /// A directory on the way to the extraction directory: whoever owns it can rename what is below it.
    Ancestor,
    /// The extraction directory itself.
    Leaf,
}

#[cfg(unix)]
impl Position {
    /// Whether a directory owned by `uid` with `mode` cannot be altered by anyone but `euid` (and root).
    pub(super) fn is_sealed(self, uid: u32, mode: u32, euid: u32) -> bool {
        let owner_ok = match self {
            Position::Ancestor => uid == euid || uid == 0,
            Position::Leaf => uid == euid,
        };
        owner_ok && mode & 0o022 == 0
    }
}

/// Whether the volume with these `statfs` flags reports every file as the running user's.
#[cfg(target_os = "macos")]
pub(super) fn volume_ignores_ownership(flags: u32) -> bool {
    let mask = libc::MNT_IGNORE_OWNERSHIP as u32;
    flags & mask == mask
}

#[cfg(target_os = "macos")]
fn on_volume_that_ignores_ownership(path: &Path) -> Result<bool> {
    use std::os::unix::ffi::OsStrExt;

    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path {} contains a NUL byte", path.display()))?;
    // SAFETY: an all-zero `statfs` is a valid out-parameter.
    let mut stat: libc::statfs = unsafe { std::mem::zeroed() };
    // SAFETY: `c_path` is a valid C string and `stat` outlives the call.
    if unsafe { libc::statfs(c_path.as_ptr(), &mut stat) } != 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| format!("statfs({}) failed", path.display()));
    }
    Ok(volume_ignores_ownership(stat.f_flags))
}

/// Only macOS has `MNT_IGNORE_OWNERSHIP` to read.
#[cfg(all(unix, not(target_os = "macos")))]
fn on_volume_that_ignores_ownership(_path: &Path) -> Result<bool> {
    Ok(false)
}

/// Why a directory is not one only the running user can change.
#[cfg(unix)]
#[derive(Debug)]
pub enum SealedDirRefusal {
    /// A component of the path is not a directory, or its owner or mode lets someone else alter it.
    Changeable {
        resolved: PathBuf,
        component: PathBuf,
        is_dir: bool,
        uid: u32,
        mode: u32,
        euid: u32,
    },
    /// A component is on a volume mounted with `MNT_IGNORE_OWNERSHIP`.
    IgnoresOwnership { resolved: PathBuf, component: PathBuf },
}

#[cfg(unix)]
impl std::fmt::Display for SealedDirRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SealedDirRefusal::Changeable {
                resolved,
                component,
                is_dir,
                uid,
                mode,
                euid,
            } => write!(
                f,
                "refusing to run the embedded binary from {}: {} is a {} owned by uid {uid} with mode {mode:o}, which \
                 someone other than the running user (uid {euid}) can change. Set XDG_RUNTIME_DIR to a directory \
                 only the running user can modify.",
                resolved.display(),
                component.display(),
                if *is_dir {
                    "directory"
                } else {
                    "path that is not a directory"
                },
            ),
            SealedDirRefusal::IgnoresOwnership { resolved, component } => write!(
                f,
                "refusing to run the embedded binary from {}: {} is on a volume mounted with MNT_IGNORE_OWNERSHIP, \
                 which reports every file as the running user's, so its owner and mode prove nothing. Set \
                 XDG_RUNTIME_DIR to a directory on a volume that keeps ownership.",
                resolved.display(),
                component.display(),
            ),
        }
    }
}

#[cfg(unix)]
impl std::error::Error for SealedDirRefusal {}

/// Windows has no such refusal (the pin is the guarantee there), so none exists: callers name the type on every
/// platform without a `cfg`.
#[cfg(windows)]
#[derive(Debug)]
pub enum SealedDirRefusal {}

#[cfg(windows)]
impl std::fmt::Display for SealedDirRefusal {
    fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {}
    }
}

#[cfg(windows)]
impl std::error::Error for SealedDirRefusal {}

/// Refuses `resolved` (a path with no link in it) unless every component is sealed against everyone but `euid`: with
/// a [`SealedDirRefusal`], or an error of the OS.
#[cfg(unix)]
pub fn check(resolved: &Path, euid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt;

    let mut ancestors: Vec<&Path> = resolved.ancestors().collect();
    ancestors.reverse();
    let last = ancestors.len() - 1;
    for (i, path) in ancestors.into_iter().enumerate() {
        let position = if i == last { Position::Leaf } else { Position::Ancestor };
        let meta = std::fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
        if !meta.is_dir() || !position.is_sealed(meta.uid(), meta.mode(), euid) {
            return Err(SealedDirRefusal::Changeable {
                resolved: resolved.to_path_buf(),
                component: path.to_path_buf(),
                is_dir: meta.is_dir(),
                uid: meta.uid(),
                mode: meta.mode() & 0o7777,
                euid,
            }
            .into());
        }
        if on_volume_that_ignores_ownership(path)? {
            return Err(SealedDirRefusal::IgnoresOwnership {
                resolved: resolved.to_path_buf(),
                component: path.to_path_buf(),
            }
            .into());
        }
    }
    Ok(())
}

#[cfg(all(test, unix))]
#[path = "sealed_dir_tests.rs"]
mod sealed_dir_tests;
