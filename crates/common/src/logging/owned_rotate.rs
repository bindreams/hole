//! `io::Write` wrapper around `file_rotate::FileRotate` that re-`chown`s the
//! active log file after each size-rotation (#572). The active filename is
//! fixed; a rotation renames it (ownership preserved) and opens a fresh
//! root-owned active file — detected here via an inode change. `chown_fn` is
//! injectable for tests; production passes a closure over `util::ownership::chown_path`.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

// On non-macOS, `reconcile_owner` is a no-op (the wrapper is a transparent
// passthrough), so every field except `inner` is written-but-never-read there;
// macOS reads them all. Suppress the dead-code denial off-macOS only.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub struct UserOwnedRotate<S, F>
where
    S: file_rotate::suffix::SuffixScheme,
    F: FnMut(&Path, u32, u32) -> io::Result<()>,
{
    inner: file_rotate::FileRotate<S>,
    active: PathBuf,
    owner: Option<(u32, u32)>,
    chown_fn: F,
    last_ino: Option<u64>,
}

impl<S, F> UserOwnedRotate<S, F>
where
    S: file_rotate::suffix::SuffixScheme,
    F: FnMut(&Path, u32, u32) -> io::Result<()>,
{
    pub fn new(inner: file_rotate::FileRotate<S>, active: PathBuf, owner: Option<(u32, u32)>, chown_fn: F) -> Self {
        Self {
            inner,
            active,
            owner,
            chown_fn,
            last_ino: None,
        }
    }

    #[cfg(target_os = "macos")]
    fn reconcile_owner(&mut self) {
        use std::os::unix::fs::MetadataExt;
        let Some((uid, gid)) = self.owner else { return };
        let Ok(ino) = std::fs::metadata(&self.active).map(|m| m.ino()) else {
            return;
        };
        if self.last_ino == Some(ino) {
            return;
        }
        if let Err(e) = (self.chown_fn)(&self.active, uid, gid) {
            tracing::warn!(error = %e, path = %self.active.display(), "chown of rotated log file failed");
        }
        self.last_ino = Some(ino);
    }

    #[cfg(not(target_os = "macos"))]
    fn reconcile_owner(&mut self) {}
}

impl<S, F> Write for UserOwnedRotate<S, F>
where
    S: file_rotate::suffix::SuffixScheme,
    F: FnMut(&Path, u32, u32) -> io::Result<()>,
{
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.reconcile_owner();
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
#[path = "owned_rotate_tests.rs"]
mod owned_rotate_tests;
