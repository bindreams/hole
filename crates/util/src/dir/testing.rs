// `mklink /J` makes a junction, the link an unprivileged user can create; `std` has no call for it.
#![allow(clippy::disallowed_methods)] // test fixtures, never privileged

//! Fixtures for tests of code that walks a path through [`Dir`](super::Dir): a link a user could have
//! planted, a folder a user owns, and a folder the system owns that the test may nonetheless write in.
//!
//! A test cannot make a link or folder that belongs to another principal without being privileged, and
//! a privileged test run would make every one of them the system's own. So each fixture hands what it
//! makes to an *unprivileged* owner whoever runs the test: a runner who is one already (unix: not
//! root; Windows: not elevated) owns it; a privileged one (root; an elevated Windows token, whose files
//! belong to Administrators) gives it away (`nobody`; the `Users` group).

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

/// Makes `path`, or the link itself if it is one, belong to an unprivileged principal.
pub fn own(path: &Path) {
    platform::own(path);
}

/// Creates the directory `path` (and the folders above it) owned by an unprivileged principal.
pub fn user_dir(path: &Path) {
    std::fs::create_dir_all(path).unwrap();
    own(path);
}

/// A link to the directory `target` at `link`, owned by an unprivileged principal: unix a symlink,
/// Windows a junction.
pub fn plant_link(target: &Path, link: &Path) {
    platform::link(target, link);
    own(link);
}

/// What a user can plant at the name a privileged reader reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlantedName {
    /// A symbolic link to a valid file elsewhere.
    SymlinkToFile,
    /// A FIFO nobody writes to: a read of it by name waits for a writer that never comes.
    #[cfg(unix)]
    Fifo,
}

/// Every [`PlantedName`] the platform has.
#[cfg(unix)]
pub const PLANTED_NAMES: &[PlantedName] = &[PlantedName::SymlinkToFile, PlantedName::Fifo];
/// Every [`PlantedName`] the platform has.
#[cfg(windows)]
pub const PLANTED_NAMES: &[PlantedName] = &[PlantedName::SymlinkToFile];

/// One privileged reader of the file `file` in a state directory, for [`planted_name_is_not_read`].
pub struct Reader<'a> {
    /// The file the reader reads.
    pub file: &'a str,
    /// Writes a valid file `file` into the directory it is given: one whose content the reader reports.
    pub write_valid: &'a dyn Fn(&Path),
    /// Reads the directory and says whether it reported the content `write_valid` wrote.
    pub reads_it: &'a dyn Fn(&Path) -> bool,
}

/// Plants `kind` at the reader's file in a fresh state directory below `scratch` (an empty folder the test owns), then
/// reads it. `Err` if the reader reported the valid file the name leads to (it read through a link), or if the
/// control read of a real valid file did not report it. A reader that opens a FIFO by name waits here forever.
pub fn planted_name_is_not_read(scratch: &Path, kind: PlantedName, reader: &Reader) -> Result<(), String> {
    let real = scratch.join("real");
    let state = scratch.join("state");
    std::fs::create_dir(&real).map_err(|err| err.to_string())?;
    std::fs::create_dir(&state).map_err(|err| err.to_string())?;
    (reader.write_valid)(&real);
    if !(reader.reads_it)(&real) {
        return Err(format!("control: the reader did not report the valid {}", reader.file));
    }
    let at = state.join(reader.file);
    match kind {
        PlantedName::SymlinkToFile => platform::file_link(&real.join(reader.file), &at),
        #[cfg(unix)]
        PlantedName::Fifo => platform::fifo(&at),
    }
    if (reader.reads_it)(&state) {
        return Err(format!(
            "{kind:?} planted at {}: the reader read through it",
            reader.file
        ));
    }
    Ok(())
}

/// A name nothing in a folder the system owns has, removed again when dropped: the place to look for what a
/// walk wrongly made in that folder.
pub struct SystemScratch {
    root: PathBuf,
    name: String,
}

impl SystemScratch {
    pub fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        SystemScratch {
            root: platform::system_scratch(),
            name: format!(
                "hole-dir-test-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ),
        }
    }

    /// The folder the system owns and anyone may write in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The name in [`Self::root`] that must stay free.
    pub fn name(&self) -> &OsStr {
        OsStr::new(&self.name)
    }

    /// Where the name would be.
    pub fn path(&self) -> PathBuf {
        self.root.join(&self.name)
    }
}

impl Default for SystemScratch {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SystemScratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(self.path());
    }
}

#[cfg(unix)]
mod platform {
    use std::path::{Path, PathBuf};

    /// The uid root gives a path to.
    const NOBODY: u32 = 65534;

    pub(super) fn own(path: &Path) {
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            std::os::unix::fs::lchown(path, Some(NOBODY), Some(NOBODY)).unwrap();
        }
    }

    pub(super) fn link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    pub(super) fn file_link(target: &Path, link: &Path) {
        std::os::unix::fs::symlink(target, link).unwrap();
    }

    pub(super) fn fifo(at: &Path) {
        use std::os::unix::ffi::OsStrExt;
        let path = std::ffi::CString::new(at.as_os_str().as_bytes()).unwrap();
        // SAFETY: `path` is a valid NUL-terminated path.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
    }

    pub(super) fn system_scratch() -> PathBuf {
        PathBuf::from("/tmp")
    }
}

#[cfg(windows)]
mod platform {
    use std::os::windows::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use windows::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT, READ_CONTROL, WRITE_OWNER,
    };

    use super::super::trail::Owner;

    /// `S-1-5-32-545`, the `Users` group: a principal that is not the system.
    const USERS: [u8; 16] = [1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 33, 2, 0, 0];

    pub(super) fn own(path: &Path) {
        // The link itself (not what it points at), with the rights to read and to change its owner.
        let file = std::fs::OpenOptions::new()
            .access_mode(READ_CONTROL.0 | WRITE_OWNER.0)
            .share_mode(7)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT.0 | FILE_FLAG_BACKUP_SEMANTICS.0)
            .open(path)
            .unwrap_or_else(|err| panic!("open {path:?} to read and change its owner: {err}"));
        if matches!(super::super::windows::owner_of(&file).unwrap(), Owner::User(_)) {
            return;
        }
        // An elevated token's files belong to Administrators; giving one away takes the restore privilege.
        super::super::windows::enable_restore_privilege()
            .expect("enable the restore privilege (a token without it cannot give a file to another owner)");
        super::super::windows::set_owner(&file, &USERS)
            .unwrap_or_else(|err| panic!("give {path:?} to the Users group: {err}"));
    }

    pub(super) fn file_link(target: &Path, link: &Path) {
        std::os::windows::fs::symlink_file(target, link).unwrap();
    }

    pub(super) fn link(target: &Path, link: &Path) {
        let made = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(made.status.success(), "mklink /J: {made:?}");
    }

    /// `C:\Users\Public`: the system's, and writable by every interactive user.
    pub(super) fn system_scratch() -> PathBuf {
        PathBuf::from(std::env::var_os("PUBLIC").expect("PUBLIC names the shared profile folder"))
    }
}
