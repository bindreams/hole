//! Windows: the lock file's DACL must grant exactly the principals that may
//! write the state file. Read by listing the ACEs: there is no second
//! principal to open the lock as.

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use windows::core::PCWSTR;
use windows::Win32::Foundation::{LocalFree, HLOCAL};
use windows::Win32::Security::Authorization::{GetNamedSecurityInfoW, SetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows::Win32::Security::{
    AclSizeInformation, AddAce, GetAce, GetAclInformation, GetSecurityDescriptorControl, InitializeAcl, ACL,
    ACL_REVISION, ACL_SIZE_INFORMATION, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    PSECURITY_DESCRIPTOR, SE_DACL_PROTECTED,
};

use super::{DefaultPlacement, Fs, Placement, Removal, VersionedFile};
use crate::versioned_file::fixtures::{dir, put, unreadable_bytes, DecisionFile, OsRecordFile};
use crate::versioned_file::CannotRead;

fn decision(value: &str) -> DecisionFile {
    DecisionFile {
        value: value.to_string(),
    }
}

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

/// `S-1-1-0` and `S-1-3-4` (OWNER RIGHTS), as SID bytes.
pub(super) const EVERYONE: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
const OWNER_RIGHTS: [u8; 12] = [1, 1, 0, 0, 0, 0, 0, 3, 4, 0, 0, 0];

const FILE_WRITE_DATA: u32 = 0x2;
const FILE_APPEND_DATA: u32 = 0x4;
const DELETE: u32 = 0x1_0000;
const WRITE_DAC: u32 = 0x4_0000;
const FILE_GENERIC_READ: u32 = 0x12_0089;
const FILE_GENERIC_WRITE: u32 = 0x12_0116;
const FILE_ALL_ACCESS: u32 = 0x1F_01FF;
const INHERITED_ACE: u8 = 0x10;
const ACCESS_DENIED_ACE_TYPE: u8 = 1;

/// One ACE as its bytes: header (type, flags, size), mask, SID.
#[derive(Clone, PartialEq, Eq)]
pub(super) struct Ace(Vec<u8>);

impl Ace {
    pub(super) fn allow(sid: &[u8], mask: u32) -> Self {
        let size = (8 + sid.len()) as u16;
        let mut bytes = vec![0u8, 0];
        bytes.extend(size.to_le_bytes());
        bytes.extend(mask.to_le_bytes());
        bytes.extend(sid);
        Self(bytes)
    }

    pub(super) fn deny(sid: &[u8], mask: u32) -> Self {
        let mut ace = Self::allow(sid, mask);
        ace.0[0] = ACCESS_DENIED_ACE_TYPE;
        ace
    }

    /// Applies to the files and directories created inside.
    fn inheritable(mut self) -> Self {
        const OBJECT_INHERIT_AND_CONTAINER_INHERIT: u8 = 0x3;
        self.0[1] = OBJECT_INHERIT_AND_CONTAINER_INHERIT;
        self
    }

    fn is_allow(&self) -> bool {
        self.0[0] == 0
    }

    fn flags(&self) -> u8 {
        self.0[1]
    }

    fn mask(&self) -> u32 {
        u32::from_le_bytes(self.0[4..8].try_into().unwrap())
    }

    fn sid(&self) -> &[u8] {
        &self.0[8..]
    }

    fn writes(&self) -> bool {
        self.mask() & (FILE_WRITE_DATA | FILE_APPEND_DATA) != 0
    }
}

impl std::fmt::Debug for Ace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "type {} flags {:#x} mask {:#x} sid {:?}",
            self.0[0],
            self.flags(),
            self.mask(),
            self.sid()
        )
    }
}

fn wide(path: &Path) -> Vec<u16> {
    path.as_os_str().encode_wide().chain(Some(0)).collect()
}

pub(super) fn aces(path: &Path) -> Vec<Ace> {
    let name = wide(path);
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated; the out pointers are valid locals.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(&mut dacl),
            None,
            &mut descriptor,
        )
    };
    assert_eq!(rc.0, 0, "GetNamedSecurityInfoW {}", path.display());
    let mut found = Vec::new();
    if !dacl.is_null() {
        let mut size = ACL_SIZE_INFORMATION::default();
        // SAFETY: `dacl` is a valid ACL owned by `descriptor`; `size` is the struct the class names.
        unsafe {
            GetAclInformation(
                dacl,
                &mut size as *mut _ as *mut _,
                std::mem::size_of::<ACL_SIZE_INFORMATION>() as u32,
                AclSizeInformation,
            )
        }
        .unwrap();
        for index in 0..size.AceCount {
            let mut ace = std::ptr::null_mut();
            // SAFETY: `index` is below the ACE count.
            unsafe { GetAce(dacl, index, &mut ace) }.unwrap();
            let header = ace as *const u8;
            // SAFETY: every ACE starts with a header whose third and fourth bytes are its size.
            let len = unsafe { u16::from_le_bytes([*header.add(2), *header.add(3)]) };
            // SAFETY: the ACE is `len` bytes long, inside the descriptor's memory.
            found.push(Ace(unsafe { std::slice::from_raw_parts(header, len as usize) }.to_vec()));
        }
    }
    // SAFETY: the descriptor came from `GetNamedSecurityInfoW` and nothing points into it any more.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    found
}

/// Whether `path`'s DACL is marked protected: a later change to the directory's
/// inheritable ACEs would otherwise be propagated into it.
fn dacl_is_protected(path: &Path) -> bool {
    let name = wide(path);
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    // SAFETY: `name` is NUL-terminated; the out pointer is a valid local.
    let rc = unsafe {
        GetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            None,
            None,
            None,
            None,
            &mut descriptor,
        )
    };
    assert_eq!(rc.0, 0, "GetNamedSecurityInfoW {}", path.display());
    let (mut control, mut revision) = (0u16, 0u32);
    // SAFETY: `descriptor` came from the call above; the out pointers are valid locals.
    unsafe { GetSecurityDescriptorControl(descriptor, &mut control, &mut revision) }.unwrap();
    // SAFETY: nothing points into the descriptor any more.
    unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
    control & SE_DACL_PROTECTED.0 != 0
}

/// Replaces `path`'s DACL with exactly `aces`, inheriting nothing.
pub(super) fn set_aces(path: &Path, aces: &[Ace]) {
    let total = 8 + aces.iter().map(|a| a.0.len()).sum::<usize>();
    let mut buffer = vec![0u32; total.div_ceil(4)];
    let acl = buffer.as_mut_ptr() as *mut ACL;
    // SAFETY: `buffer` is `total` aligned bytes, enough for the header and every ACE.
    unsafe { InitializeAcl(acl, total as u32, ACL_REVISION) }.unwrap();
    for ace in aces {
        // SAFETY: each ACE is a complete, valid ACE of the length it names.
        unsafe {
            AddAce(
                acl,
                ACL_REVISION,
                u32::MAX,
                ace.0.as_ptr() as *const _,
                ace.0.len() as u32,
            )
        }
        .unwrap();
    }
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated and `acl` is a valid ACL.
    let rc = unsafe {
        SetNamedSecurityInfoW(
            PCWSTR(name.as_ptr()),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
            None,
            None,
            Some(acl),
            None,
        )
    };
    assert_eq!(rc.0, 0, "SetNamedSecurityInfoW {}", path.display());
}

/// Publishes the state file with its default DACL plus `extra`.
struct Extra(Vec<Ace>);

impl Placement for Extra {
    fn prepare_tmp(&self, tmp: &Path) -> io::Result<()> {
        let mut all = aces(tmp);
        all.extend(self.0.clone());
        set_aces(tmp, &all);
        Ok(())
    }
}

fn paths() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let dir = dir();
    let state = dir.path().join("decision.json");
    let lock = dir.path().join("decision.json.lock");
    (dir, state, lock)
}

fn everyone(aces: &[Ace]) -> Vec<&Ace> {
    aces.iter().filter(|a| a.sid() == EVERYONE).collect()
}

#[skuld::test]
fn the_lock_is_closed_to_a_principal_that_can_only_read_the_state_file() {
    let (dir, state, lock) = paths();

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(&decision("v"), &Extra(vec![Ace::allow(&EVERYONE, FILE_GENERIC_READ)]))
        .unwrap();

    assert_eq!(
        everyone(&aces(&state)).len(),
        1,
        "the state file is readable by everyone"
    );
    let lock_aces = aces(&lock);
    assert_eq!(everyone(&lock_aces), Vec::<&Ace>::new(), "{lock_aces:?}");
    assert!(!lock_aces.is_empty());
}

#[skuld::test]
fn the_lock_is_open_to_every_principal_that_can_write_the_state_file() {
    let (dir, state, lock) = paths();

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(&decision("v"), &Extra(vec![Ace::allow(&EVERYONE, FILE_ALL_ACCESS)]))
        .unwrap();

    let lock_aces = aces(&lock);
    let writers: Vec<Ace> = aces(&state)
        .into_iter()
        .filter(|a| a.is_allow() && a.writes())
        .collect();
    assert!(writers.len() > 1, "{writers:?}");
    for writer in writers {
        assert!(
            lock_aces
                .iter()
                .any(|a| a.is_allow() && a.sid() == writer.sid() && a.mask() & FILE_WRITE_DATA != 0),
            "{writer:?} can write the state file but not the lock: {lock_aces:?}"
        );
    }
    assert_eq!(everyone(&lock_aces).len(), 1, "{lock_aces:?}");
}

#[skuld::test]
fn a_deny_on_the_state_file_stays_a_deny_on_the_lock() {
    let (dir, _state, lock) = paths();
    // Denied first, so it wins over the allow after it, as on the state file.
    let placement = Extra(vec![
        Ace::deny(&EVERYONE, FILE_WRITE_DATA),
        Ace::allow(&EVERYONE, FILE_ALL_ACCESS),
    ]);

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(&decision("v"), &placement)
        .unwrap();

    let lock_aces = aces(&lock);
    let denies: Vec<&Ace> = lock_aces.iter().filter(|a| !a.is_allow()).collect();
    assert_eq!(denies.len(), 1, "{lock_aces:?}");
    assert_eq!((denies[0].sid(), denies[0].mask()), (&EVERYONE[..], FILE_WRITE_DATA));
    let deny_at = lock_aces.iter().position(|a| !a.is_allow()).unwrap();
    let allow_at = lock_aces
        .iter()
        .position(|a| a.sid() == EVERYONE && a.is_allow())
        .unwrap();
    assert!(deny_at < allow_at, "the deny must still come first: {lock_aces:?}");
}

#[skuld::test]
fn the_lock_grants_read_and_write_and_nothing_that_could_delete_or_hand_out_more() {
    let (dir, _state, lock) = paths();

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(&decision("v"), &Extra(vec![Ace::allow(&EVERYONE, FILE_ALL_ACCESS)]))
        .unwrap();

    let allowed = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
    let lock_aces = aces(&lock);
    assert!(!lock_aces.is_empty());
    for ace in lock_aces.iter().filter(|a| a.is_allow()) {
        let owner_only_extra = if ace.sid() == OWNER_RIGHTS { WRITE_DAC } else { 0 };
        assert_eq!(ace.mask() & !(allowed | owner_only_extra), 0, "{ace:?}");
        assert_eq!(ace.mask() & DELETE, 0, "{ace:?}");
    }
}

#[skuld::test]
fn the_owner_always_keeps_the_lock() {
    let (dir, _state, lock) = paths();

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(&decision("v"), &plain())
        .unwrap();

    assert!(
        aces(&lock)
            .iter()
            .any(|a| a.is_allow() && a.sid() == OWNER_RIGHTS && a.mask() & FILE_WRITE_DATA != 0),
        "an owner may change the state file's DACL, so it keeps the lock"
    );
}

#[skuld::test]
fn the_lock_has_its_own_dacl_with_nothing_inherited() {
    let (dir, _state, lock) = paths();

    VersionedFile::<DecisionFile>::new(dir.path())
        .store(&decision("v"), &plain())
        .unwrap();

    let lock_aces = aces(&lock);
    assert!(!lock_aces.is_empty());
    for ace in lock_aces {
        assert_eq!(ace.flags() & INHERITED_ACE, 0, "{ace:?}");
    }
}

/// Records the lock file's ACEs at the instant it exists.
struct AtCreation {
    lock: PathBuf,
    seen: std::sync::Mutex<Vec<Vec<Ace>>>,
}

impl Fs for AtCreation {
    fn after_lock_created(&self, _file: &std::fs::File) {
        self.seen.lock().unwrap().push(aces(&self.lock));
    }
}

// A lock that is narrowed after it is made can be opened, in between, by any
// principal the directory's DACL names, and that handle keeps its access.
#[skuld::test]
fn a_new_lock_has_its_final_dacl_when_it_first_exists() {
    let (dir, _state, lock) = paths();
    // New files here are readable by everyone, as under a shared install root.
    let mut open_dir = aces(dir.path());
    open_dir.push(Ace::allow(&EVERYONE, FILE_GENERIC_READ).inheritable());
    set_aces(dir.path(), &open_dir);
    let fs = std::sync::Arc::new(AtCreation {
        lock: lock.clone(),
        seen: Default::default(),
    });

    VersionedFile::<DecisionFile>::with_fs(dir.path(), fs.clone())
        .store(&decision("v"), &plain())
        .unwrap();

    let seen = fs.seen.lock().unwrap();
    assert_eq!(seen.len(), 1, "one lock was made");
    assert_eq!(seen[0], aces(&lock), "the DACL it was made with is the one it keeps");
    assert!(everyone(&seen[0]).is_empty(), "{:?}", seen[0]);
    assert!(seen[0].iter().all(|a| a.flags() & INHERITED_ACE == 0), "{:?}", seen[0]);
    assert!(
        dacl_is_protected(&lock),
        "a change to the directory would be propagated into the lock"
    );
}

#[skuld::test]
fn remove_and_move_aside_make_a_missing_lock_for_the_files_writers_only() {
    for remove in [true, false] {
        let (dir, state, lock) = paths();
        // A directory whose new files are readable by everyone, as one under a
        // shared install root may be: a lock created by default would be too.
        let mut open_dir = aces(dir.path());
        open_dir.push(Ace::allow(&EVERYONE, FILE_GENERIC_READ).inheritable());
        set_aces(dir.path(), &open_dir);
        put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
        let mut with_readers = aces(&state);
        with_readers.push(Ace::allow(&EVERYONE, FILE_GENERIC_READ));
        set_aces(&state, &with_readers);
        let file = VersionedFile::<DecisionFile>::new(dir.path());

        if remove {
            assert_eq!(file.remove().unwrap(), Removal::Removed);
        } else {
            assert!(file.move_aside().unwrap().is_some());
        }

        let lock_aces = aces(&lock);
        assert_eq!(
            everyone(&lock_aces),
            Vec::<&Ace>::new(),
            "remove={remove}: {lock_aces:?}"
        );
        assert!(!lock_aces.is_empty(), "remove={remove}");
    }
}

#[skuld::test]
fn a_lock_wider_than_its_files_writers_is_narrowed_by_every_operation() {
    for op in ["store", "remove", "move_aside"] {
        let (dir, state, lock) = paths();
        put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
        put(&dir, "decision.json.lock", b"");
        let mut wider = aces(&lock);
        wider.push(Ace::allow(&EVERYONE, FILE_GENERIC_READ));
        set_aces(&lock, &wider);
        assert_eq!(everyone(&aces(&state)).len(), 0);
        let file = VersionedFile::<DecisionFile>::new(dir.path());

        match op {
            "store" => file.store(&decision("v"), &plain()).unwrap(),
            "remove" => drop(file.remove().unwrap()),
            _ => drop(file.move_aside().unwrap()),
        }

        let lock_aces = aces(&lock);
        assert_eq!(everyone(&lock_aces), Vec::<&Ace>::new(), "{op}: {lock_aces:?}");
    }
}

#[skuld::test]
fn the_lock_has_the_same_dacl_after_every_operation() {
    let (dir, _state, lock) = paths();
    let file = VersionedFile::<DecisionFile>::new(dir.path());
    file.store(&decision("v0"), &plain()).unwrap();
    let first = aces(&lock);

    file.store(&decision("v1"), &plain()).unwrap();
    file.remove().unwrap();
    file.store(&decision("v2"), &plain()).unwrap();

    assert_eq!(aces(&lock), first);
}

// The caller cannot open the lock, so it is no writer of the file: it may still
// learn that the file's role would leave it alone.
#[skuld::test]
fn remove_by_a_non_writer_answers_kept_where_the_role_keeps_the_file() {
    let dir = dir();
    let bytes = unreadable_bytes(CannotRead::Corrupt);
    put(&dir, "os-record.json", bytes);
    let lock = put(&dir, "os-record.json.lock", b"");
    set_aces(&lock, &[Ace::deny(&EVERYONE, FILE_ALL_ACCESS)]);

    let removal = VersionedFile::<OsRecordFile>::new(dir.path()).remove();

    assert_eq!(removal.unwrap(), Removal::Kept);
    assert_eq!(std::fs::read(dir.path().join("os-record.json")).unwrap(), bytes);
}

/// The file is gone by the time it is read.
struct Vanished;

impl Fs for Vanished {
    fn read(&self, _path: &Path) -> io::Result<Vec<u8>> {
        Err(io::ErrorKind::NotFound.into())
    }
}

#[skuld::test]
fn remove_by_a_non_writer_answers_absent_for_a_file_that_is_gone_when_read() {
    let dir = dir();
    put(&dir, "decision.json", br#"{"version":1,"value":"v"}"#);
    let lock = put(&dir, "decision.json.lock", b"");
    set_aces(&lock, &[Ace::deny(&EVERYONE, FILE_ALL_ACCESS)]);

    let removal = VersionedFile::<DecisionFile>::with_fs(dir.path(), std::sync::Arc::new(Vanished)).remove();

    assert_eq!(removal.unwrap(), Removal::Absent);
}

#[skuld::test]
fn remove_by_a_non_writer_is_the_lock_error_where_the_role_would_act() {
    for bytes in [
        &br#"{"version":1,"value":"v"}"#[..],
        unreadable_bytes(CannotRead::Corrupt),
    ] {
        let dir = dir();
        put(&dir, "decision.json", bytes);
        let lock = put(&dir, "decision.json.lock", b"");
        set_aces(&lock, &[Ace::deny(&EVERYONE, FILE_ALL_ACCESS)]);

        let removal = VersionedFile::<DecisionFile>::new(dir.path()).remove();

        assert_eq!(removal.unwrap_err().kind(), io::ErrorKind::PermissionDenied);
    }
}
