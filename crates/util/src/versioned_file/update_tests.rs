//! `update`, `observe` and `create_new` as a caller sees them: no lost update, the lock held only where it should be,
//! an atomic claim, and what a `Placement` is given.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{mpsc, Barrier};

use crate::versioned_file::fixtures::{dir, names, put, ClaimFile, Counter, DecisionFile, WithFloat};
use crate::versioned_file::{
    Change, CreateOutcome, DefaultPlacement, Loaded, StoreError, UpdateOutcome, VersionedFile,
};

fn plain() -> DefaultPlacement {
    DefaultPlacement::default()
}

fn increment(file: &VersionedFile<Counter>) {
    file.update(&plain(), |now| {
        let n = match &now.loaded {
            Loaded::Current { value, .. } => value.n,
            _ => 0,
        };
        (Change::Store(Counter { n: n + 1 }), ())
    })
    .unwrap();
}

const THREADS: usize = 8;
const ROUNDS: usize = 25;

#[skuld::test]
fn n_threads_incrementing_a_counter_through_update_lose_no_update() {
    let dir = dir();
    let barrier = Barrier::new(THREADS);

    std::thread::scope(|scope| {
        for _ in 0..THREADS {
            scope.spawn(|| {
                // Separate handles: the lock belongs to the path, not to the handle.
                let file = VersionedFile::<Counter>::new(dir.path());
                barrier.wait();
                for _ in 0..ROUNDS {
                    increment(&file);
                }
            });
        }
    });

    let observed = VersionedFile::<Counter>::new(dir.path()).observe();
    match observed.loaded {
        Loaded::Current { value, .. } => assert_eq!(value.n, (THREADS * ROUNDS) as u64),
        other => panic!("{other:?}"),
    }
}

#[skuld::test]
fn decide_sees_what_is_on_disk_and_its_result_comes_back() {
    let dir = dir();
    put(&dir, "decision.json", br#"{"version":1,"value":"on disk"}"#);
    let file = VersionedFile::<DecisionFile>::new(dir.path());

    let (seen, outcome) = file
        .update(&plain(), |now| match &now.loaded {
            Loaded::Current { value, .. } => (Change::Keep, value.value.clone()),
            other => panic!("{other:?}"),
        })
        .unwrap();

    assert_eq!(seen, "on disk");
    assert_eq!(outcome, UpdateOutcome::Unchanged);
}

#[skuld::test]
fn an_encode_error_changes_nothing() {
    let dir = dir();
    put(&dir, "with-float.json", br#"{"version":1,"x":1.5}"#);
    let file = VersionedFile::<WithFloat>::new(dir.path());
    let before = file.observe().generation;

    let err = file
        .update(&plain(), |_| (Change::Store(WithFloat { x: f64::NAN }), ()))
        .unwrap_err();

    assert!(matches!(err, StoreError::Encode(_)), "{err:?}");
    assert_eq!(
        std::fs::read(dir.path().join("with-float.json")).unwrap(),
        br#"{"version":1,"x":1.5}"#
    );
    assert_eq!(names(&dir), ["with-float.json"]);
    assert_eq!(file.observe().generation, before);
}

// create_new ----------------------------------------------------------------------------------------------------------

#[skuld::test]
fn create_new_claims_once_over_n_threads() {
    let dir = dir();
    let barrier = Barrier::new(THREADS);
    let created = AtomicUsize::new(0);
    let taken = AtomicUsize::new(0);

    std::thread::scope(|scope| {
        for n in 0..THREADS {
            let (barrier, created, taken, dir) = (&barrier, &created, &taken, &dir);
            scope.spawn(move || {
                let file = VersionedFile::<ClaimFile>::new(dir.path());
                barrier.wait();
                match file
                    .create_new(&ClaimFile { value: format!("t{n}") }, &plain())
                    .unwrap()
                {
                    CreateOutcome::Created => created.fetch_add(1, Ordering::SeqCst),
                    CreateOutcome::Taken => taken.fetch_add(1, Ordering::SeqCst),
                };
            });
        }
    });

    assert_eq!(created.load(Ordering::SeqCst), 1);
    assert_eq!(taken.load(Ordering::SeqCst), THREADS - 1);
    assert_eq!(names(&dir), ["claim.json"], "a loser left a temp file");
}

#[skuld::test]
fn create_new_over_a_corrupt_file_is_taken_and_leaves_it() {
    let dir = dir();
    put(&dir, "claim.json", b"{ not json");
    let file = VersionedFile::<ClaimFile>::new(dir.path());

    let got = file.create_new(&ClaimFile { value: "v".into() }, &plain()).unwrap();

    assert_eq!(got, CreateOutcome::Taken);
    assert_eq!(std::fs::read(dir.path().join("claim.json")).unwrap(), b"{ not json");
    assert_eq!(names(&dir), ["claim.json"]);
}

#[skuld::test]
fn create_new_leaves_no_temp_file_and_a_readable_claim() {
    let dir = dir();
    let file = VersionedFile::<ClaimFile>::new(dir.path());

    assert_eq!(
        file.create_new(&ClaimFile { value: "v".into() }, &plain()).unwrap(),
        CreateOutcome::Created
    );

    assert_eq!(names(&dir), ["claim.json"]);
    assert!(matches!(file.observe().loaded, Loaded::Current { .. }));
}

#[skuld::test]
fn create_new_makes_a_missing_directory() {
    let root = dir();
    let file = VersionedFile::<ClaimFile>::new(&root.path().join("logs"));

    assert_eq!(
        file.create_new(&ClaimFile { value: "v".into() }, &plain()).unwrap(),
        CreateOutcome::Created
    );

    assert!(root.path().join("logs").join("claim.json").is_file());
}

/// `create_new` neither waits for the path lock nor moves the generation: its atomicity is the hard link.
#[skuld::test]
fn create_new_takes_no_lock_and_leaves_the_generation() {
    let dir = dir();
    let file = VersionedFile::<ClaimFile>::new(dir.path());
    let (inside, entered) = mpsc::sync_channel::<()>(0);
    let (release, released) = mpsc::sync_channel::<()>(0);
    let before = file.observe().generation;

    std::thread::scope(|scope| {
        let file = &file;
        scope.spawn(move || {
            file.update(&plain(), |_| {
                inside.send(()).unwrap();
                released.recv().unwrap();
                (Change::Keep, ())
            })
            .unwrap();
        });
        entered.recv().unwrap();
        // The slot is held by the `update` above; a `create_new` that took it would never return.
        let got = file.create_new(&ClaimFile { value: "v".into() }, &plain()).unwrap();
        release.send(()).unwrap();
        assert_eq!(got, CreateOutcome::Created);
    });

    assert_eq!(file.observe().generation, before);
}

// observe -------------------------------------------------------------------------------------------------------------

/// A second name for a file is read only when the folder's owner can vouch for it. A test cannot make a file the
/// system owns without being the system, so the case is stated for any runner (as `read_state_file`'s is).
#[skuld::test]
fn observe_applies_the_vouched_file_rule() {
    let dir = dir();
    put(&dir, "victim", br#"{"version":1,"value":"theirs"}"#);
    std::fs::hard_link(dir.path().join("victim"), dir.path().join("decision.json")).unwrap();

    let observed = VersionedFile::<DecisionFile>::new(dir.path()).observe();

    match crate::dir::testing::runner_is_the_system() {
        true => match observed.loaded {
            Loaded::Unreadable { error, kind } => {
                assert_eq!(
                    crate::dir::Refusal::from_error(&error),
                    Some(&crate::dir::Refusal::ForeignFile)
                );
                assert_eq!(kind, crate::versioned_file::UnreadableKind::File);
            }
            other => panic!("the system never made a file with two names: {other:?}"),
        },
        false => assert!(
            matches!(observed.loaded, Loaded::Current { .. }),
            "{:?}",
            observed.loaded
        ),
    }
}

// Placement -----------------------------------------------------------------------------------------------------------

/// Rewrites the directory's DACL with itself, which needs the directory opened for it.
#[cfg(windows)]
struct ProtectsDir {
    wants_acl: bool,
}

#[cfg(windows)]
impl crate::versioned_file::Placement for ProtectsDir {
    fn open_for_acl(&self) -> bool {
        self.wants_acl
    }

    fn prepare_dir(&self, dir: &crate::dir::Dir) -> std::io::Result<()> {
        use std::os::windows::io::AsRawHandle;
        use windows::Win32::Foundation::HANDLE;
        use windows::Win32::Security::Authorization::{GetSecurityInfo, SetSecurityInfo, SE_FILE_OBJECT};
        use windows::Win32::Security::{DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

        let handle = HANDLE(dir.file().as_raw_handle());
        let mut dacl = std::ptr::null_mut();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        // SAFETY: the out-pointers are live locals; the descriptor is leaked, as in the other ACL test.
        let read = unsafe {
            GetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(&mut dacl),
                None,
                Some(&mut descriptor),
            )
        };
        if read.0 != 0 {
            return Err(std::io::Error::from_raw_os_error(read.0 as i32));
        }
        // SAFETY: `dacl` points into the descriptor read above.
        let write = unsafe {
            SetSecurityInfo(
                handle,
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION,
                None,
                None,
                Some(dacl),
                None,
            )
        };
        match write.0 {
            0 => Ok(()),
            code => Err(std::io::Error::from_raw_os_error(code as i32)),
        }
    }
}

#[cfg(windows)]
#[skuld::test]
fn a_placement_asking_for_acl_gets_a_directory_that_can_be_protected() {
    let dir = dir();
    let file = VersionedFile::<ClaimFile>::new(dir.path());
    let value = ClaimFile { value: "v".into() };

    let denied = file.update(&ProtectsDir { wants_acl: false }, |_| {
        (Change::Store(value.clone()), ())
    });
    let denied_claim = file.create_new(&value, &ProtectsDir { wants_acl: false });
    assert!(denied.is_err(), "guard: a directory opened for use cannot be protected");
    assert!(
        denied_claim.is_err(),
        "guard: a directory opened for use cannot be protected"
    );

    file.update(&ProtectsDir { wants_acl: true }, |_| (Change::Store(value.clone()), ()))
        .unwrap();
    std::fs::remove_file(dir.path().join("claim.json")).unwrap();
    assert_eq!(
        file.create_new(&value, &ProtectsDir { wants_acl: true }).unwrap(),
        CreateOutcome::Created
    );
}
