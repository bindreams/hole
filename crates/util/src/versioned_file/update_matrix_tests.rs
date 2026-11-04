//! Every cell of what `update` does: a change over each state a file can be in, per role. The expectations are
//! written out by hand from the role table (spec rev 4, rule 2), not computed from `Role`, and each is checked on
//! the outcome and on the bytes left on disk.

use std::ffi::OsStr;
use std::io;
use std::path::PathBuf;
use std::sync::Arc;

use crate::dir::ReadDir;
use crate::versioned_file::fixtures::{
    dir, names, put, unreadable_bytes, ClaimFile, ConfigFile, CoverFile, DecisionFile, DroppedFile, LegacyRecordFile,
    OsRecordFile,
};
use crate::versioned_file::store::Fs;
use crate::versioned_file::{
    CannotRead, Change, DefaultPlacement, StoreError, UpdateOutcome, VersionedFile, VersionedState,
};

const CURRENT: &[u8] = br#"{"version":1,"value":"old"}"#;
const UNREAD: &[u8] = b"bytes nobody could read: hunter2";

trait Valued: VersionedState + Clone + std::fmt::Debug {
    fn with(value: &str) -> Self;
}

macro_rules! valued {
    ($($t:ty),*) => { $(impl Valued for $t {
        fn with(value: &str) -> Self { Self { value: value.into() } }
    })* };
}

valued!(
    DecisionFile,
    OsRecordFile,
    LegacyRecordFile,
    ConfigFile,
    ClaimFile,
    CoverFile
);

/// Every read fails, while the file stays on disk.
struct DeniedRead;

impl Fs for DeniedRead {
    fn read(&self, _dir: &ReadDir, _name: &OsStr) -> io::Result<Vec<u8>> {
        Err(io::Error::from(io::ErrorKind::PermissionDenied))
    }
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum State {
    Absent,
    Current,
    Newer,
    Corrupt,
    IoFailed,
}

impl State {
    fn bytes(self) -> Option<&'static [u8]> {
        match self {
            State::Absent => None,
            State::Current => Some(CURRENT),
            State::Newer => Some(unreadable_bytes(CannotRead::Newer)),
            State::Corrupt => Some(unreadable_bytes(CannotRead::Corrupt)),
            State::IoFailed => Some(UNREAD),
        }
    }
}

struct Case<S: VersionedState> {
    dir: tempfile::TempDir,
    file: VersionedFile<S>,
    original: Option<&'static [u8]>,
}

impl<S: Valued> Case<S> {
    fn new(state: State) -> Self {
        let dir = dir();
        let original = state.bytes();
        if let Some(bytes) = original {
            put(&dir, S::FILE_NAME, bytes);
        }
        let file = match state {
            State::IoFailed => VersionedFile::<S>::with_fs(dir.path(), Arc::new(DeniedRead)),
            _ => VersionedFile::<S>::new(dir.path()),
        };
        Self { dir, file, original }
    }

    fn change(&self, change: Change<S>) -> Result<UpdateOutcome, StoreError> {
        self.file
            .update(&DefaultPlacement::default(), |_| (change, ()))
            .map(|(_, outcome)| outcome)
    }

    fn names(&self) -> Vec<String> {
        names(&self.dir)
    }

    fn name_bytes(&self) -> Vec<u8> {
        std::fs::read(self.dir.path().join(S::FILE_NAME)).unwrap()
    }

    fn backup(&self) -> PathBuf {
        self.dir.path().join(format!("{}.unreadable.bak", S::FILE_NAME))
    }

    fn backup_name(&self) -> String {
        format!("{}.unreadable.bak", S::FILE_NAME)
    }

    fn untouched(&self) {
        assert_eq!(
            self.name_bytes(),
            self.original.unwrap(),
            "{}: the file changed",
            S::FILE_NAME
        );
        assert_eq!(
            self.names(),
            [S::FILE_NAME],
            "{}: something was left beside it",
            S::FILE_NAME
        );
    }
}

// What a role does over a file it cannot read -------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Then {
    Refused,
    BackedUp,
    Overwritten,
    Kept,
    MovedAside,
    Removed,
}

const UNREADABLE: [State; 3] = [State::Newer, State::Corrupt, State::IoFailed];

fn store_over_unreadable<S: Valued>(expected: [Then; 3]) {
    for (state, then) in UNREADABLE.into_iter().zip(expected) {
        let case = Case::<S>::new(state);
        let got = case.change(Change::Store(S::with("new")));
        let what = format!("{} over {state:?}", S::FILE_NAME);
        match then {
            Then::Refused => {
                match (state, &got) {
                    (
                        State::Newer,
                        Err(StoreError::Unreadable {
                            cause: CannotRead::Newer,
                            ..
                        }),
                    ) => {}
                    (
                        State::Corrupt,
                        Err(StoreError::Unreadable {
                            cause: CannotRead::Corrupt,
                            ..
                        }),
                    ) => {}
                    (
                        State::IoFailed,
                        Err(StoreError::ReadFailed {
                            kind: io::ErrorKind::PermissionDenied,
                            ..
                        }),
                    ) => {}
                    _ => panic!("{what}: {got:?}"),
                }
                case.untouched();
            }
            Then::BackedUp => {
                assert!(matches!(got, Ok(UpdateOutcome::Stored)), "{what}: {got:?}");
                assert!(
                    String::from_utf8(case.name_bytes()).unwrap().contains("\"new\""),
                    "{what}"
                );
                assert_eq!(std::fs::read(case.backup()).unwrap(), case.original.unwrap(), "{what}");
                assert_eq!(case.names(), [S::FILE_NAME.to_owned(), case.backup_name()], "{what}");
            }
            Then::Overwritten => {
                assert!(matches!(got, Ok(UpdateOutcome::Stored)), "{what}: {got:?}");
                assert!(
                    String::from_utf8(case.name_bytes()).unwrap().contains("\"new\""),
                    "{what}"
                );
                assert_eq!(case.names(), [S::FILE_NAME], "{what}");
            }
            Then::Kept | Then::MovedAside | Then::Removed => unreachable!("not a store outcome"),
        }
    }
}

fn remove_over_unreadable<S: Valued>(expected: [Then; 3]) {
    for (state, then) in UNREADABLE.into_iter().zip(expected) {
        let case = Case::<S>::new(state);
        let got = case.change(Change::Remove);
        let what = format!("{} over {state:?}", S::FILE_NAME);
        match then {
            Then::Kept => {
                assert!(matches!(got, Ok(UpdateOutcome::Kept)), "{what}: {got:?}");
                case.untouched();
            }
            Then::MovedAside => {
                assert!(
                    matches!(&got, Ok(UpdateOutcome::MovedAside(p)) if *p == case.backup()),
                    "{what}: {got:?}"
                );
                assert_eq!(std::fs::read(case.backup()).unwrap(), case.original.unwrap(), "{what}");
                assert_eq!(case.names(), [case.backup_name()], "{what}");
            }
            Then::Removed => {
                assert!(matches!(got, Ok(UpdateOutcome::Removed)), "{what}: {got:?}");
                assert!(case.names().is_empty(), "{what}");
            }
            Then::Refused | Then::BackedUp | Then::Overwritten => unreachable!("not a remove outcome"),
        }
    }
}

use Then::{BackedUp, Kept, MovedAside, Overwritten, Refused, Removed};

#[skuld::test]
fn a_store_over_a_file_the_role_cannot_read_does_what_the_role_says() {
    store_over_unreadable::<DecisionFile>([BackedUp, BackedUp, BackedUp]);
    store_over_unreadable::<OsRecordFile>([Refused, Refused, Refused]);
    store_over_unreadable::<LegacyRecordFile>([Refused, Refused, Refused]);
    store_over_unreadable::<ConfigFile>([Refused, Overwritten, BackedUp]);
    store_over_unreadable::<ClaimFile>([Refused, Refused, Refused]);
    store_over_unreadable::<CoverFile>([BackedUp, BackedUp, BackedUp]);
}

#[skuld::test]
fn a_remove_over_a_file_the_role_cannot_read_does_what_the_role_says() {
    remove_over_unreadable::<DecisionFile>([MovedAside, MovedAside, MovedAside]);
    remove_over_unreadable::<OsRecordFile>([Kept, Kept, Kept]);
    remove_over_unreadable::<LegacyRecordFile>([Kept, Kept, Kept]);
    remove_over_unreadable::<ConfigFile>([Kept, Kept, MovedAside]);
    remove_over_unreadable::<ClaimFile>([Removed, Removed, Removed]);
    remove_over_unreadable::<CoverFile>([MovedAside, MovedAside, Kept]);
}

// What no role decides ------------------------------------------------------------------------------------------------

const ALL: [State; 5] = [
    State::Absent,
    State::Current,
    State::Newer,
    State::Corrupt,
    State::IoFailed,
];

fn role_independent<S: Valued>() {
    for state in ALL {
        let what = format!("{} {state:?}", S::FILE_NAME);

        // Keep writes nothing, over anything.
        let case = Case::<S>::new(state);
        let before = case.names();
        let generation = case.file.observe().generation;
        assert!(
            matches!(case.change(Change::Keep), Ok(UpdateOutcome::Unchanged)),
            "{what}: keep"
        );
        assert_eq!(case.names(), before, "{what}: keep");
        assert_eq!(case.file.observe().generation, generation, "{what}: keep");

        // MoveAside moves, whatever the role and whatever the file holds.
        let case = Case::<S>::new(state);
        let got = case.change(Change::MoveAside);
        match state {
            State::Absent => assert!(matches!(got, Ok(UpdateOutcome::Absent)), "{what}: move aside {got:?}"),
            _ => {
                assert!(
                    matches!(&got, Ok(UpdateOutcome::MovedAside(p)) if *p == case.backup()),
                    "{what}: {got:?}"
                );
                assert_eq!(std::fs::read(case.backup()).unwrap(), case.original.unwrap(), "{what}");
                assert_eq!(case.names(), [case.backup_name()], "{what}");
            }
        }
    }

    // A file the role can read, or none, is replaced or removed with no backup.
    for state in [State::Absent, State::Current] {
        let what = format!("{} {state:?}", S::FILE_NAME);
        let case = Case::<S>::new(state);
        assert!(
            matches!(case.change(Change::Store(S::with("new"))), Ok(UpdateOutcome::Stored)),
            "{what}"
        );
        assert_eq!(case.names(), [S::FILE_NAME], "{what}: store");

        let case = Case::<S>::new(state);
        let got = case.change(Change::Remove);
        match state {
            State::Absent => assert!(matches!(got, Ok(UpdateOutcome::Absent)), "{what}: {got:?}"),
            _ => assert!(matches!(got, Ok(UpdateOutcome::Removed)), "{what}: {got:?}"),
        }
        assert!(case.names().is_empty(), "{what}: remove");
    }
}

#[skuld::test]
fn keep_move_aside_and_a_readable_file_mean_the_same_for_every_role() {
    role_independent::<DecisionFile>();
    role_independent::<OsRecordFile>();
    role_independent::<LegacyRecordFile>();
    role_independent::<ConfigFile>();
    role_independent::<ClaimFile>();
    role_independent::<CoverFile>();
}

/// A version the chain's floor dropped on purpose is neither protected nor an error.
#[skuld::test]
fn an_obsolete_file_is_replaced_and_removed_without_a_backup() {
    for change in [Change::Store(DroppedFile { value: 7 }), Change::Remove] {
        let dir = dir();
        put(&dir, "dropped.json", br#"{"version":1,"value":1}"#);
        let file = VersionedFile::<DroppedFile>::new(dir.path());
        let removing = matches!(change, Change::Remove);

        let ((), outcome) = file.update(&DefaultPlacement::default(), |_| (change, ())).unwrap();

        match removing {
            true => assert_eq!(outcome, UpdateOutcome::Removed),
            false => assert_eq!(outcome, UpdateOutcome::Stored),
        }
        assert_eq!(
            names(&dir).len(),
            usize::from(!removing),
            "no backup: {:?}",
            names(&dir)
        );
    }
}

#[skuld::test]
fn a_directory_that_is_not_there_is_made_by_a_store_and_by_nothing_else() {
    for (change, made) in [
        (Change::Keep, false),
        (Change::Remove, false),
        (Change::MoveAside, false),
        (Change::Store(DecisionFile { value: "v".into() }), true),
    ] {
        let root = dir();
        let missing = root.path().join("not-there");
        let file = VersionedFile::<DecisionFile>::new(&missing);

        file.update(&DefaultPlacement::default(), |_| (change, ())).unwrap();

        assert_eq!(missing.exists(), made);
    }
}
