//! Windows-only properties of the stored file: its attributes, and a state
//! directory whose plain path is `MAX_PATH` or longer.

use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::MetadataExt;
use std::os::windows::io::AsRawHandle;
use std::path::Path;

use windows::core::PCWSTR;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Storage::FileSystem::{
    FileBasicInfo, SetFileAttributesW, SetFileInformationByHandle, FILE_ATTRIBUTE_HIDDEN,
    FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_ATTRIBUTE_READONLY, FILE_ATTRIBUTE_TEMPORARY, FILE_BASIC_INFO,
};

use super::{
    no_directory_flush, sync_dir_with, tolerate_missing_directory_flush, CannotRead, DefaultPlacement, Loaded,
    Placement, Removal, VersionedFile,
};
use crate::dir::Dir;
use crate::versioned_file::fixtures::{dir, long_dir, unreadable_bytes, DecisionFile, OsRecordFile};

/// Sets the attributes of the open file (a zero time in `FILE_BASIC_INFO` leaves that time as it is).
fn set_attributes(file: &File, attributes: u32) -> io::Result<()> {
    let info = FILE_BASIC_INFO {
        FileAttributes: attributes,
        ..Default::default()
    };
    // SAFETY: `info` is a valid `FILE_BASIC_INFO` of the size passed and the handle is open for writing attributes.
    unsafe {
        SetFileInformationByHandle(
            HANDLE(file.as_raw_handle()),
            FileBasicInfo,
            (&raw const info).cast(),
            size_of::<FILE_BASIC_INFO>() as u32,
        )
    }
    .map_err(io::Error::other)
}

fn listing(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("read_dir")
        .map(|e| e.expect("entry").file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

fn record(value: &str) -> OsRecordFile {
    OsRecordFile {
        value: value.to_owned(),
    }
}

fn is_temporary(path: &Path) -> bool {
    attributes(path) & FILE_ATTRIBUTE_TEMPORARY.0 != 0
}

fn attributes(path: &Path) -> u32 {
    std::fs::metadata(path).unwrap().file_attributes()
}

/// A [`Placement`] that sets `FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED`
/// on the temp file: on Windows the attributes are the file's mode, and `prepare_tmp` is
/// where a placement sets it.
struct Attributed;

impl Placement for Attributed {
    fn prepare_tmp(&self, tmp: &File) -> io::Result<()> {
        set_attributes(tmp, (FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED).0)
    }
}

fn assert_placed_but_not_temporary(path: &Path) {
    let attributes = attributes(path);
    assert_eq!(attributes & FILE_ATTRIBUTE_TEMPORARY.0, 0, "attributes {attributes:#x}");
    for kept in [FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NOT_CONTENT_INDEXED] {
        assert_eq!(
            attributes & kept.0,
            kept.0,
            "the placement's {kept:?} was lost: attributes {attributes:#x}"
        );
    }
}

// Attributes ==========================================================================================================

#[skuld::test]
fn the_first_store_does_not_leave_the_file_marked_temporary() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());

    file.store(&record("one"), &DefaultPlacement::default()).unwrap();

    assert!(!is_temporary(file.path()));
}

#[skuld::test]
fn a_store_over_an_existing_file_does_not_leave_it_marked_temporary() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());
    file.store(&record("one"), &DefaultPlacement::default()).unwrap();

    file.store(&record("two"), &DefaultPlacement::default()).unwrap();

    assert!(!is_temporary(file.path()));
}

#[skuld::test]
fn the_first_store_keeps_the_attributes_a_placement_set_but_clears_temporary() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());

    file.store(&record("one"), &Attributed).unwrap();

    assert_placed_but_not_temporary(file.path());
}

#[skuld::test]
fn a_store_over_an_existing_file_keeps_the_attributes_a_placement_set_but_clears_temporary() {
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());
    file.store(&record("one"), &Attributed).unwrap();

    file.store(&record("two"), &Attributed).unwrap();

    assert_placed_but_not_temporary(file.path());
    assert!(matches!(file.load(), Loaded::Current { value, .. } if value == record("two")));
}

// Reading =============================================================================================================

#[skuld::test]
fn load_reads_a_folder_nobody_may_add_to() {
    // A load asks the folder for nothing a write needs: a machine that tightened its ACL to read-only still reads.
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());
    file.store(&record("one"), &DefaultPlacement::default()).unwrap();
    let _denied = crate::dir::testing::AddDenied::to(dir.path());

    assert!(matches!(file.load(), Loaded::Current { value, .. } if value == record("one")));
}

// Volumes without a directory flush ===================================================================================

fn os(code: i32) -> io::Error {
    io::Error::from_raw_os_error(code)
}

/// `ERROR_INVALID_FUNCTION` (1) and `ERROR_NOT_SUPPORTED` (50): what an SMB
/// share or a 9P volume answers a directory flush with.
#[skuld::test]
fn only_invalid_function_and_not_supported_mean_the_volume_has_no_directory_flush() {
    for code in [1, 50] {
        assert!(no_directory_flush(&os(code)), "code {code}");
    }
    for code in [
        2,    // ERROR_FILE_NOT_FOUND
        3,    // ERROR_PATH_NOT_FOUND
        5,    // ERROR_ACCESS_DENIED
        32,   // ERROR_SHARING_VIOLATION
        87,   // ERROR_INVALID_PARAMETER
        112,  // ERROR_DISK_FULL
        120,  // ERROR_CALL_NOT_IMPLEMENTED
        1117, // ERROR_IO_DEVICE
    ] {
        assert!(!no_directory_flush(&os(code)), "code {code}");
    }
    assert!(!no_directory_flush(&io::Error::other("no os code")));
}

#[skuld::test]
fn a_directory_flush_the_volume_does_not_offer_is_not_an_error() {
    for code in [1, 50] {
        tolerate_missing_directory_flush(Err(os(code))).unwrap();
    }
}

#[skuld::test]
fn any_other_directory_flush_error_is_returned() {
    for code in [2, 5, 112, 1117] {
        let err = tolerate_missing_directory_flush(Err(os(code))).unwrap_err();
        assert_eq!(err.raw_os_error(), Some(code));
    }
    tolerate_missing_directory_flush(Ok(())).unwrap();
}

// Long paths ==========================================================================================================

#[skuld::test]
fn a_store_over_an_existing_file_works_in_a_directory_of_260_characters_or_more() {
    let root = dir();
    let long = long_dir(root.path());
    let file = VersionedFile::<OsRecordFile>::new(&long);
    file.store(&record("one"), &DefaultPlacement::default()).unwrap();

    file.store(&record("two"), &DefaultPlacement::default()).unwrap();

    assert!(matches!(file.load(), Loaded::Current { value, .. } if value == record("two")));
    assert_eq!(listing(&long), ["os-record.json"]);
}

#[skuld::test]
fn move_aside_moves_a_corrupt_file_in_a_directory_of_260_characters_or_more() {
    let root = dir();
    let long = long_dir(root.path());
    let file = VersionedFile::<DecisionFile>::new(&long);
    std::fs::write(file.path(), unreadable_bytes(CannotRead::Corrupt)).unwrap();

    let backup = file.move_aside().unwrap().expect("the file was there");

    assert_eq!(listing(&long), ["decision.json.unreadable.bak"]);
    assert_eq!(backup, long.join("decision.json.unreadable.bak"));
}

#[skuld::test]
fn remove_moves_a_corrupt_decision_file_aside_in_a_directory_of_260_characters_or_more() {
    let root = dir();
    let long = long_dir(root.path());
    let file = VersionedFile::<DecisionFile>::new(&long);
    std::fs::write(file.path(), unreadable_bytes(CannotRead::Corrupt)).unwrap();

    let removal = file.remove().unwrap();

    assert_eq!(removal, Removal::MovedAside(long.join("decision.json.unreadable.bak")));
    assert_eq!(listing(&long), ["decision.json.unreadable.bak"]);
}

#[skuld::test]
fn the_directory_flush_tolerates_a_volume_without_one_where_it_is_wired() {
    use windows::Win32::Foundation::{ERROR_INVALID_FUNCTION, ERROR_IO_DEVICE};
    let dir = dir();
    let os = |code: u32| io::Error::from_raw_os_error(code as i32);

    let handle = Dir::open(dir.path(), false, None).unwrap();

    sync_dir_with(&handle, |_| Err(os(ERROR_INVALID_FUNCTION.0))).unwrap();
    let err = sync_dir_with(&handle, |_| Err(os(ERROR_IO_DEVICE.0))).unwrap_err();
    assert_eq!(err.raw_os_error(), Some(ERROR_IO_DEVICE.0 as i32));
}

/// Sets `FILE_ATTRIBUTE_READONLY`, which `prepare_tmp`'s contract forbids.
struct ReadOnly;

impl Placement for ReadOnly {
    fn prepare_tmp(&self, tmp: &File) -> io::Result<()> {
        set_attributes(tmp, FILE_ATTRIBUTE_READONLY.0)
    }
}

#[skuld::test]
fn a_read_only_placement_makes_the_next_store_fail_and_keeps_the_old_value() {
    // Pins the documented contract of `Placement::prepare_tmp`.
    let dir = dir();
    let file = VersionedFile::<OsRecordFile>::new(dir.path());
    file.store(&record("one"), &ReadOnly).unwrap();

    let err = file.store(&record("two"), &ReadOnly).unwrap_err();

    assert!(format!("{err:?}").contains("PermissionDenied"), "{err:?}");
    assert!(matches!(file.load(), Loaded::Current { value, .. } if value == record("one")));
    // Clean up so the temp dir can be removed.
    let wide: Vec<u16> = file.path().as_os_str().encode_wide().chain([0]).collect();
    // SAFETY: `wide` is NUL-terminated and outlives the call.
    unsafe {
        SetFileAttributesW(
            PCWSTR(wide.as_ptr()),
            windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
        )
    }
    .unwrap();
}
