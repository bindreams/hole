use super::*;

fn file() -> Facts {
    Facts {
        disk_file: true,
        attributes: 0,
    }
}

// vet =================================================================================================================

#[skuld::test]
fn a_single_link_disk_file_passes() {
    assert_eq!(vet(file()), Ok(()));
}

#[skuld::test]
fn a_reparse_point_is_refused() {
    let facts = Facts {
        attributes: FILE_ATTRIBUTE_REPARSE_POINT.0,
        ..file()
    };
    assert_eq!(vet(facts), Err(Refusal::Symlink));
}

#[skuld::test]
fn a_directory_is_refused() {
    let facts = Facts {
        attributes: FILE_ATTRIBUTE_DIRECTORY.0,
        ..file()
    };
    assert_eq!(vet(facts), Err(Refusal::NotRegular));
}

#[skuld::test]
fn a_handle_that_is_not_a_disk_file_is_refused() {
    let facts = Facts {
        disk_file: false,
        ..file()
    };
    assert_eq!(vet(facts), Err(Refusal::NotRegular));
}

// A failed open names its NTSTATUS ------------------------------------------------------------------------------------

#[skuld::test]
fn a_lock_file_held_without_sharing_fails_to_open_naming_its_ntstatus() {
    use std::os::windows::fs::OpenOptionsExt;

    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("held.lock");
    let _holder = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(&path)
        .unwrap();

    let err = open_locked(&path, false, None, caller()).unwrap_err();

    // STATUS_SHARING_VIOLATION
    assert!(err.to_string().contains("NTSTATUS 0xC0000043"), "{err}");
}
