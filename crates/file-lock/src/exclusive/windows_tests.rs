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
