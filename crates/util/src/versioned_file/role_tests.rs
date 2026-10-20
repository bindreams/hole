use super::{RemoveOver, Role, StoreOver};
use crate::versioned_file::CannotRead::{Corrupt, Newer};
use crate::versioned_file::WhyUnreadable;

/// Every cell written out by hand, one row per role, `Newer` then `Corrupt` in each column.
#[skuld::test]
fn the_role_table_has_exactly_these_cells() {
    use RemoveOver::{Keep, MoveAside as MoveRemoved};
    use StoreOver::{MoveAside, Overwrite, Refuse};

    struct Row {
        role: Role,
        store: [StoreOver; 2],
        remove: [RemoveOver; 2],
        blocks_connect: [bool; 2],
    }

    let table = [
        Row {
            role: Role::Decision,
            store: [MoveAside, MoveAside],
            remove: [MoveRemoved, MoveRemoved],
            blocks_connect: [false, false],
        },
        Row {
            role: Role::OsRecord,
            store: [Refuse, Refuse],
            remove: [Keep, Keep],
            blocks_connect: [true, true],
        },
        Row {
            role: Role::LegacyRecord,
            store: [Refuse, Refuse],
            remove: [Keep, Keep],
            blocks_connect: [false, false],
        },
        Row {
            role: Role::Config,
            store: [Refuse, Overwrite],
            remove: [Keep, Keep],
            blocks_connect: [false, false],
        },
    ];

    for row in table {
        for (i, why) in [Newer, Corrupt].into_iter().enumerate() {
            let role = row.role;
            assert_eq!(role.on_store(why), row.store[i], "{role:?} {why:?} on_store");
            assert_eq!(role.on_remove(why), row.remove[i], "{role:?} {why:?} on_remove");
            assert_eq!(
                role.unreadable_blocks_connect(why),
                row.blocks_connect[i],
                "{role:?} {why:?} unreadable_blocks_connect"
            );
        }
    }
}

#[skuld::test]
fn unreadable_blocks_connect_is_true_only_for_os_record() {
    for role in [Role::Decision, Role::OsRecord, Role::LegacyRecord, Role::Config] {
        for why in [Newer, Corrupt] {
            assert_eq!(
                role.unreadable_blocks_connect(why),
                role == Role::OsRecord,
                "{role:?} {why:?}"
            );
        }
    }
}

/// The cells for a read that failed with an I/O error: the bytes were never seen,
/// so no backup is skipped and nothing is destroyed. One row per role.
#[skuld::test]
fn the_io_failure_cells_are_exactly_these() {
    use RemoveOver::{Keep, MoveAside as MoveRemoved};
    use StoreOver::{MoveAside, Refuse};

    let table = [
        (Role::Decision, MoveAside, MoveRemoved, false),
        (Role::OsRecord, Refuse, Keep, true),
        (Role::LegacyRecord, Refuse, Keep, false),
        (Role::Config, MoveAside, MoveRemoved, false),
    ];

    for (role, store, remove, blocks_connect) in table {
        assert_eq!(role.on_store_io_failure(), store, "{role:?} on_store_io_failure");
        assert_eq!(role.on_remove_io_failure(), remove, "{role:?} on_remove_io_failure");
        assert_eq!(
            role.io_failure_blocks_connect(),
            blocks_connect,
            "{role:?} io_failure_blocks_connect"
        );
    }
}

/// `blocks_connect` is the one question a caller asks of any unreadable file; it
/// must give the answer of the matching cell above, whatever the cause.
#[skuld::test]
fn blocks_connect_takes_the_cell_of_its_cause() {
    for role in [Role::Decision, Role::OsRecord, Role::LegacyRecord, Role::Config] {
        let blocks = role == Role::OsRecord;
        for why in [Newer, Corrupt] {
            assert_eq!(
                role.blocks_connect(WhyUnreadable::CannotRead(why)),
                blocks,
                "{role:?} {why:?}"
            );
        }
        assert_eq!(
            role.blocks_connect(WhyUnreadable::ReadFailed(std::io::ErrorKind::PermissionDenied)),
            blocks,
            "{role:?} read failed"
        );
    }
}
