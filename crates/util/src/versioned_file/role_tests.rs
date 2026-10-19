use super::{RemoveOver, Role, StoreOver};
use crate::versioned_file::CannotRead::{Corrupt, Newer};

/// Every cell written by hand from the Roles table in the design: one row per
/// role, `Newer` then `Corrupt` in each column.
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
