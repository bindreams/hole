use super::{RemoveOver, Role, StoreOver};
use crate::versioned_file::CannotRead::{Corrupt, Newer};

/// Every cell written out by hand, one row per role, `Newer` then `Corrupt` in each column.
#[skuld::test]
fn the_role_table_has_exactly_these_cells() {
    use RemoveOver::{Keep, MoveAside as MoveRemoved};
    use StoreOver::{MoveAside, Overwrite, Refuse};

    struct Row {
        role: Role,
        store: [StoreOver; 2],
        remove: [RemoveOver; 2],
    }

    let table = [
        Row {
            role: Role::Decision,
            store: [MoveAside, MoveAside],
            remove: [MoveRemoved, MoveRemoved],
        },
        Row {
            role: Role::OsRecord,
            store: [Refuse, Refuse],
            remove: [Keep, Keep],
        },
        Row {
            role: Role::LegacyRecord,
            store: [Refuse, Refuse],
            remove: [Keep, Keep],
        },
        Row {
            role: Role::Config,
            store: [Refuse, Overwrite],
            remove: [Keep, Keep],
        },
    ];

    for row in table {
        for (i, why) in [Newer, Corrupt].into_iter().enumerate() {
            let role = row.role;
            assert_eq!(role.on_store(why), row.store[i], "{role:?} {why:?} on_store");
            assert_eq!(role.on_remove(why), row.remove[i], "{role:?} {why:?} on_remove");
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
        (Role::Decision, MoveAside, MoveRemoved),
        (Role::OsRecord, Refuse, Keep),
        (Role::LegacyRecord, Refuse, Keep),
        (Role::Config, MoveAside, MoveRemoved),
    ];

    for (role, store, remove) in table {
        assert_eq!(role.on_store_io_failure(), store, "{role:?} on_store_io_failure");
        assert_eq!(role.on_remove_io_failure(), remove, "{role:?} on_remove_io_failure");
    }
}

/// The one question a caller asks of an unreadable file: its role either blocks a connect or not, whatever the cause.
#[skuld::test]
fn only_the_os_record_and_cover_roles_block_a_connect() {
    let table = [
        (Role::Decision, false),
        (Role::OsRecord, true),
        (Role::LegacyRecord, false),
        (Role::Config, false),
        (Role::Claim, false),
        (Role::Cover, true),
    ];
    for (role, blocks) in table {
        assert_eq!(role.blocks_connect(), blocks, "{role:?}");
    }
}

/// The `Claim` role's cells, written out by hand.
#[skuld::test]
fn claim_role_cells_match_the_spec_table() {
    let role = Role::Claim;
    for why in [Newer, Corrupt] {
        assert_eq!(role.on_store(why), StoreOver::Refuse, "on_store {why:?}");
        assert_eq!(role.on_remove(why), RemoveOver::Remove, "on_remove {why:?}");
    }
    assert_eq!(role.on_store_io_failure(), StoreOver::Refuse);
    assert_eq!(role.on_remove_io_failure(), RemoveOver::Remove);
}

/// The `Cover` role's cells, written out by hand.
#[skuld::test]
fn cover_role_cells_match_the_spec_table() {
    let role = Role::Cover;
    for why in [Newer, Corrupt] {
        assert_eq!(role.on_store(why), StoreOver::MoveAside, "on_store {why:?}");
        assert_eq!(role.on_remove(why), RemoveOver::MoveAside, "on_remove {why:?}");
    }
    assert_eq!(role.on_store_io_failure(), StoreOver::MoveAside);
    assert_eq!(role.on_remove_io_failure(), RemoveOver::Keep);
}
