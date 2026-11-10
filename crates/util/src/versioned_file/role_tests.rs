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

/// Only the user's own data follows the privilege of the process that handles it (a user's own, or a privileged one
/// such as a GUI run under `sudo`); every other role is a privileged process's whoever runs it.
#[skuld::test]
fn the_principal_of_each_role_is_exactly_this() {
    use crate::dir::Principal::{System, User};

    // (role, its principal when the process is System, when the process is User)
    let table = [
        (Role::Decision, System, System),
        (Role::OsRecord, System, System),
        (Role::LegacyRecord, System, System),
        (Role::Config, System, User),
        (Role::Claim, System, System),
        (Role::Cover, System, System),
    ];

    for (role, as_system, as_user) in table {
        assert_eq!(role.principal(System), as_system, "{role:?} in a privileged process");
        assert_eq!(role.principal(User), as_user, "{role:?} in an unprivileged process");
    }
}

/// A file of a role the process's privilege changes cannot be built without saying which process: that is the one role
/// whose two principals differ.
#[skuld::test]
fn only_the_config_role_depends_on_the_privilege_of_the_process() {
    for (role, depends) in [
        (Role::Decision, false),
        (Role::OsRecord, false),
        (Role::LegacyRecord, false),
        (Role::Config, true),
        (Role::Claim, false),
        (Role::Cover, false),
    ] {
        assert_eq!(role.depends_on_the_process(), depends, "{role:?}");
    }
}

/// The `Claim` role's cells, written out by hand.
#[skuld::test]
fn claim_role_cells_match_the_spec_table() {
    let role = Role::Claim;
    for why in [Newer, Corrupt] {
        assert_eq!(role.on_store(why), StoreOver::Refuse, "on_store {why:?}");
        assert_eq!(role.on_remove(why), RemoveOver::Remove, "on_remove {why:?}");
        assert!(
            !role.unreadable_blocks_connect(why),
            "unreadable_blocks_connect {why:?}"
        );
    }
    assert_eq!(role.on_store_io_failure(), StoreOver::Refuse);
    assert_eq!(role.on_remove_io_failure(), RemoveOver::Remove);
    assert!(!role.io_failure_blocks_connect());
}

/// The `Cover` role's cells, written out by hand.
#[skuld::test]
fn cover_role_cells_match_the_spec_table() {
    let role = Role::Cover;
    for why in [Newer, Corrupt] {
        assert_eq!(role.on_store(why), StoreOver::MoveAside, "on_store {why:?}");
        assert_eq!(role.on_remove(why), RemoveOver::MoveAside, "on_remove {why:?}");
        assert!(role.unreadable_blocks_connect(why), "unreadable_blocks_connect {why:?}");
    }
    assert_eq!(role.on_store_io_failure(), StoreOver::MoveAside);
    assert_eq!(role.on_remove_io_failure(), RemoveOver::Keep);
    assert!(role.io_failure_blocks_connect());
}
