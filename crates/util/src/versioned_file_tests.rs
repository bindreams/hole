//! The template for a new state file; see the module docs of `versioned_file`.

use serde::{Deserialize, Serialize};

use super::{DefaultPlacement, Loaded, Obsolete, Role, Schema, VersionedFile, VersionedState};

// The current schema of the file. Version 1 has nothing before it, so its
// `Prev` is `Obsolete<0>` and its `upgrade` is `match prev {}`. A later version
// freezes this type as `LayoutV1`, adds `LayoutV2` with `type Prev = LayoutV1`
// and an infallible `upgrade`, and points `VersionedState` at `LayoutV2`.
#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Layout {
    plugin_dir: String,
}

impl Schema for Layout {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for Layout {
    const FILE_NAME: &'static str = "layout.json";
    const ROLE: Role = Role::OsRecord;
}

crate::assert_contiguous!(Layout);

#[skuld::test]
fn an_os_record_is_stored_and_loaded_back() {
    let dir = tempfile::tempdir().expect("tempdir");
    let file = VersionedFile::<Layout>::new(dir.path());
    file.store(
        &Layout {
            plugin_dir: "plugins".into(),
        },
        &DefaultPlacement::default(),
    )
    .expect("store");

    match file.load() {
        Loaded::Current { value, found: 1 } => assert_eq!(
            value,
            Layout {
                plugin_dir: "plugins".into()
            }
        ),
        other => panic!("{other:?}"),
    }
}
