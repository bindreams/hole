//! A chain of four types with no gap passes `assert_contiguous!` on its top
//! type alone, and a valid `UNVERSIONED_AS` builds.

use serde::{Deserialize, Serialize};
use std::path::Path;
use util::versioned_file::{Obsolete, Role, Schema, VersionedFile, VersionedState};

#[derive(Deserialize)]
struct V2 {}

#[derive(Deserialize)]
struct V3 {}

#[derive(Serialize, Deserialize)]
struct V4 {}

impl Schema for V2 {
    const VERSION: u32 = 2;
    type Prev = Obsolete<1>;
    fn upgrade(prev: Obsolete<1>) -> Self {
        match prev {}
    }
}

impl Schema for V3 {
    const VERSION: u32 = 3;
    type Prev = V2;
    fn upgrade(_: V2) -> Self {
        V3 {}
    }
}

impl Schema for V4 {
    const VERSION: u32 = 4;
    type Prev = V3;
    fn upgrade(_: V3) -> Self {
        V4 {}
    }
}

impl VersionedState for V4 {
    const FILE_NAME: &'static str = "v4.json";
    const ROLE: Role = Role::Config;
    const UNVERSIONED_AS: Option<u32> = Some(4);
}

util::assert_contiguous!(V4);

fn main() {
    let _ = VersionedFile::<V4>::new(Path::new("."));
}
