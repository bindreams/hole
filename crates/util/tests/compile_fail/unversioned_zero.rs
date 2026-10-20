//! An absent `version` that reads as 0 is below every schema: it does not build.

use serde::{Deserialize, Serialize};
use std::path::Path;
use util::versioned_file::{Obsolete, Role, Schema, VersionedFile, VersionedState};

#[derive(Serialize, Deserialize)]
struct Config {}

impl Schema for Config {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl VersionedState for Config {
    const FILE_NAME: &'static str = "config.json";
    const ROLE: Role = Role::Config;
    const UNVERSIONED_AS: Option<u32> = Some(0);
}

fn main() {
    let _ = VersionedFile::<Config>::new(Path::new("."));
}
