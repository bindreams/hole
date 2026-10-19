//! Version 3 follows version 1: version 2 has no schema.

use serde::Deserialize;
use util::versioned_file::{Chain, Obsolete, Schema};

#[derive(Deserialize)]
struct V1 {}

#[derive(Deserialize)]
struct V3 {}

impl Schema for V1 {
    const VERSION: u32 = 1;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
        match prev {}
    }
}

impl Schema for V3 {
    const VERSION: u32 = 3;
    type Prev = V1;
    fn upgrade(_: V1) -> Self {
        V3 {}
    }
}

fn main() {
    let _ = <V3 as Chain>::decode(3, b"{}");
}
