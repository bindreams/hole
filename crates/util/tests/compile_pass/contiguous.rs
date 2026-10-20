//! A chain with no gap builds, with a floor above zero.

use serde::Deserialize;
use util::versioned_file::{Chain, Obsolete, Schema};

#[derive(Deserialize)]
struct V2 {}

#[derive(Deserialize)]
struct V3 {}

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

util::assert_contiguous!(V3);

fn main() {
    let _ = <V3 as Chain>::decode(3, b"{}");
}
