//! The gap is between version 2 and the floor, below the named top type
//! `V3`: `assert_contiguous!(V3)` must still report it, where nothing decodes
//! the chain.

use serde::Deserialize;
use util::versioned_file::{Obsolete, Schema};

#[derive(Deserialize)]
struct V2 {}

#[derive(Deserialize)]
struct V3 {}

// Version 1 is neither dropped nor described.
impl Schema for V2 {
    const VERSION: u32 = 2;
    type Prev = Obsolete<0>;
    fn upgrade(prev: Obsolete<0>) -> Self {
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

fn main() {}
