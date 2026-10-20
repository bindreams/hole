//! A gap is reported by `assert_contiguous!` even where nothing decodes the
//! chain, which is what `cargo check` of a test target relies on.

use serde::Deserialize;
use util::versioned_file::{Obsolete, Schema};

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

util::assert_contiguous!(V3);

fn main() {}
