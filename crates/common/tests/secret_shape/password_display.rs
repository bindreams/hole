//! `Password` must never gain a `Display` impl.
//!
//! `expose()` is its single named exit, so `rg '\.expose\(\)'` enumerates
//! every site that reads a real secret. A `Display` impl silently makes that
//! two, and `password = %entry.password` becomes a leak instead of a compile
//! error. Nothing else fails when one is added — the derived `Debug` is
//! hand-written and would still say `<redacted>` — which is why the shape,
//! not only its consequence, has to be pinned.

fn main() {
    let password = hole_common::config::Password::new("hunter2");
    println!("{password}");
}
