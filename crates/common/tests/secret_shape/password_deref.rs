//! `Password` must never gain a `Deref` impl.
//!
//! A `Deref<Target = str>` (or `Target = String`, which coerces onward) is a
//! second, unnamed exit: `&*password` and every `&str`-taking call become
//! leak sites that `expose()` no longer enumerates. See `password_display.rs`
//! for the sibling half.

fn main() {
    let password = hole_common::config::Password::new("hunter2");
    let exposed: &str = &*password;
    let _ = exposed;
}
