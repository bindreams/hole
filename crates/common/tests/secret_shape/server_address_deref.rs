//! `ServerAddress` must never gain a `Deref` impl. See
//! `password_deref.rs` for the reasoning.

fn main() {
    let address = hole_common::config::ServerAddress::new("203.0.113.7");
    let exposed: &str = &*address;
    let _ = exposed;
}
