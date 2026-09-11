//! `ServerAddress` must never gain a `Display` impl — the same rule as
//! `Password`'s, with a redacting sink underneath as a second line of
//! defense rather than instead of this one.

fn main() {
    let address = hole_common::config::ServerAddress::new("203.0.113.7");
    println!("{address}");
}
