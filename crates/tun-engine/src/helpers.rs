//! Ergonomic primitives for common Router implementations.
//!
//! These are opt-in helpers, not required by the [`Router`](crate::engine::Router)
//! trait. They cover the most common patterns:
//!
//! - [`socks5_client::socks5_connect`] — dial a SOCKS5 upstream.
//! - [`socks5_udp::Socks5UdpRelay`] — RFC 1928 UDP ASSOCIATE client.
//! - [`bypass::create_bypass_tcp`] / [`bypass::create_bypass_udp`] — open
//!   sockets bound to a specific upstream NIC, bypassing the TUN.

pub mod bypass;
pub mod socks5_client;
pub mod socks5_udp;

pub use bypass::{create_bypass_tcp, create_bypass_udp};
pub use socks5_client::socks5_connect;
pub use socks5_udp::{decode_socks5_udp, encode_socks5_udp, Socks5UdpRelay};
