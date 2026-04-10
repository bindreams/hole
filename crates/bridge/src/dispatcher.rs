//! TCP dispatcher — owns the TUN device and smoltcp interface, runs
//! per-connection filter decisions, and dispatches to proxy/bypass/block
//! paths. Constructed by `ProxyManager::start`, destroyed on `stop`.

pub mod block_log;
pub mod socks5_client;
