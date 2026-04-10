//! TCP dispatcher — owns the TUN device and smoltcp interface, runs
//! per-connection filter decisions, and dispatches to proxy/bypass/block
//! paths. Constructed by `ProxyManager::start`, destroyed on `stop`.

pub mod block_log;
pub mod bypass;
pub mod device;
pub mod socks5_client;
pub mod upstream_dns;
