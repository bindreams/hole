//! TUN device lifecycle and platform driver loading.

#[cfg(target_os = "windows")]
pub mod wintun;
