// Re-exports for platform-specific bridge setup.

#[cfg(target_os = "macos")]
#[path = "platform/macos.rs"]
pub mod os;

#[cfg(target_os = "windows")]
#[path = "platform/windows.rs"]
pub mod os;
