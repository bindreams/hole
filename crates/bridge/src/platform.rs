// Re-exports for platform-specific bridge setup.

#[cfg(target_os = "macos")]
#[path = "platform/macos.rs"]
pub mod os;

#[cfg(target_os = "windows")]
#[path = "platform/windows.rs"]
pub mod os;

/// Shared macOS image-swap. The pure plan is cfg-free (so it table-tests on any
/// host); the real `renamex_np`/`getattrlist` FFI inside is macOS-gated.
pub mod swap;
