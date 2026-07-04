//! macOS Dock icon set at runtime via `applicationIconImage`.
//!
//! Unbundled runs (`cargo tauri dev`, `target/debug/hole`) have no `Info.plist`,
//! so macOS would show the generic icon; setting it at runtime covers them. A
//! bundled release already has the multi-resolution ICNS, so it is left alone.

use std::path::Path;

use objc2::rc::Retained;
use objc2::{AnyThread, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSImage};
use objc2_foundation::NSData;
use tracing::warn;

/// App icon PNG, rendered from `icons/icon-macos.svg` by build.rs.
fn app_icon_png() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.png"))
}

/// Whether `exe` sits inside a macOS bundle (`.../<name>.app/Contents/MacOS/<bin>`).
fn is_bundled_exe(exe: &Path) -> bool {
    let Some(macos) = exe.parent() else { return false };
    let Some(app) = macos.parent().and_then(Path::parent) else {
        return false;
    };
    macos.ends_with("Contents/MacOS") && app.extension().is_some_and(|e| e == "app")
}

/// Whether the running process is a bundled `.app` (which carries its own Dock ICNS).
fn running_bundled() -> bool {
    match std::env::current_exe() {
        Ok(exe) => is_bundled_exe(&exe),
        // Benign either way (the override is idempotent); default to unbundled, but
        // trace it so a real bundled install that ever hits this is diagnosable.
        Err(e) => {
            tracing::debug!(error = %e, "current_exe() failed; treating process as unbundled for the Dock icon");
            false
        }
    }
}

/// Decode the compiled-in app icon. Split out to unit-test the NSData→NSImage
/// bridge without a running NSApplication. `None` for a nil or zero-size image.
fn decode_app_icon() -> Option<Retained<NSImage>> {
    let data = NSData::with_bytes(app_icon_png());
    let image = NSImage::initWithData(NSImage::alloc(), &data)?;
    let size = image.size();
    (size.width > 0.0 && size.height > 0.0).then_some(image)
}

/// Set the Dock icon. Call site: Tauri `setup` (main thread).
pub fn set_dock_icon(mtm: MainThreadMarker) {
    if running_bundled() {
        return;
    }
    // Cosmetic: never abort a running VPN over a Dock icon — warn and keep the default.
    let Some(image) = decode_app_icon() else {
        warn!("could not decode the app icon; leaving the default Dock icon");
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    // SAFETY: called on the main thread (`mtm`) with a valid NSImage.
    unsafe { app.setApplicationIconImage(Some(&image)) };
}

#[cfg(test)]
#[path = "dock_icon_tests.rs"]
mod dock_icon_tests;
