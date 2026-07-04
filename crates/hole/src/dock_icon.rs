//! macOS Dock icon set at runtime via `applicationIconImage`.
//!
//! Unbundled runs (`cargo tauri dev`, `target/debug/hole`) have no `Info.plist`,
//! so macOS shows the generic icon; this gives the real Hole icon in every launch mode.

use objc2::rc::Retained;
use objc2::{AnyThread, MainThreadMarker};
use objc2_app_kit::{NSApplication, NSImage};
use objc2_foundation::NSData;
use tracing::warn;

/// App icon PNG, rendered from `icons/icon-macos.svg` by build.rs.
fn app_icon_png() -> &'static [u8] {
    include_bytes!(concat!(env!("OUT_DIR"), "/app-icon.png"))
}

/// Decode the compiled-in app icon. Split out so the NSData→NSImage bridge is
/// unit-testable without a running NSApplication.
fn decode_app_icon() -> Option<Retained<NSImage>> {
    let data = NSData::with_bytes(app_icon_png());
    NSImage::initWithData(NSImage::alloc(), &data)
}

/// Set the Dock icon. Call site: Tauri `setup` (main thread).
pub fn set_dock_icon(mtm: MainThreadMarker) {
    // Cosmetic: a decode failure is near-impossible (build-rendered PNG, decode
    // test) but must never abort a running VPN — warn and keep the default icon.
    let Some(image) = decode_app_icon() else {
        warn!("could not decode the app icon; leaving the default Dock icon");
        return;
    };
    let app = NSApplication::sharedApplication(mtm);
    // SAFETY: `image` is a valid NSImage.
    unsafe { app.setApplicationIconImage(Some(&image)) };
}

#[cfg(test)]
#[path = "dock_icon_tests.rs"]
mod dock_icon_tests;
