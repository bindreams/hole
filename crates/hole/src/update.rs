// Auto-update: check GitHub releases, download, and verify. The privileged
// bridge owns the install (binary swap + service restart) via the cutover; the
// GUI hands it the verified payload over `POST /v1/update-apply`.

pub(crate) mod check;
mod download;
mod error;
mod periodic;
mod verify;

pub use check::{check_for_update, UpdateInfo};
pub use download::download_asset;
pub use error::UpdateError;
pub use periodic::start_update_checker;
pub use verify::fetch_manifest;

/// The macOS `.app` swap-target hint for `ApplyUpdate`, derived from the GUI's
/// own `current_exe` (`<bundle>/Contents/MacOS/hole`). The bridge re-validates it
/// against `CFBundleIdentifier == com.hole.app`, so a bad/undeterminable path is
/// rejected there as a destination precondition (400, distinct from the 422
/// payload-verify failure). Windows has no bundle and sends `None` (the SCM
/// install dir is canonical).
pub fn app_dest_hint() -> Option<String> {
    #[cfg(target_os = "macos")]
    {
        let exe = std::env::current_exe().ok()?;
        hole_bridge::cutover::app_dest::resolve_app_dest_from_exe(&exe).map(|p| p.to_string_lossy().into_owned())
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

/// Tauri-managed state for update availability.
pub struct UpdateState {
    pub tx: tokio::sync::watch::Sender<Option<UpdateInfo>>,
    pub rx: tokio::sync::watch::Receiver<Option<UpdateInfo>>,
}

impl Default for UpdateState {
    fn default() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(None);
        Self { tx, rx }
    }
}
