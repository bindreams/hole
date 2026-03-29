// Auto-update: check GitHub releases, download, and install.

pub(crate) mod check;
mod download;
mod error;
mod install;
mod periodic;
mod verify;

pub use check::{check_for_update, UpdateInfo};
pub use download::download_asset;
pub use error::UpdateError;
pub use install::run_installer;
pub use periodic::start_update_checker;
pub use verify::verify_asset;

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
