// "Start at Login" toggle logic for the tray menu, extracted from tray.rs so
// the decision logic is unit-testable (the tray handler itself needs a full
// Tauri app context).

use tauri_plugin_autostart::{AutoLaunchManager, Error};

/// Seam over the autostart plugin so [`toggle`] is testable without a Tauri app.
pub trait Autostart {
    fn is_enabled(&self) -> Result<bool, Error>;
    fn enable(&self) -> Result<(), Error>;
    fn disable(&self) -> Result<(), Error>;
}

impl Autostart for AutoLaunchManager {
    fn is_enabled(&self) -> Result<bool, Error> {
        AutoLaunchManager::is_enabled(self)
    }

    fn enable(&self) -> Result<(), Error> {
        AutoLaunchManager::enable(self)
    }

    fn disable(&self) -> Result<(), Error> {
        AutoLaunchManager::disable(self)
    }
}

/// Which step of the toggle failed. The Display form may embed filesystem
/// paths (auto-launch's "app path doesn't exist: <exe path>") and must only
/// reach gui.log; dialogs use [`ToggleError::user_message`].
#[derive(Debug, thiserror::Error)]
pub enum ToggleError {
    #[error("failed to check autostart state: {0}")]
    Check(#[source] Error),
    #[error("failed to enable autostart: {0}")]
    Enable(#[source] Error),
    #[error("failed to disable autostart: {0}")]
    Disable(#[source] Error),
}

impl ToggleError {
    /// PII-free message for the error dialog; the full detail lands in gui.log.
    pub fn user_message(&self) -> &'static str {
        match self {
            ToggleError::Check(_) => "Could not check whether Start at Login is enabled. See gui.log for details.",
            ToggleError::Enable(_) => "Failed to enable Start at Login. See gui.log for details.",
            ToggleError::Disable(_) => "Failed to disable Start at Login. See gui.log for details.",
        }
    }
}

/// Flip the OS autostart registration to the opposite of its current state.
/// Returns the new state on success.
pub fn toggle(autostart: &impl Autostart) -> Result<bool, ToggleError> {
    if autostart.is_enabled().map_err(ToggleError::Check)? {
        autostart.disable().map_err(ToggleError::Disable)?;
        Ok(false)
    } else {
        autostart.enable().map_err(ToggleError::Enable)?;
        Ok(true)
    }
}

#[cfg(test)]
#[path = "autostart_tests.rs"]
mod autostart_tests;
