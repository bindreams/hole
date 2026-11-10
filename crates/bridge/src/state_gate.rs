//! The connect gate: a connect is refused while a record of what this bridge did to the OS cannot be read.
//!
//! Such a record (routes, plugins, a macOS pf cover) may name something a connect would write over and so strand. The
//! type refuses the write; the gate refuses the connect before anything is mutated, so a refusal never leaves a half
//! started session behind. A decision file is never a reason: its own writer backs it up and replaces it.

use std::path::{Path, PathBuf};

use thiserror::Error;

/// Refuses a connect while any record under `state_dir` that blocks one cannot be read.
///
/// Every record type whose role blocks a connect (`OsRecord`, `Cover`) is read here. Today: `RouteState`,
/// `PluginState`, `FailClosedState`, `LockdownPfState`. A type of either role added later must be added here.
pub fn check(state_dir: &Path) -> Result<(), StateBlocked> {
    let paths: Vec<PathBuf> = tun_engine::routing::state::blocking(state_dir)
        .into_iter()
        .chain(crate::plugin_state::blocking(state_dir))
        .chain(tun_engine::routing::failclosed::blocking_state(state_dir))
        .collect();
    match paths.is_empty() {
        true => Ok(()),
        false => Err(StateBlocked::new(paths)),
    }
}

/// The files a connect was refused over. `Display` names the files and no directory: it reaches the bridge log and
/// `last_error`, and a state path can name a user. The user-facing text is composed from [`StateBlocked::files`] at the
/// display site. `Debug` names the files too.
///
/// [`check`] raises it before anything is mutated; a route install that finds its record unreadable raises it after
/// the start began, and the start rolls back as for any failed route install.
#[derive(Error)]
#[error("start refused: these state files cannot be read: {}", self.files().join(", "))]
pub struct StateBlocked {
    paths: Vec<PathBuf>,
}

impl std::fmt::Debug for StateBlocked {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StateBlocked").field("files", &self.files()).finish()
    }
}

impl StateBlocked {
    pub(crate) fn new(paths: Vec<PathBuf>) -> Self {
        Self { paths }
    }

    /// The full paths, for a test that checks which file blocked.
    #[cfg(test)]
    pub(crate) fn paths(&self) -> &[PathBuf] {
        &self.paths
    }

    /// The file name of each blocking file, in order.
    pub fn files(&self) -> Vec<String> {
        self.paths
            .iter()
            .map(|p| match p.file_name() {
                Some(name) => name.to_string_lossy().into_owned(),
                None => "a state file".to_owned(),
            })
            .collect()
    }
}

#[cfg(test)]
#[path = "state_gate_tests.rs"]
mod state_gate_tests;
