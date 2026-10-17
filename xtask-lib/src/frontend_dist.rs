//! Whether a Tauri build can embed the frontend it is configured to.

use std::path::{Path, PathBuf};

use anyhow::Context;
use path_clean::PathClean;
use serde_json::Value;
use tauri_utils::config::{Config, FrontendDist};

/// The `frontendDist` directory a build must embed but cannot find, if any.
///
/// Tauri embeds the frontend unless the build is a dev build (`dev`) with a
/// `devUrl`, in which case the webview loads that URL instead; an embedding
/// build panics in `tauri-codegen` when the directory is absent. This is the
/// same decision, asked before that panic so the caller can report it.
///
/// It is made over the config tauri makes it over, parsed into tauri's own
/// types: `base` is what `tauri_utils::config::parse::read_from` returns (the
/// config file with its platform file merged in) and `tauri_config` is the
/// `TAURI_CONFIG` environment variable, a JSON merge patch over `base`.
/// A `frontendDist` that tauri reads as a URL, or as a list of files, is not a
/// directory to look for.
///
/// The returned path is for display; existence is asked of `config_dir` joined
/// with the configured path, as tauri asks it.
pub fn missing_frontend_dist(
    dev: bool,
    mut base: Value,
    tauri_config: Option<&str>,
    config_dir: &Path,
    exists: impl Fn(&Path) -> bool,
) -> anyhow::Result<Option<PathBuf>> {
    if let Some(patch) = tauri_config {
        let patch: Value = serde_json::from_str(patch).context("TAURI_CONFIG is not valid JSON")?;
        json_patch::merge(&mut base, &patch);
    }
    let config: Config = serde_json::from_value(base).context("the merged Tauri config is invalid")?;
    if dev && config.build.dev_url.is_some() {
        return Ok(None);
    }
    let Some(FrontendDist::Directory(path)) = config.build.frontend_dist else {
        return Ok(None);
    };
    let dir = config_dir.join(path);
    Ok((!exists(&dir)).then(|| dir.clean()))
}
