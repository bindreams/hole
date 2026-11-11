//! The Tauri config of a target as `tauri-build` reads it: `tauri.conf.json` with the platform file
//! (`tauri.macos.conf.json`, ...) merged over it. One reader, so the build script, its sidecar stubs and the
//! conformance tests never disagree about what a platform's config says.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// The merged config for `triple` read from `config_dir`, and the files it read (the ones a build script must watch).
pub fn merged_tauri_config(triple: &str, config_dir: &Path) -> Result<(serde_json::Value, Vec<PathBuf>)> {
    let target = tauri_utils::platform::Target::from_triple(triple);
    tauri_utils::config::parse::read_from(target, config_dir)
        .with_context(|| format!("failed to read the Tauri config for {triple}"))
}
