use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

fn default_true() -> bool {
    true
}

#[derive(Debug, Deserialize)]
pub struct WixConfig {
    /// Path to the `.wxs` source file (required).
    pub wxs: PathBuf,

    /// Whether to run `cargo build --release --workspace` before building the MSI.
    #[serde(default = "default_true")]
    pub build: bool,

    /// Output MSI path. Defaults to `target/<profile>/<package-name>.msi`.
    #[serde(default)]
    pub output: Option<PathBuf>,

    /// WiX preprocessor defines (`-d KEY=VALUE`).
    #[serde(default)]
    pub defines: BTreeMap<String, String>,

    /// Files to stage, grouped by bindpath name.
    /// Each entry maps a destination filename to a source path (relative to workspace root).
    /// Use `{target}` in source paths to reference `target/<profile>/`.
    #[serde(default)]
    pub files: BTreeMap<String, BTreeMap<String, String>>,
}

/// Package information extracted from Cargo.toml metadata.
#[derive(Debug)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub workspace_root: PathBuf,
    pub target_dir: PathBuf,
}

/// Load `[package.metadata.wix]` from the Cargo.toml at the given manifest path
/// (or the current directory's Cargo.toml if `None`).
pub fn load_config(manifest_path: Option<&Path>) -> Result<(WixConfig, PackageInfo)> {
    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.no_deps();
    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    let metadata = cmd
        .exec()
        .map_err(|e| Error::Config(format!("failed to read cargo metadata: {e}")))?;

    // Find the root package (the one whose manifest is in the workspace root or the specified path).
    let root_manifest = manifest_path.map(|p| p.to_path_buf()).unwrap_or_else(|| {
        std::env::current_dir()
            .expect("failed to get current directory")
            .join("Cargo.toml")
    });

    let root_manifest = root_manifest.canonicalize().unwrap_or(root_manifest.clone());

    let package = metadata
        .packages
        .iter()
        .find(|p| {
            let pkg_manifest = p.manifest_path.as_std_path();
            pkg_manifest == root_manifest || pkg_manifest.canonicalize().ok().as_deref() == Some(&root_manifest)
        })
        .ok_or_else(|| Error::Config(format!("no package found at {}", root_manifest.display())))?;

    let wix_metadata = package
        .metadata
        .get("wix")
        .ok_or_else(|| Error::Config("[package.metadata.wix] not found in Cargo.toml".into()))?;

    let config: WixConfig = serde_json::from_value(wix_metadata.clone())
        .map_err(|e| Error::Config(format!("failed to parse [package.metadata.wix]: {e}")))?;

    let info = PackageInfo {
        name: package.name.clone(),
        version: package.version.to_string(),
        workspace_root: metadata.workspace_root.clone().into(),
        target_dir: metadata.target_directory.clone().into(),
    };

    Ok((config, info))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
