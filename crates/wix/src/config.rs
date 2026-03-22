use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct WixConfig {
    /// Path to the `.wxs` source file, relative to the crate's manifest directory (required).
    pub wxs: PathBuf,

    /// Output MSI path, relative to workspace root.
    /// Default: `<target_dir>/release/<package_name>.msi`.
    #[serde(default)]
    pub output: Option<PathBuf>,

    /// Command (argv-style) to run before `wix build`.
    #[serde(default)]
    pub before: Vec<String>,

    /// Command (argv-style) to run after `wix build`.
    #[serde(default)]
    pub after: Vec<String>,

    /// WiX preprocessor defines (`-d KEY=VALUE`).
    /// `ProductVersion` is auto-injected from Cargo.toml version unless overridden here.
    #[serde(default)]
    pub defines: BTreeMap<String, String>,

    /// WiX bindpaths (`-bindpath NAME=PATH`), resolved relative to workspace root.
    #[serde(default)]
    pub bindpaths: BTreeMap<String, PathBuf>,
}

/// Package information extracted from Cargo.toml metadata.
#[derive(Debug)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub manifest_dir: PathBuf,
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

    // Find the root package
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

    let manifest_dir = package
        .manifest_path
        .parent()
        .expect("manifest_path should have a parent")
        .as_std_path()
        .to_path_buf();

    let info = PackageInfo {
        name: package.name.clone(),
        version: package.version.to_string(),
        manifest_dir,
        workspace_root: metadata.workspace_root.clone().into(),
        target_dir: metadata.target_directory.clone().into(),
    };

    Ok((config, info))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
