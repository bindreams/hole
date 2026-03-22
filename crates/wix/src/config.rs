use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct WixConfig {
    /// Path to the `.wxs` source file, relative to workspace root (required).
    pub wxs: PathBuf,

    /// Workspace member whose name and version are used for the MSI.
    /// Auto-injects `ProductVersion` define. Default output path uses this name.
    #[serde(default)]
    pub package: Option<String>,

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
    /// `ProductVersion` is auto-injected from the `package` version unless overridden here.
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

/// Load WiX config from `[workspace.metadata.wix]` in the workspace root Cargo.toml.
pub fn load_config(manifest_path: Option<&Path>) -> Result<(WixConfig, PackageInfo)> {
    let mut cmd = cargo_metadata::MetadataCommand::new();
    cmd.no_deps();
    if let Some(path) = manifest_path {
        cmd.manifest_path(path);
    }

    let metadata = cmd
        .exec()
        .map_err(|e| Error::Config(format!("failed to read cargo metadata: {e}")))?;

    let wix_metadata = metadata
        .workspace_metadata
        .get("wix")
        .ok_or_else(|| Error::Config("[workspace.metadata.wix] not found in Cargo.toml".into()))?;

    let config: WixConfig = serde_json::from_value(wix_metadata.clone())
        .map_err(|e| Error::Config(format!("failed to parse [workspace.metadata.wix]: {e}")))?;

    let workspace_root: PathBuf = metadata.workspace_root.clone().into();

    // If a package is specified, look up its name and version
    let (name, version) = if let Some(ref pkg_name) = config.package {
        let pkg = metadata
            .packages
            .iter()
            .find(|p| p.name == *pkg_name)
            .ok_or_else(|| Error::Config(format!("package '{pkg_name}' not found in workspace")))?;
        (pkg.name.to_string(), pkg.version.to_string())
    } else {
        // Fall back to workspace directory name, no version
        let dir_name = metadata.workspace_root.file_name().unwrap_or("project").to_string();
        (dir_name, String::new())
    };

    let info = PackageInfo {
        name,
        version,
        manifest_dir: workspace_root.clone(),
        workspace_root,
        target_dir: metadata.target_directory.clone().into(),
    };

    Ok((config, info))
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
