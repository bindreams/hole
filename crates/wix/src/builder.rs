use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::staging;
use crate::toolchain;

/// Builder for constructing and running WiX MSI builds.
pub struct Builder {
    pub(crate) wxs_file: PathBuf,
    pub(crate) build_first: bool,
    pub(crate) output: Option<PathBuf>,
    pub(crate) defines: BTreeMap<String, String>,
    pub(crate) files: BTreeMap<String, BTreeMap<String, String>>,
    pub(crate) extra_bindpaths: BTreeMap<String, PathBuf>,
    pub(crate) workspace_root: PathBuf,
    pub(crate) target_dir: PathBuf,
    pub(crate) target_triple: String,
}

impl Builder {
    /// Create a new builder with the given `.wxs` source file path.
    pub fn new(wxs_file: impl Into<PathBuf>) -> Self {
        Self {
            wxs_file: wxs_file.into(),
            build_first: true,
            output: None,
            defines: BTreeMap::new(),
            files: BTreeMap::new(),
            extra_bindpaths: BTreeMap::new(),
            workspace_root: PathBuf::new(),
            target_dir: PathBuf::new(),
            target_triple: String::new(),
        }
    }

    /// Whether to run `cargo build --release --workspace` before WiX. Default: `true`.
    pub fn build_first(mut self, yes: bool) -> Self {
        self.build_first = yes;
        self
    }

    /// Set the output MSI path.
    pub fn output(mut self, path: impl Into<PathBuf>) -> Self {
        self.output = Some(path.into());
        self
    }

    /// Add a WiX preprocessor define (`-d KEY=VALUE`).
    pub fn define(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.defines.insert(key.into(), value.into());
        self
    }

    /// Set the files-to-stage config (from `[package.metadata.wix.files]`).
    pub fn files(mut self, files: BTreeMap<String, BTreeMap<String, String>>) -> Self {
        self.files = files;
        self
    }

    /// Add a direct bindpath (bypasses staging).
    pub fn bindpath(mut self, name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        self.extra_bindpaths.insert(name.into(), path.into());
        self
    }

    /// Set the workspace root directory.
    pub fn workspace_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.workspace_root = path.into();
        self
    }

    /// Set the target directory (e.g., `target/release`).
    pub fn target_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.target_dir = path.into();
        self
    }

    /// Set the Rust target triple (e.g., `x86_64-pc-windows-msvc`).
    /// Used for `{arch}` expansion in staging paths.
    pub fn target_triple(mut self, triple: impl Into<String>) -> Self {
        self.target_triple = triple.into();
        self
    }

    /// Build the MSI installer.
    ///
    /// 1. Optionally runs `cargo build --release --workspace`
    /// 2. Stages files (if configured)
    /// 3. Downloads WiX (if not cached)
    /// 4. Runs `wix build`
    ///
    /// Returns the path to the built MSI.
    pub fn build(&self) -> Result<PathBuf> {
        if self.build_first {
            self.run_cargo_build()?;
        }

        // Stage files
        let (_staging_dir, staged_bindpaths) = if !self.files.is_empty() {
            let (dir, bp) = staging::stage(&self.files, &self.workspace_root, &self.target_dir, &self.target_triple)?;
            (Some(dir), bp)
        } else {
            (None, BTreeMap::new())
        };

        // Merge bindpaths: staged + extra (extra wins on conflict)
        let mut all_bindpaths = staged_bindpaths;
        all_bindpaths.extend(self.extra_bindpaths.clone());

        // Determine output path
        let output = self.output.clone().unwrap_or_else(|| {
            self.target_dir
                .join(self.wxs_file.file_stem().unwrap_or_default())
                .with_extension("msi")
        });

        // Ensure WiX is available
        let wix_exe = toolchain::ensure_wix()?;

        // Build args and run
        let args = self.wix_args(&wix_exe, &output, &all_bindpaths);

        eprintln!(
            "Running: {} {}",
            wix_exe.display(),
            args.iter()
                .map(|a| a.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ")
        );

        let result = std::process::Command::new(&wix_exe)
            .args(&args)
            .current_dir(&self.workspace_root)
            .output()?;

        if !result.status.success() {
            let stderr = String::from_utf8_lossy(&result.stderr).into_owned();
            return Err(Error::BuildFailed {
                code: result.status.code().unwrap_or(-1),
                stderr,
            });
        }

        Ok(output)
    }

    /// Construct the `wix build` command-line arguments.
    fn wix_args(&self, _wix_exe: &Path, output: &Path, bindpaths: &BTreeMap<String, PathBuf>) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();

        args.push("build".into());
        args.push(self.wxs_file.as_os_str().into());

        for (name, path) in bindpaths {
            args.push("-bindpath".into());
            args.push(format!("{name}={}", path.display()).into());
        }

        for (key, value) in &self.defines {
            args.push("-d".into());
            args.push(format!("{key}={value}").into());
        }

        args.push("-o".into());
        args.push(output.as_os_str().into());

        args
    }

    fn run_cargo_build(&self) -> Result<()> {
        eprintln!("Running: cargo build --release --workspace");
        let status = std::process::Command::new("cargo")
            .args(["build", "--release", "--workspace"])
            .current_dir(&self.workspace_root)
            .status()?;

        if !status.success() {
            return Err(Error::CargoBuildFailed(status.code().unwrap_or(-1)));
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "builder_tests.rs"]
mod builder_tests;
