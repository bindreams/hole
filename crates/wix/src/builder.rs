use std::collections::BTreeMap;
use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};
use crate::toolchain;

/// Builder for constructing and running WiX MSI builds.
pub struct Builder {
    pub(crate) wxs_file: PathBuf,
    pub(crate) output: Option<PathBuf>,
    pub(crate) before: Vec<String>,
    pub(crate) after: Vec<String>,
    pub(crate) skip_before: bool,
    pub(crate) skip_after: bool,
    pub(crate) defines: BTreeMap<String, String>,
    pub(crate) bindpaths: BTreeMap<String, PathBuf>,
    pub(crate) workspace_root: PathBuf,
    pub(crate) target_dir: PathBuf,
    pub(crate) package_name: String,
    pub(crate) package_version: String,
}

impl Builder {
    pub fn new(wxs_file: impl Into<PathBuf>) -> Self {
        Self {
            wxs_file: wxs_file.into(),
            output: None,
            before: Vec::new(),
            after: Vec::new(),
            skip_before: false,
            skip_after: false,
            defines: BTreeMap::new(),
            bindpaths: BTreeMap::new(),
            workspace_root: PathBuf::new(),
            target_dir: PathBuf::new(),
            package_name: String::new(),
            package_version: String::new(),
        }
    }

    pub fn output(mut self, path: impl Into<PathBuf>) -> Self {
        self.output = Some(path.into());
        self
    }

    pub fn before(mut self, cmd: Vec<String>) -> Self {
        self.before = cmd;
        self
    }

    pub fn after(mut self, cmd: Vec<String>) -> Self {
        self.after = cmd;
        self
    }

    pub fn skip_before(mut self, yes: bool) -> Self {
        self.skip_before = yes;
        self
    }

    pub fn skip_after(mut self, yes: bool) -> Self {
        self.skip_after = yes;
        self
    }

    pub fn define(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.defines.insert(key.into(), value.into());
        self
    }

    pub fn bindpath(mut self, name: impl Into<String>, path: impl Into<PathBuf>) -> Self {
        self.bindpaths.insert(name.into(), path.into());
        self
    }

    pub fn workspace_root(mut self, path: impl Into<PathBuf>) -> Self {
        self.workspace_root = path.into();
        self
    }

    pub fn target_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.target_dir = path.into();
        self
    }

    pub fn package_name(mut self, name: impl Into<String>) -> Self {
        self.package_name = name.into();
        self
    }

    pub fn package_version(mut self, version: impl Into<String>) -> Self {
        self.package_version = version.into();
        self
    }

    /// Build the MSI installer.
    ///
    /// 1. Inject auto-defines (ProductVersion)
    /// 2. Run `before` hook (if configured and not skipped)
    /// 3. Download/extract WiX (if not cached)
    /// 4. Run `wix build`
    /// 5. Run `after` hook (if configured and not skipped)
    pub fn build(&self) -> Result<PathBuf> {
        // Resolve output path
        let output = self.output.clone().unwrap_or_else(|| {
            self.target_dir
                .join("release")
                .join(format!("{}.msi", self.package_name))
        });

        // Auto-inject defines (into a local copy, not mutating self)
        let mut defines = self.defines.clone();
        if !self.package_version.is_empty() {
            defines
                .entry("ProductVersion".into())
                .or_insert_with(|| self.package_version.clone());
        }

        // Build env vars for hooks
        let env = self.hook_env(&output);

        // Before hook
        if !self.skip_before && !self.before.is_empty() {
            self.run_hook("before", &self.before.clone(), &env)?;
        }

        // Ensure WiX is available
        let wix_exe = toolchain::ensure_wix()?;

        // Run wix build
        let args = self.wix_args(&wix_exe, &output, &defines);

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

        // After hook
        if !self.skip_after && !self.after.is_empty() {
            if let Err(e) = self.run_hook("after", &self.after.clone(), &env) {
                eprintln!("warning: after hook failed: {e}");
            }
        }

        Ok(output)
    }

    /// Build the environment variables map for hook commands.
    pub(crate) fn hook_env(&self, output: &Path) -> BTreeMap<String, String> {
        let mut env = BTreeMap::new();
        env.insert("WIX_OUTPUT".into(), output.to_string_lossy().into_owned());
        env.insert("WIX_WXS".into(), self.wxs_file.to_string_lossy().into_owned());
        env.insert("WIX_PACKAGE_NAME".into(), self.package_name.clone());
        env.insert("WIX_PACKAGE_VERSION".into(), self.package_version.clone());
        env.insert(
            "WIX_WORKSPACE_ROOT".into(),
            self.workspace_root.to_string_lossy().into_owned(),
        );
        env.insert("WIX_TARGET_DIR".into(), self.target_dir.to_string_lossy().into_owned());
        env
    }

    /// Construct `wix build` command-line arguments.
    fn wix_args(&self, _wix_exe: &Path, output: &Path, defines: &BTreeMap<String, String>) -> Vec<OsString> {
        let mut args: Vec<OsString> = Vec::new();

        args.push("build".into());
        args.push(self.wxs_file.as_os_str().into());

        for (name, path) in &self.bindpaths {
            args.push("-bindpath".into());
            args.push(format!("{name}={}", path.display()).into());
        }

        for (key, value) in defines {
            args.push("-d".into());
            args.push(format!("{key}={value}").into());
        }

        args.push("-o".into());
        args.push(output.as_os_str().into());

        args
    }

    fn run_hook(&self, label: &str, argv: &[String], env: &BTreeMap<String, String>) -> Result<()> {
        let program = &argv[0];
        let hook_args = &argv[1..];

        eprintln!("Running {label} hook: {}", argv.join(" "));

        let status = std::process::Command::new(program)
            .args(hook_args)
            .envs(env)
            .current_dir(&self.workspace_root)
            .status()?;

        if !status.success() {
            return Err(Error::HookFailed {
                command: argv.join(" "),
                code: status.code().unwrap_or(-1),
            });
        }

        Ok(())
    }
}

#[cfg(test)]
#[path = "builder_tests.rs"]
mod builder_tests;
