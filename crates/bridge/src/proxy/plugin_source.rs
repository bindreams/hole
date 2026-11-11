//! Where the bridge finds the plugins it runs, and the proof that a path is one of them.
//!
//! The bridge runs as root (or SYSTEM), and a bare name handed to the plugin spawner is looked up on the inherited
//! `PATH`, which is user-writable when the bridge is elevated from the GUI. So the only thing the spawner accepts is a
//! [`BundledPlugin`], and the only thing that builds one is [`PluginSource::resolve`]: a plugin Hole ships, in the
//! folder this source says Hole's plugins live in.
//!
//! [`PluginSource`] is the one owner of "where are the plugins" for every platform and mode; a caller asks it for a
//! path and never sees which platform it is on. Per-variant behaviour is a method of the type, one exhaustive match
//! each, and no other file names a variant except the per-platform constructors.

use std::path::{Path, PathBuf};

use hole_common::plugin;
use thiserror::Error;
use util::versioned_file::WhyUnreadable;

use crate::plugin_repair::layout_stamp::STAMP_FILE_NAME;
use crate::plugin_repair::layout_stamp::{self, StampState};
use crate::plugin_repair::{PluginDirLayout, RepairVerdict, Standing};

// Where the plugins are ===============================================================================================

/// Where bundled plugins are looked up.
#[derive(Debug, Clone)]
pub enum PluginSource {
    /// The macOS service: a fixed folder only root can write, that the service fills from the plugins `hole` carries.
    /// Not derived from the executable. Resolves a plugin only once this start's repair left the folder holding
    /// what `hole` carries.
    Managed {
        layout: PluginDirLayout,
        /// A folder only root can write, where plugins that extract themselves put what they extract.
        runtime_dir: PathBuf,
        /// How the repair of this start ended: the one judge of whether the folder may be run from.
        verdict: RepairVerdict,
    },
    /// The Windows service: beside the installed bridge executable, where the installer put them.
    InstallDir { exe: BridgeExe },
    /// A foreground run: beside the bridge executable, which is a staged build directory.
    BuildDir { exe: BridgeExe },
    /// `--plugin-dir` where the platform keeps no stamp: the admin's folder, read and never written.
    Explicit { dir: PathBuf },
    /// `--plugin-dir` on macOS: the admin's folder, read and never written. The stamp says which folder this is (a
    /// Hole plugin folder, not any other), not who wrote it: the folder must carry a current stamp, read under the
    /// bridge's vouched-read rules (the real folder, not a user's link to one somebody else owns), and nothing more
    /// is checked.
    ExplicitStamped { dir: PathBuf },
}

/// The bridge executable a source looks beside.
#[derive(Debug, Clone)]
pub enum BridgeExe {
    /// The running executable, asked of the OS each time a plugin is resolved.
    Running,
    /// This executable, for a staged install.
    At(PathBuf),
    /// An executable the OS cannot name, as a failing `current_exe()`: for a test.
    #[cfg(test)]
    Unknown,
}

impl BridgeExe {
    fn path(&self) -> std::io::Result<PathBuf> {
        match self {
            BridgeExe::Running => std::env::current_exe(),
            BridgeExe::At(exe) => Ok(exe.clone()),
            #[cfg(test)]
            BridgeExe::Unknown => Err(std::io::Error::new(
                std::io::ErrorKind::NotFound,
                "staged: no bridge executable",
            )),
        }
    }
}

impl Default for PluginSource {
    /// Beside the running executable: what a development build and a test run use.
    fn default() -> Self {
        Self::build_dir(BridgeExe::Running)
    }
}

impl PluginSource {
    /// Beside `exe`, the bridge executable of a staged build directory.
    pub fn build_dir(exe: BridgeExe) -> Self {
        PluginSource::BuildDir { exe }
    }

    /// The bundled plugin `name` names, found in this source's folder, or why it cannot run. Side-effect free.
    ///
    /// A friendly name (`v2ray-plugin`) resolves to its `binary_name` (`ex-ray`).
    pub fn resolve(&self, name: &str) -> Result<BundledPlugin, PluginResolveError> {
        let descriptor = bundled_descriptor(name)?;
        let file_name = format!("{}{}", descriptor.binary_name, std::env::consts::EXE_SUFFIX);
        let dir = self.root(name)?;
        let path = dir.join(&file_name);
        if path.is_file() {
            Ok(BundledPlugin {
                descriptor,
                path,
                runtime_dir: self.runtime_dir().map(Path::to_path_buf),
            })
        } else {
            Err(PluginResolveError::BinaryMissing {
                plugin: name.to_string(),
                binary: file_name,
                remedy: self.remedy(),
            })
        }
    }

    /// A folder only root can write, for a plugin that extracts something at run time. `None` where the plugin's own
    /// default is as safe as it gets.
    pub fn runtime_dir(&self) -> Option<&Path> {
        match self {
            PluginSource::Managed { runtime_dir, .. } => Some(runtime_dir),
            PluginSource::InstallDir { .. } => None,
            PluginSource::BuildDir { .. } => None,
            PluginSource::Explicit { .. } => None,
            PluginSource::ExplicitStamped { .. } => None,
        }
    }

    /// The folder to look in for `plugin`, or why there is none.
    fn root(&self, plugin: &str) -> Result<PathBuf, PluginResolveError> {
        match self {
            PluginSource::Managed {
                layout,
                runtime_dir,
                verdict,
            } => match verdict.standing() {
                Standing::Vouched => Ok(layout.dir.clone()),
                Standing::NotPrepared => Err(PluginResolveError::FolderNotPrepared {
                    plugin: plugin.to_string(),
                }),
                Standing::FolderNotRepaired => Err(PluginResolveError::FolderNotRepaired {
                    plugin: plugin.to_string(),
                }),
                Standing::RuntimeDirNotMade => Err(PluginResolveError::RuntimeDirNotMade {
                    plugin: plugin.to_string(),
                    dir: runtime_dir.clone(),
                }),
                Standing::StampUnreadable(why) => Err(PluginResolveError::LayoutUnreadable {
                    plugin: plugin.to_string(),
                    stamp: layout.dir.join(STAMP_FILE_NAME).display().to_string(),
                    why,
                    remedy: "Move the file aside while Hole is stopped, and Hole will rebuild the folder.",
                }),
            },
            PluginSource::InstallDir { exe } => beside(exe, plugin),
            PluginSource::BuildDir { exe } => beside(exe, plugin),
            PluginSource::Explicit { dir } => Ok(dir.clone()),
            PluginSource::ExplicitStamped { dir } => match layout_stamp::state(dir) {
                StampState::Current => Ok(dir.clone()),
                // Only to word the error: a stamp is never taken from a folder that is not there.
                StampState::Nothing if is_gone(dir) => Err(PluginResolveError::PluginDirNotFound {
                    plugin: plugin.to_string(),
                }),
                StampState::Nothing => Err(PluginResolveError::NotAPluginFolder {
                    plugin: plugin.to_string(),
                }),
                StampState::Unreadable(why) => Err(PluginResolveError::LayoutUnreadable {
                    plugin: plugin.to_string(),
                    // The admin named this folder; the message does not.
                    stamp: format!("{STAMP_FILE_NAME} in the `--plugin-dir` folder"),
                    why,
                    remedy: "Name the real `--plugin-dir` folder, not a link to it, and check that its layout file is readable.",
                }),
            },
        }
    }

    /// What to do about a plugin missing from this source's folder.
    fn remedy(&self) -> &'static str {
        match self {
            PluginSource::Managed { .. } => "Reinstall Hole.",
            PluginSource::InstallDir { .. } => "Reinstall Hole.",
            PluginSource::BuildDir { .. } => "Run `cargo xtask stage` to stage the plugins, or pass `--plugin-dir`.",
            PluginSource::Explicit { .. } => "Check the `--plugin-dir` folder.",
            PluginSource::ExplicitStamped { .. } => "Check the `--plugin-dir` folder.",
        }
    }
}

/// Whether nothing is at `dir`. A path that cannot be looked at is not gone.
fn is_gone(dir: &Path) -> bool {
    matches!(std::fs::symlink_metadata(dir), Err(e) if e.kind() == std::io::ErrorKind::NotFound)
}

/// `dir` as the absolute path of a directory, for a `--plugin-dir` folder. Made absolute without resolving a link: the
/// bridge reads the folder, and a link in the path is the admin's own.
pub fn absolute_plugin_dir(dir: PathBuf) -> std::io::Result<PathBuf> {
    let dir = std::path::absolute(dir)?;
    match std::fs::metadata(&dir) {
        Ok(meta) if meta.is_dir() => Ok(dir),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "the `--plugin-dir` path is not a directory",
        )),
        Err(e) => Err(e),
    }
}

/// The directory of the real file `exe` names.
fn beside(exe: &BridgeExe, plugin: &str) -> Result<PathBuf, PluginResolveError> {
    let exe_unknown = |cause| PluginResolveError::ExeUnknown {
        plugin: plugin.to_string(),
        cause,
    };
    let exe = exe.path().map_err(|e| exe_unknown(Some(e)))?;
    // Before canonicalizing: that resolves a relative path against the cwd, which would put the plugin lookup
    // wherever the process happens to be.
    if !exe.is_absolute() {
        return Err(exe_unknown(None));
    }
    // Canonicalize to resolve symlinks: the bridge may be registered via symlink, but the sibling plugin binary is
    // next to the real binary.
    let exe = match std::fs::canonicalize(&exe) {
        Ok(real) => real,
        Err(e) => {
            tracing::debug!(
                error = &e as &dyn std::error::Error,
                "bridge executable not canonicalized; resolving the plugin beside it as given"
            );
            exe
        }
    };
    exe.parent().map(Path::to_path_buf).ok_or_else(|| exe_unknown(None))
}

// What was found ======================================================================================================

/// A plugin Hole ships, bound to the binary the bridge runs for it: the only thing the plugin spawner accepts.
///
/// Only [`PluginSource::resolve`] builds one, so a value proves `descriptor` is a shipped plugin and `path` is the
/// absolute file that descriptor's binary name selects in the folder that source names.
#[derive(Debug, Clone)]
pub struct BundledPlugin {
    descriptor: &'static plugin::PluginDescriptor,
    path: PathBuf,
    runtime_dir: Option<PathBuf>,
}

impl BundledPlugin {
    pub fn descriptor(&self) -> &'static plugin::PluginDescriptor {
        self.descriptor
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The folder only root can write that this plugin extracts into, if its source has one
    /// ([`PluginSource::runtime_dir`]).
    pub fn runtime_dir(&self) -> Option<&Path> {
        self.runtime_dir.as_deref()
    }

    /// A shipped plugin pointed at an arbitrary binary, for tests that spawn a stub or run without an install dir.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str, path: impl Into<PathBuf>) -> Self {
        let descriptor = bundled_descriptor(name).unwrap_or_else(|e| panic!("for_test: {e}"));
        Self::for_test_descriptor(descriptor, path)
    }

    /// [`for_test`](Self::for_test) with a descriptor that is not in the table, for a test that needs a plugin whose
    /// descriptor says something none of the shipped ones do.
    #[cfg(test)]
    pub(crate) fn for_test_descriptor(descriptor: &'static plugin::PluginDescriptor, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        assert!(path.is_absolute(), "for_test: {path:?} is not absolute");
        Self {
            descriptor,
            path,
            runtime_dir: None,
        }
    }
}

/// The one gate for "may this plugin run": it must be one Hole ships.
fn bundled_descriptor(name: &str) -> Result<&'static plugin::PluginDescriptor, PluginResolveError> {
    plugin::lookup(name).ok_or_else(|| PluginResolveError::NotBundled { name: name.to_string() })
}

/// Why a configured plugin cannot be resolved to a binary Hole will run.
///
/// Every `Display` reaches the GUI toast verbatim. It shows the plugin name as the user configured it, escaped so that
/// whatever characters it holds stay inert, and a binary by file name; none shows a path except the fixed system ones of
/// the service's own layout file and runtime folder.
#[derive(Debug, Error)]
pub enum PluginResolveError {
    /// The name is not in [`plugin::known_plugin_names`].
    #[error(
        "plugin {name:?} is not bundled with Hole, and Hole runs only its bundled plugins. Bundled plugins: {}",
        plugin::known_plugin_names_joined()
    )]
    NotBundled { name: String },
    /// A bundled plugin whose binary is absent from the folder Hole looks in: a damaged installation, not a
    /// configuration problem. `binary` is the file name looked for (`ex-ray.exe` on Windows).
    #[error(
        "Hole's bundled plugin \"{plugin}\" is missing ({binary} not found where Hole looks for its plugins). {remedy}"
    )]
    BinaryMissing {
        plugin: String,
        binary: String,
        remedy: &'static str,
    },
    /// The bridge could not establish which directory it is installed in, so there is nowhere to look for the bundled
    /// plugin. `cause` is the OS error from `current_exe()`; it stays off the `Display`, which may not name a path.
    #[error("cannot locate the directory Hole is installed in, so its bundled plugin \"{plugin}\" cannot be found")]
    ExeUnknown {
        plugin: String,
        #[source]
        cause: Option<std::io::Error>,
    },
    /// The plugin folder's layout file exists and was refused (not one this release can read, or not read at all), so the
    /// folder is not run from.
    #[error("the layout file of Hole's plugin folder ({stamp}) was refused ({why}), so Hole will not run its bundled plugin \"{plugin}\" from that folder. {remedy}")]
    LayoutUnreadable {
        plugin: String,
        stamp: String,
        why: WhyUnreadable,
        remedy: &'static str,
    },
    /// The service has not yet made its plugin folder hold the bundled plugins.
    #[error(
        "Hole has not finished preparing its plugin folder, so it will not run its bundled plugin \"{plugin}\" yet"
    )]
    FolderNotPrepared { plugin: String },
    /// The service could not make its plugin folder hold the bundled plugins, so what is there may be anything.
    #[error("Hole could not make its plugin folder hold the bundled plugins (the bridge log says why), so it will not run its bundled plugin \"{plugin}\" from it. Reinstall Hole.")]
    FolderNotRepaired { plugin: String },
    /// The service could not make the folder plugins extract into, so plugins are not run. The plugin folder itself is
    /// fine; something may be in the way of `dir`.
    #[error("Hole could not make {}, the folder its bundled plugins run in (something may be in the way of it; the bridge log says why), so it will not run its bundled plugin \"{plugin}\". Remove what is at that path, and Hole makes it at its next start.", dir.display())]
    RuntimeDirNotMade { plugin: String, dir: PathBuf },
    /// The `--plugin-dir` folder carries no current layout file, so it is not a plugin folder Hole made.
    #[error("the `--plugin-dir` folder is not a Hole plugin folder (it has no current layout file), so Hole will not run its bundled plugin \"{plugin}\" from it")]
    NotAPluginFolder { plugin: String },
    /// The `--plugin-dir` folder is not there (it was removed after the bridge started).
    #[error("the `--plugin-dir` folder was not found, so Hole cannot run its bundled plugin \"{plugin}\" from it")]
    PluginDirNotFound { plugin: String },
}

#[cfg(test)]
#[path = "plugin_source_tests.rs"]
mod plugin_source_tests;
