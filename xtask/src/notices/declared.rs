//! Components no package manager declares: the fonts and the binaries Hole ships as they came.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::config::{Declared, TextSource, VersionSource};
use super::take::LicenceDirs;
use super::{go, rust_std, Component, Config, NoticesError, Origin};
use crate::bindir::{bindir_entries, upstream_library_path};
use crate::manifest::Platform;

/// What makes everything under `.cache/`.
const PROVISION: &str = "cargo xtask deps";

/// The folder of fonts the UI ships; every file in it needs an entry. So does every file the BINDIR ships as it came
/// from upstream.
const FONTS_DIR: &str = "ui/fonts";

/// The declared components of `platform`'s artifact, from `config` as [`Config::for_platform`] left it for that platform.
/// Fails when a file that ships as it is has no entry, or when an entry names a file or folder that is not there.
pub fn collect(platform: &Platform, repo_root: &Path, config: &Config) -> Result<Vec<Component>, NoticesError> {
    let mut covered = BTreeSet::new();
    let mut components = Vec::new();

    for entry in &config.declared {
        for file in &entry.files {
            require(repo_root, &entry.name, file, Path::is_file)?;
            covered.insert(file.clone());
        }
        if let Some(dir) = &entry.dir {
            require(repo_root, &entry.name, dir, Path::is_dir)?;
            require_licence_file(repo_root, dir)?;
        }
        let (source_dir, text_dir) = folders_of(entry, repo_root)?;
        components.push(Component {
            name: entry.name.clone(),
            version: version_of(entry, repo_root)?,
            origin: Origin::Declared,
            license: Some(entry.license.clone()),
            source_dir,
            url: entry.url.clone(),
            modified_copy: false,
            replaces: None,
            text_dir,
        });
    }

    for path in fonts(repo_root)? {
        if !covered.contains(&path) {
            return Err(NoticesError::UnlistedFile { path });
        }
    }
    // The BINDIR names what ships as it came from upstream; an entry covers it by the repository path it is provisioned at.
    for entry in bindir_entries(platform.os) {
        if entry.kind.needs_a_declared_entry() {
            let path = upstream_library_path(&entry.name)
                .expect("every upstream library of the BINDIR has a path in `bindir::upstream_library_path`");
            if !covered.contains(path) {
                return Err(NoticesError::UnlistedFile { path: path.to_owned() });
            }
        }
    }
    Ok(components)
}

/// The folders an entry's texts come from: the folder of its own licence files (`dir`), and the folder of the file its
/// `text_from` names: the Rust toolchain's, which must be the pinned one, or the Go toolchain's that builds `ex-ray`.
fn folders_of(entry: &Declared, repo_root: &Path) -> Result<(Option<PathBuf>, Option<PathBuf>), NoticesError> {
    match entry.text_from {
        None => Ok((entry.dir.as_ref().map(|dir| repo_root.join(dir)), None)),
        Some(TextSource::RustToolchainCopyright) => {
            let toolchain = rust_std::toolchain(repo_root)?;
            toolchain.require_pinned(&rust_toolchain_channel(repo_root)?)?;
            Ok((None, Some(rust_std::doc_dir(&toolchain.sysroot))))
        }
        Some(TextSource::GoToolchain) => Ok((None, Some(go::toolchain(repo_root)?.root))),
    }
}

/// The version an entry states, or reads from the file that pins it.
fn version_of(entry: &Declared, repo_root: &Path) -> Result<String, NoticesError> {
    match entry.version_from {
        None => Ok(entry.version.clone().unwrap_or_default()),
        Some(VersionSource::RustToolchain) => rust_toolchain_channel(repo_root),
        Some(VersionSource::GoToolchain) => Ok(go::toolchain(repo_root)?.version),
    }
}

fn rust_toolchain_channel(repo_root: &Path) -> Result<String, NoticesError> {
    let path = repo_root.join("rust-toolchain.toml");
    let text = std::fs::read_to_string(&path).map_err(|source| NoticesError::Io {
        path: path.clone(),
        source,
    })?;
    let tool = |reason: String| NoticesError::Tool {
        command: "read rust-toolchain.toml".to_owned(),
        reason,
    };
    let parsed: toml::Table = text.parse().map_err(|e: toml::de::Error| tool(e.to_string()))?;
    parsed
        .get("toolchain")
        .and_then(|toolchain| toolchain.get("channel"))
        .and_then(toml::Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| tool("`[toolchain] channel` is missing".to_owned()))
}

/// The files in the fonts folder and the folders under it, repository-relative with `/`.
fn fonts(repo_root: &Path) -> Result<Vec<String>, NoticesError> {
    let mut files = Vec::new();
    walk(&repo_root.join(FONTS_DIR), FONTS_DIR, &mut files)?;
    files.sort();
    Ok(files)
}

/// Add to `files` every file under `dir`, named by `relative` (the path of `dir`) and its own name.
fn walk(dir: &Path, relative: &str, files: &mut Vec<String>) -> Result<(), NoticesError> {
    let io = |source| NoticesError::Io {
        path: dir.to_owned(),
        source,
    };
    for entry in std::fs::read_dir(dir).map_err(io)? {
        let entry = entry.map_err(io)?;
        let name = format!("{relative}/{}", entry.file_name().to_string_lossy());
        match entry.path().is_dir() {
            true => walk(&entry.path(), &name, files)?,
            false => files.push(name),
        }
    }
    Ok(())
}

fn require(repo_root: &Path, entry: &str, path: &str, exists: fn(&Path) -> bool) -> Result<(), NoticesError> {
    if exists(&repo_root.join(path)) {
        return Ok(());
    }
    // Anything under `.cache/` is made by a provisioning command, not kept in the repository.
    if path.starts_with(".cache/") {
        return Err(NoticesError::Provision {
            what: path.to_owned(),
            command: PROVISION.to_owned(),
        });
    }
    Err(NoticesError::UnusedEntry {
        entry: entry.to_owned(),
        reason: format!("names `{path}`, which does not exist"),
    })
}

/// A folder under `.cache/` is filled by a provisioning command, so one that holds no licence file is a cache that an
/// older command filled: the command fills it again.
fn require_licence_file(repo_root: &Path, dir: &str) -> Result<(), NoticesError> {
    if !dir.starts_with(".cache/") || LicenceDirs::default().has_licence_file(&repo_root.join(dir))? {
        return Ok(());
    }
    Err(NoticesError::Provision {
        what: format!("a licence file in {dir}/"),
        command: PROVISION.to_owned(),
    })
}
