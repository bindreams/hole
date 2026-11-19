//! `cargo xtask notices`: the third-party notices file of one platform's `hole` artifact.
//!
//! [`config`] reads `.config/notices.yaml`, [`take()`] picks the licence followed for a [`Component`] and the text printed
//! for it. Every failure is a [`NoticesError`] that names the component and the entry to add.

use std::path::{Path, PathBuf};

use crate::manifest::Platform;

pub mod config;
pub mod declared;
pub mod go;
pub mod npm;
pub mod render;
pub mod rust;
pub mod rust_std;
pub mod take;

pub use config::Config;
pub use take::{take, LicenseText, Taken, TextKind};

/// Every third-party component of `platform`'s artifact. `config` is [`Config::for_platform`] of `platform`. Fails on an
/// override that matches no component. `hole_version` addresses modified Go copies in that release's source.
pub fn collect(
    platform: &Platform,
    repo_root: &Path,
    config: &Config,
    hole_version: &str,
) -> Result<Vec<Component>, NoticesError> {
    let metadata = rust::read_metadata(repo_root, crate::target::target_triple(*platform))?;
    let mut components = rust::collect(&metadata, rust::ROOTS)?;
    let listing = go::list(repo_root, platform)?;
    components.extend(go::collect(&listing, repo_root, &render::source_url(hole_version))?);
    components.extend(npm::collect(repo_root, platform)?);
    components.extend(declared::collect(platform, repo_root, config)?);
    check_overrides_used(config, &components)?;
    Ok(components)
}

/// Where a run for the host's own artifact writes its file, relative to the repository root. What stages the host's file
/// reads this one path, and none derives it.
pub const HOST_OUTPUT: &str = ".cache/notices/NOTICES.md";

/// Where a run for `platform` writes its file when `--out` is not given, relative to the repository root: [`HOST_OUTPUT`]
/// when `platform` is `host`, however it came to be named, and any other platform's own folder. A host that is not known
/// is no platform's, so a platform named on it is another.
pub fn default_output(platform: &Platform, host: Option<Platform>) -> PathBuf {
    match host == Some(*platform) {
        true => PathBuf::from(HOST_OUTPUT),
        false => PathBuf::from(".cache/notices")
            .join(format!("{}-{}", platform.os, platform.arch))
            .join("NOTICES.md"),
    }
}

/// Write the notices file of `platform`'s `hole` artifact to `out` and return its path.
///
/// Every component that cannot be placed is reported together, each with the entry that would settle it.
pub fn generate(platform: &Platform, repo_root: &Path, out: &Path) -> anyhow::Result<PathBuf> {
    let config = Config::load(repo_root)?.for_platform(platform);
    let version =
        xtask_lib::version::cargo_toml_version_for_group(repo_root, xtask_lib::version::Group::Hole)?.to_string();
    let components = collect(platform, repo_root, &config, &version)?;

    let out = repo_root.join(out);
    let written = write_from(components, &config, &version, &out)?;

    let count = |origins: &[Origin]| {
        written
            .taken
            .iter()
            .filter(|(c, _)| origins.contains(&c.origin))
            .count()
    };
    eprintln!(
        "xtask: {}: {} crates, {} Go modules and packages, {} npm packages, {} declared; {} bytes",
        out.display(),
        count(&[Origin::Crate]),
        count(&[Origin::GoModule, Origin::GoPackage]),
        count(&[Origin::Npm]),
        count(&[Origin::Declared]),
        written.bytes
    );
    Ok(out)
}

/// What [`write_from`] wrote.
#[derive(Debug)]
pub struct Written {
    pub taken: Vec<(Component, Taken)>,
    pub bytes: usize,
}

/// Take the licence and text of every one of `components` and write the notices file of Hole `hole_version` to `out`.
/// One that cannot be placed is reported with every other that cannot, in one error; any other error stops the run where
/// it arises. Nothing is written unless all are placed.
pub fn write_from(
    components: Vec<Component>,
    config: &Config,
    hole_version: &str,
    out: &Path,
) -> anyhow::Result<Written> {
    let mut taken = Vec::new();
    let mut unplaced = Vec::new();
    for component in components {
        match take(&component, config) {
            Ok(text) => taken.push((component, text)),
            Err(e) if e.is_about_one_component() => unplaced.push(e),
            Err(e) => return Err(e.into()),
        }
    }
    if !unplaced.is_empty() {
        let list: String = unplaced.iter().map(|e| format!("\n  - {e}")).collect();
        anyhow::bail!("{} components cannot be placed:{list}", unplaced.len());
    }

    let text = render::render(hole_version, &taken);
    write_output(out, &text)?;
    Ok(Written {
        taken,
        bytes: text.len(),
    })
}

/// Write `text` to `out`, creating its folder. An existing file is replaced, never written through: `stage` hard-links
/// the generated file into the folders it stages, and a later generation must not change those.
fn write_output(out: &Path, text: &str) -> anyhow::Result<()> {
    use anyhow::Context;

    if let Some(dir) = out.parent() {
        std::fs::create_dir_all(dir).with_context(|| format!("failed to create {}", dir.display()))?;
    }
    crate::stage::write_replacing(out, text.as_bytes())
}

/// Fails on an override whose component is not among `components`.
pub fn check_overrides_used(config: &Config, components: &[Component]) -> Result<(), NoticesError> {
    for entry in &config.overrides {
        let used = components.iter().any(|component| entry.applies_to(component));
        if !used {
            return Err(NoticesError::UnusedEntry {
                entry: entry.name.clone(),
                reason: format!(
                    "(under `overrides:`{}) matches no component of this artifact; remove it, fix its `name` or `version`, \
                     or limit its `platforms:` to the artifacts that carry the component",
                    entry
                        .version
                        .as_ref()
                        .map(|v| format!(", version {v}"))
                        .unwrap_or_default()
                ),
            });
        }
    }
    Ok(())
}

/// One third-party thing in an artifact.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub name: String,
    pub version: String,
    pub origin: Origin,
    /// The SPDX expression the component declares; `None` when its ecosystem declares none.
    pub license: Option<String>,
    /// The folder holding the component's own licence files.
    pub source_dir: Option<PathBuf>,
    /// Where the component's source can be had; printed beside its name.
    pub url: Option<String>,
    /// A Go module replaced by a copy that this repository keeps and patches: `name` and `version` are the upstream's
    /// it was derived from, and `url` is the address of the copy.
    pub modified_copy: bool,
    /// For a Go module replaced by another module's version, `name version` of the module it replaces: `name`, `version`
    /// and `url` are the replacement's, which is what is linked.
    pub replaces: Option<String>,
    /// The folder holding the file a declared entry's `text_from` names, for a component whose texts are not its own
    /// licence files.
    pub text_dir: Option<PathBuf>,
}

impl Component {
    /// `name version` (just the name when it has no version), how a message and the notices file name it; a modified
    /// copy is named for what it was derived from, and a replacement for what it replaces.
    pub fn label(&self) -> String {
        let name = match self.version.as_str() {
            "" => self.name.clone(),
            version => format!("{} {version}", self.name),
        };
        let name = match &self.replaces {
            Some(replaced) => format!("{name} (replacing {replaced})"),
            None => name,
        };
        match self.modified_copy {
            true => format!("modified copy of {name}"),
            false => name,
        }
    }
}

impl Origin {
    /// Whether the component is listed by hand in `.config/notices.yaml`, under `declared:`.
    pub fn is_declared_by_hand(self) -> bool {
        match self {
            Origin::Crate => false,
            Origin::GoModule => false,
            Origin::GoPackage => false,
            Origin::Npm => false,
            Origin::Declared => true,
        }
    }

    /// The package ecosystem the component's name belongs to, for what an entry of `overrides:` names; `None` for a
    /// component no ecosystem lists.
    pub fn ecosystem(self) -> Option<config::Ecosystem> {
        match self {
            Origin::Crate => Some(config::Ecosystem::Crate),
            Origin::GoModule => Some(config::Ecosystem::Go),
            Origin::GoPackage => Some(config::Ecosystem::Go),
            Origin::Npm => Some(config::Ecosystem::Npm),
            Origin::Declared => None,
        }
    }
}

impl Origin {
    /// The sentence that tells a reader what to write in `.config/notices.yaml` to give the component `name` the `field`
    /// its files lack. A declared component has its own entry and the field goes into it; any other is reached by an
    /// `overrides:` entry of its ecosystem, which cannot reach a declared one.
    pub fn entry_to_add(self, name: &str, field: &str) -> String {
        match self {
            Origin::Crate => config::Ecosystem::Crate.entry_to_add(name, field),
            Origin::GoModule => config::Ecosystem::Go.entry_to_add(name, field),
            Origin::GoPackage => config::Ecosystem::Go.entry_to_add(name, field),
            Origin::Npm => config::Ecosystem::Npm.entry_to_add(name, field),
            Origin::Declared => format!("Add `{field}` to the `declared:` entry for `{name}` in .config/notices.yaml"),
        }
    }
}

/// Where a [`Component`] came from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Crate,
    /// A Go module that holds linked packages.
    GoModule,
    /// A Go package that carries a licence of its own beside its module's.
    GoPackage,
    Npm,
    /// Listed by hand in `.config/notices.yaml`: no package manager declares it.
    Declared,
}

/// Why generation stopped. Each variant names what was met and the entry of `.config/notices.yaml` that settles it.
#[derive(Debug, thiserror::Error)]
pub enum NoticesError {
    #[error("{}: {source}", path.display())]
    Io { path: PathBuf, source: std::io::Error },

    #[error("{} is not UTF-8 text; a licence file is printed as it is, so it must be", path.display())]
    NotUtf8 { path: PathBuf },

    #[error("{path}: {reason}")]
    Config { path: String, reason: String },

    #[error("{what} is missing; `{command}` provides it")]
    Provision { what: String, command: String },

    /// A tool ran and said something this generator cannot read, or failed.
    #[error("{command}: {reason}")]
    Tool { command: String, reason: String },

    #[error("the entry of .config/notices.yaml for `{entry}` {reason}; fix or remove it")]
    UnusedEntry { entry: String, reason: String },

    #[error(
        "{path} ships as it is, and no `declared:` entry in .config/notices.yaml lists it under `files:`. Add one with its \
         name, licence, and a holder line or text read from its upstream"
    )]
    UnlistedFile { path: String },

    #[error(
        "{component}: the licence `{expression}` does not parse: {reason}. {} (its `license` replaces the one that does not parse)",
        ecosystem.entry_to_add(name, &format!("version: {version:?}, license: <SPDX expression>"))
    )]
    BadExpression {
        component: String,
        ecosystem: config::Ecosystem,
        name: String,
        version: String,
        expression: String,
        reason: String,
    },

    #[error(
        "{component}: no licence in `{expression}` is on the list. Read the component's licence, and if it is compatible \
         with GPL-3.0-or-later and this file meets its duty for a binary copy, add it to `licenses:` in .config/notices.yaml"
    )]
    LicenseNotOnList { component: String, expression: String },

    #[error(
        "{component}: declares no licence. {} after reading its licence file",
        ecosystem.entry_to_add(name, &format!("version: {version:?}, license: <SPDX expression>"))
    )]
    NoLicense {
        component: String,
        ecosystem: config::Ecosystem,
        name: String,
        version: String,
    },

    #[error(
        "{component}: `{license}` requires its notice to accompany a binary copy, and the component ships no licence file. {} with the text read from its upstream repository",
        origin.entry_to_add(name, &format!("texts: [{{license: {license}, text: ..., source: <upstream URL>}}]"))
    )]
    NoText {
        component: String,
        origin: Origin,
        name: String,
        license: String,
    },

    #[error(
        "{component}: the .config/notices.yaml entry for `{name}` supplies `{license}`, which is not a licence followed \
         for this component that asks for its own text; remove that item from its `texts:`"
    )]
    UnusedText {
        component: String,
        name: String,
        license: String,
    },

    #[error(
        "{component}: declares the licence `{declared}`, and the .config/notices.yaml entry for `{name}` (version \
         {version}) sets `license: {entry}`; remove `license:` from that entry, which replaces only a licence that is \
         missing or does not parse"
    )]
    LicenseConflict {
        component: String,
        name: String,
        version: String,
        declared: String,
        entry: String,
    },
}

impl NoticesError {
    /// Whether the error is about the licence of one component, which the generator collects with the others that
    /// cannot be placed and reports together; any other error stops the run where it arises. One arm per variant: a
    /// variant that shares a consequence with another is still its own decision.
    pub fn is_about_one_component(&self) -> bool {
        match self {
            NoticesError::Io { .. } => false,
            NoticesError::NotUtf8 { .. } => false,
            NoticesError::Config { .. } => false,
            NoticesError::Provision { .. } => false,
            NoticesError::Tool { .. } => false,
            NoticesError::UnusedEntry { .. } => false,
            NoticesError::UnlistedFile { .. } => false,
            NoticesError::BadExpression { .. } => true,
            NoticesError::LicenseNotOnList { .. } => true,
            NoticesError::NoLicense { .. } => true,
            NoticesError::NoText { .. } => true,
            NoticesError::UnusedText { .. } => true,
            NoticesError::LicenseConflict { .. } => true,
        }
    }
}

#[cfg(test)]
#[path = "notices/declared_tests.rs"]
mod declared_tests;
#[cfg(test)]
#[path = "notices/go_tests.rs"]
mod go_tests;
#[cfg(test)]
#[path = "notices_tests.rs"]
mod notices_tests;
#[cfg(test)]
#[path = "notices/npm_tests.rs"]
mod npm_tests;
#[cfg(test)]
#[path = "notices/remedy_tests.rs"]
mod remedy_tests;
#[cfg(test)]
#[path = "notices/render_tests.rs"]
mod render_tests;
#[cfg(test)]
#[path = "notices/rust_std_tests.rs"]
mod rust_std_tests;
#[cfg(test)]
#[path = "notices/rust_tests.rs"]
mod rust_tests;
#[cfg(test)]
#[path = "notices/take_tests.rs"]
mod take_tests;

#[cfg(test)]
#[path = "notices/config_tests.rs"]
mod config_tests;
