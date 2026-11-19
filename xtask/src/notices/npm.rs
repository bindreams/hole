//! The npm packages the UI is built from: the production packages npm installed in `node_modules`.

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use super::{Component, NoticesError, Origin};
use crate::manifest::Platform;

/// The lock file and `node_modules`, relative to the repository root.
const LOCK: &str = "package-lock.json";
const NODE_MODULES: &str = "node_modules";
/// npm's record, inside `node_modules`, of the packages it installed there.
const INSTALLED: &str = ".package-lock.json";
/// What fills `node_modules` from the lock file.
const NPM_INSTALL: &str = "cargo xtask build npm-install";

#[derive(Deserialize)]
struct Lock {
    #[serde(rename = "lockfileVersion")]
    version: u32,
    #[serde(default)]
    packages: BTreeMap<String, LockedPackage>,
}

#[derive(Deserialize)]
struct LockedPackage {
    version: Option<String>,
    license: Option<String>,
    #[serde(default)]
    dev: bool,
    /// Installed only where npm finds it fit: `os`, `cpu` and `libc` decide, and a dependency only an optional package
    /// needs is optional too.
    #[serde(default)]
    optional: bool,
    /// Both a dev dependency and an optional dependency of a non-dev package (npm's own words): not dev-only, and
    /// installed only where npm finds it fit, like `optional`.
    #[serde(default, rename = "devOptional")]
    dev_optional: bool,
}

impl LockedPackage {
    /// Whether npm may leave the package out of `node_modules`: a production-only install leaves out what is `dev`, and
    /// an install on a platform it does not fit leaves out what is `optional` or `devOptional`.
    fn may_be_left_out(&self) -> bool {
        self.dev || self.optional || self.dev_optional
    }

    /// Whether the package ships, and npm installs it only on some platforms.
    fn is_platform_bound_production(&self) -> bool {
        !self.dev && (self.optional || self.dev_optional)
    }
}

#[derive(Deserialize)]
struct Record {
    #[serde(default)]
    packages: BTreeMap<String, InstalledPackage>,
}

#[derive(Deserialize)]
struct InstalledPackage {
    version: Option<String>,
    #[serde(default)]
    dev: bool,
}

/// The part of a package's own `package.json` that says which version is in its folder.
#[derive(Deserialize)]
struct Manifest {
    version: Option<String>,
}

/// The production packages npm installed in `repo_root`'s `node_modules`, read from the folder's own record of them
/// (`node_modules/.package-lock.json`) and checked against `package-lock.json`, for the artifact of `target`.
pub fn collect(repo_root: &Path, target: &Platform) -> Result<Vec<Component>, NoticesError> {
    let modules = repo_root.join(NODE_MODULES);
    if !modules.is_dir() {
        return Err(NoticesError::Provision {
            what: format!("{NODE_MODULES}/ (the UI's npm packages)"),
            command: NPM_INSTALL.to_owned(),
        });
    }
    let read = |path: std::path::PathBuf| {
        std::fs::read_to_string(&path).map_err(|source| match source.kind() {
            std::io::ErrorKind::NotFound if path.ends_with(INSTALLED) => NoticesError::Provision {
                what: format!("{NODE_MODULES}/{INSTALLED} (npm's record of what it installed)"),
                command: NPM_INSTALL.to_owned(),
            },
            _ => NoticesError::Io { path, source },
        })
    };
    let lock = read(repo_root.join(LOCK))?;
    let installed = read(modules.join(INSTALLED))?;
    collect_installed(&lock, &installed, &modules, target, Platform::host())
}

/// The components of a `package-lock.json` (version 2 or later) over `installed`, the text of npm's record of what it
/// put in `node_modules`: every package of the record that is not dev-only, except the root project. Sorted by name.
///
/// What ships is what the lock says and what is installed is what the record says, and they agree entry by entry:
/// - each package of the record is in the lock at the same version, marked `dev` or not alike;
/// - each package of the lock that the record lacks is `dev`, `optional` or `devOptional` (npm leaves any of those out:
///   a production-only install, or a platform the package does not fit); one with none of the three is a production
///   package and must be there;
/// - each component's folder holds a `package.json` of the version the record gives, since the licence files are read
///   from that folder.
///
/// Anything else is a `node_modules` that is not what the lock describes. The record is the host's: a `target` other
/// than `host` can be read only when the lock has no production package that is `optional` or `devOptional`, which is
/// then installed on every platform alike.
pub fn collect_installed(
    lock: &str,
    installed: &str,
    node_modules: &Path,
    target: &Platform,
    host: Option<Platform>,
) -> Result<Vec<Component>, NoticesError> {
    let lock_error = |reason: String| NoticesError::Tool {
        command: LOCK.to_owned(),
        reason,
    };
    let lock: Lock = serde_json::from_str(lock).map_err(|e| lock_error(format!("does not parse: {e}")))?;
    if lock.version < 2 {
        return Err(lock_error(format!(
            "has lockfileVersion {}, which lists no packages; regenerate it with a current npm",
            lock.version
        )));
    }
    if host != Some(*target) {
        let platform_bound = lock
            .packages
            .iter()
            .filter(|(_, package)| package.is_platform_bound_production())
            .find_map(|(key, _)| name_of(key));
        if let Some(name) = platform_bound {
            return Err(lock_error(format!(
                "lists the production package {name}, which npm installs only on some platforms, so the npm set can \
                 only be read on the platform it is for: run this on {target}"
            )));
        }
    }
    let record: Record = serde_json::from_str(installed).map_err(|e| NoticesError::Tool {
        command: format!("{NODE_MODULES}/{INSTALLED}"),
        reason: format!("does not parse: {e}"),
    })?;
    let mismatch = |detail: String| NoticesError::Provision {
        what: format!("{NODE_MODULES}/ as {LOCK} lists it ({detail})"),
        command: NPM_INSTALL.to_owned(),
    };

    let mut components = Vec::new();
    for (key, package) in &record.packages {
        let Some(name) = name_of(key) else { continue };
        let version = package.version.as_deref().ok_or_else(|| NoticesError::Tool {
            command: format!("{NODE_MODULES}/{INSTALLED}"),
            reason: format!("lists {key} with no version"),
        })?;
        let locked = lock
            .packages
            .get(key)
            .ok_or_else(|| mismatch(format!("{name} {version} is installed and the lock does not list it")))?;
        match locked.version.as_deref() {
            Some(listed) if listed == version => {}
            listed => {
                return Err(mismatch(format!(
                    "{name} {version} is installed and the lock lists {}",
                    listed.unwrap_or("no version")
                )))
            }
        }
        if package.dev != locked.dev {
            let kind = |dev: bool| if dev { "dev-only" } else { "production" };
            return Err(mismatch(format!(
                "{name} {version} is installed as a {} package and the lock lists it as a {} one",
                kind(package.dev),
                kind(locked.dev)
            )));
        }
        if package.dev {
            continue;
        }
        let dir = node_modules.join(key.strip_prefix(&format!("{NODE_MODULES}/")).unwrap_or(key));
        let manifest = std::fs::read_to_string(dir.join("package.json")).map_err(|e| {
            mismatch(format!(
                "{name} {version} has no readable package.json in its folder: {e}"
            ))
        })?;
        let in_folder = serde_json::from_str::<Manifest>(&manifest)
            .map_err(|e| mismatch(format!("the package.json of {name} {version} does not parse: {e}")))?
            .version;
        if in_folder.as_deref() != Some(version) {
            return Err(mismatch(format!(
                "{name} {version} is installed and its folder holds {}",
                in_folder.as_deref().unwrap_or("a package.json with no version")
            )));
        }
        components.push(Component {
            url: Some(format!("https://www.npmjs.com/package/{name}/v/{version}")),
            modified_copy: false,
            replaces: None,
            text_dir: None,
            name: name.to_owned(),
            version: version.to_owned(),
            origin: Origin::Npm,
            license: locked.license.clone(),
            source_dir: Some(dir),
        });
    }

    for (key, locked) in &lock.packages {
        let Some(name) = name_of(key) else { continue };
        if !locked.may_be_left_out() && !record.packages.contains_key(key) {
            let version = locked.version.as_deref().unwrap_or("with no version");
            return Err(mismatch(format!("{name} {version} is not installed")));
        }
    }

    components.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    Ok(components)
}

/// The package a lock key is for: the key is the install path, `node_modules/a`, or `node_modules/a/node_modules/b` for
/// a nested copy. `None` for the root project's key.
fn name_of(key: &str) -> Option<&str> {
    key.rsplit_once(&format!("{NODE_MODULES}/")).map(|(_, name)| name)
}
