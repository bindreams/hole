//! The Go modules linked into `ex-ray`, from `go list -deps`.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Deserialize;

use super::take::{LicenceDirs, LicenseText, Taken, TextKind};
use super::{Component, NoticesError, Origin};
use crate::manifest::Platform;

/// Where the Go module of `ex-ray` is.
const EX_RAY_DIR: &str = "crates/ex-ray";

const LICENSE_FILE: &str = "LICENSE";

/// What `go list -deps -json` says about one package.
#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoPackage {
    import_path: String,
    dir: Option<PathBuf>,
    #[serde(default)]
    standard: bool,
    module: Option<GoModule>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoModule {
    path: String,
    version: Option<String>,
    #[serde(default)]
    main: bool,
    dir: Option<PathBuf>,
    replace: Option<GoReplacement>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct GoReplacement {
    /// The replacing module's path, or the directory when it is replaced by one.
    path: String,
    /// Absent when the module is replaced by a directory; set when it is replaced by another module's version.
    version: Option<String>,
    dir: Option<PathBuf>,
}

/// `go list -deps -json` of `ex-ray` for `platform`. Offline: a module that is not in the module cache fails instead of
/// being fetched.
pub fn list(repo_root: &Path, platform: &Platform) -> Result<String, NoticesError> {
    run(repo_root, &["list", "-deps", "-json", "."], Some(platform))
}

/// The Go toolchain that builds `ex-ray`.
#[derive(Clone, Debug)]
pub struct Toolchain {
    /// `go env GOVERSION`, as `go1.27.0`.
    pub version: String,
    /// `go env GOROOT`: the toolchain's folder, which holds its `LICENSE`.
    pub root: PathBuf,
}

/// The toolchain `go` selects in `ex-ray`'s own folder, as the build does: its `go.mod`'s `toolchain` line is a minimum,
/// so a newer local `go` stays and builds. `go` missing is a [`NoticesError::Tool`] naming where to get it.
pub fn toolchain(repo_root: &Path) -> Result<Toolchain, NoticesError> {
    let printed = run(repo_root, &["env", "GOVERSION", "GOROOT"], None)?;
    let mut values = printed.lines();
    match (values.next(), values.next(), values.next()) {
        (Some(version), Some(root), None) if !version.is_empty() && !root.is_empty() => Ok(Toolchain {
            version: version.to_owned(),
            root: PathBuf::from(root),
        }),
        _ => Err(NoticesError::Tool {
            command: "go env GOVERSION GOROOT".to_owned(),
            reason: format!("printed {printed:?}, not the two values asked for, one per line"),
        }),
    }
}

/// What `go <args>` prints to stdout in `ex-ray`'s folder. With a `platform` it is for that platform's artifact: without
/// cgo, and offline.
fn run(repo_root: &Path, args: &[&str], platform: Option<&Platform>) -> Result<String, NoticesError> {
    let mut command = Command::new("go");
    command.args(args).current_dir(repo_root.join(EX_RAY_DIR));
    if let Some(platform) = platform {
        command
            .env("GOOS", platform.os.to_string())
            .env("GOARCH", platform.arch.to_string())
            .env("CGO_ENABLED", "0")
            .env("GOPROXY", "off");
    }
    let line = crate::command::describe(&command);
    let output = crate::command::run_captured(&mut command)
        .map_err(crate::ex_ray::go_not_found_hint)
        .map_err(|e| NoticesError::Tool {
            command: format!("{line} (the modules come from `cargo xtask ex-ray`, which runs `go mod download`)"),
            reason: format!("{e:#}"),
        })?;
    String::from_utf8(output.stdout).map_err(|_| NoticesError::Tool {
        command: line,
        reason: "printed output that is not UTF-8".to_owned(),
    })
}

/// The licence of a Go toolchain: its `LICENSE`, as it is, which the standard library is under.
pub fn taken(toolchain_root: &Path, license: String) -> Result<Taken, NoticesError> {
    let path = toolchain_root.join(LICENSE_FILE);
    let body = std::fs::read_to_string(&path).map_err(|source| match source.kind() {
        std::io::ErrorKind::InvalidData => NoticesError::NotUtf8 { path: path.clone() },
        _ => NoticesError::Io {
            path: path.clone(),
            source,
        },
    })?;
    Ok(Taken {
        license,
        texts: vec![LicenseText {
            title: LICENSE_FILE.to_owned(),
            body,
            kind: TextKind::Own,
            source: None,
        }],
        note: None,
    })
}

/// The Go components behind a `go list -deps -json` listing: each module that holds a linked
/// package, and each linked package that carries a licence of its own below its module's root. A replaced module
/// is read from the directory it was replaced by. One replaced by another module's version is that module, named for it
/// and labelled as replacing the original; one replaced by a directory is a modified copy, at the address of that
/// directory under `source_url` (which names `repo_root` in the repository). One component per module the build links,
/// named as the build names it: a module that another is replaced by, and the replacement required on its own, are two.
/// Sorted by name.
pub fn collect(listing: &str, repo_root: &Path, source_url: &str) -> Result<Vec<Component>, NoticesError> {
    let tool_error = |reason: String| NoticesError::Tool {
        command: "go list -deps -json".to_owned(),
        reason,
    };

    // Keyed by the module as the build names it (its original path and version), not as it is printed.
    let mut components: BTreeMap<(String, String), Component> = BTreeMap::new();
    // Module path -> (its root, the module, the directories of its linked packages).
    let mut modules: BTreeMap<String, (PathBuf, GoModule, Vec<PathBuf>)> = BTreeMap::new();

    for package in serde_json::Deserializer::from_str(listing).into_iter::<GoPackage>() {
        let package = package.map_err(|e| tool_error(format!("its output does not parse: {e}")))?;
        // The standard library is no module: the `declared:` entry for it covers every package of it.
        if package.standard {
            continue;
        }
        let Some(module) = package.module.filter(|module| !module.main) else {
            continue;
        };
        let root = module
            .replace
            .as_ref()
            .and_then(|replacement| replacement.dir.clone())
            .or_else(|| module.dir.clone())
            .ok_or_else(|| NoticesError::Provision {
                what: format!(
                    "the source of Go module {} (package {})",
                    module.path, package.import_path
                ),
                command: "cargo xtask ex-ray".to_owned(),
            })?;
        let linked = package.dir.unwrap_or_else(|| root.clone());
        let entry = modules
            .entry(module.path.clone())
            .or_insert_with(|| (root, module, Vec::new()));
        entry.2.push(linked);
    }

    let mut finder = LicenceDirs::default();
    for (path, (root, module, dirs)) in modules {
        let original_version = module.version.clone().unwrap_or_default();
        // A module replaced by another module's version is that module: its code, version and address are linked.
        let (linked_path, version, replaces, is_copy) = match module.replace.as_ref() {
            Some(GoReplacement {
                path: replacement,
                version: Some(version),
                ..
            }) => (
                replacement.clone(),
                version.clone(),
                Some(format!("{path} {original_version}")),
                false,
            ),
            Some(GoReplacement { version: None, .. }) => (path.clone(), original_version.clone(), None, true),
            None => (path.clone(), original_version.clone(), None, false),
        };
        let component = |name: String, origin: Origin, dir: PathBuf| -> Result<Component, NoticesError> {
            let url = if is_copy {
                address_in_repository(&path, &dir, repo_root, source_url)?
            } else {
                format!("https://pkg.go.dev/{linked_path}@{version}")
            };
            Ok(Component {
                url: Some(url),
                name,
                version: version.clone(),
                origin,
                license: None,
                source_dir: Some(dir),
                modified_copy: is_copy,
                replaces: replaces.clone(),
                text_dir: None,
            })
        };
        components.insert(
            (path.clone(), original_version.clone()),
            component(linked_path.clone(), Origin::GoModule, root.clone())?,
        );
        for dir in dirs {
            if let Some(nested) = nearest_licence_below(&root, &dir, &mut finder)? {
                let relative = nested
                    .strip_prefix(&root)
                    .expect("a nested directory is under the root");
                let below = relative
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                components.insert(
                    (format!("{path}/{below}"), original_version.clone()),
                    component(format!("{linked_path}/{below}"), Origin::GoPackage, nested)?,
                );
            }
        }
    }
    let mut components: Vec<Component> = components.into_values().collect();
    components.sort_by(|a, b| (&a.name, &a.version, &a.replaces).cmp(&(&b.name, &b.version, &b.replaces)));
    Ok(components)
}

/// The address of `dir`, a directory of the repository at `repo_root`, under `source_url`. `module` is the Go module
/// the directory replaces.
fn address_in_repository(module: &str, dir: &Path, repo_root: &Path, source_url: &str) -> Result<String, NoticesError> {
    let relative = dir.strip_prefix(repo_root).map_err(|_| NoticesError::Tool {
        command: "go list -deps -json".to_owned(),
        reason: format!(
            "module {module} is replaced by {}, which is not in the repository at {}",
            dir.display(),
            repo_root.display()
        ),
    })?;
    let parts = relative.components().map(|part| part.as_os_str().to_string_lossy());
    Ok(std::iter::once(source_url.to_owned())
        .chain(parts.map(|part| part.into_owned()))
        .collect::<Vec<_>>()
        .join("/"))
}

/// The nearest directory from `package_dir` up to, but not including, `root` that holds a licence file.
pub(super) fn nearest_licence_below(
    root: &Path,
    package_dir: &Path,
    finder: &mut LicenceDirs,
) -> Result<Option<PathBuf>, NoticesError> {
    if !package_dir.starts_with(root) {
        return Err(NoticesError::Tool {
            command: "go list -deps -json".to_owned(),
            reason: format!(
                "the package directory {} is not under the root {} of its module",
                package_dir.display(),
                root.display()
            ),
        });
    }
    for dir in package_dir.ancestors().take_while(|dir| *dir != root) {
        if finder.has_licence_file(dir)? {
            return Ok(Some(dir.to_owned()));
        }
    }
    Ok(None)
}
