//! The crates linked into a `hole` artifact, from the Cargo resolve graph.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use cargo_metadata::{DependencyKind, Metadata, MetadataCommand, Package, PackageId};

use super::{Component, NoticesError, Origin};

/// The packages whose binaries a `hole` artifact carries: the app, and the plugin it embeds or ships beside it.
pub const ROOTS: &[&str] = &["hole", "galoshes"];

/// `cargo metadata` for `triple`: resolve edges that apply to that target only. `--locked`, so an out-of-date
/// `Cargo.lock` fails at once and is not rewritten. Cargo downloads the sources of the packages it reports into the
/// registry when they are not there, so no separate fetch is needed first.
pub fn read_metadata(repo_root: &Path, triple: &str) -> Result<Metadata, NoticesError> {
    MetadataCommand::new()
        .manifest_path(repo_root.join("Cargo.toml"))
        .other_options(vec![
            "--filter-platform".to_owned(),
            triple.to_owned(),
            "--locked".to_owned(),
        ])
        .exec()
        .map_err(|e| NoticesError::Tool {
            command: format!("cargo metadata --locked --filter-platform {triple}"),
            reason: e.to_string(),
        })
}

/// The third-party crates the `roots` link: reached from them by normal dependency edges, through workspace members,
/// and not through a proc-macro crate (it runs in the compiler and is not in the binary). Workspace members are not
/// components. Sorted by name and version.
///
/// The result is a superset of what the binaries link, on purpose. `cargo metadata` has one node per package with the
/// features of its build script and of its target merged, so a crate that only a build script or another workspace
/// member enables is reachable by a normal edge, and crates that no binary links are listed. Over-noticing is safe; an
/// exact per-package walk (`cargo tree -p`) could leave out a crate that the installers' `--workspace` build links,
/// because they unify features across members.
pub fn collect(metadata: &Metadata, roots: &[&str]) -> Result<Vec<Component>, NoticesError> {
    let resolve = metadata.resolve.as_ref().ok_or_else(|| NoticesError::Tool {
        command: "cargo metadata".to_owned(),
        reason: "returned no resolve graph".to_owned(),
    })?;
    let packages: HashMap<&PackageId, &Package> = metadata.packages.iter().map(|p| (&p.id, p)).collect();
    let nodes: HashMap<&PackageId, _> = resolve.nodes.iter().map(|n| (&n.id, n)).collect();

    let mut pending: Vec<&PackageId> = Vec::new();
    for root in roots {
        let found = metadata
            .workspace_packages()
            .into_iter()
            .find(|p| p.name.as_str() == *root)
            .ok_or_else(|| NoticesError::Tool {
                command: "cargo metadata".to_owned(),
                reason: format!("the workspace has no package `{root}`"),
            })?;
        pending.push(&found.id);
    }

    // `cargo metadata` lists every package it reaches: an id with no node or no record breaks that, and a crate that
    // vanished here would vanish from the notices.
    let broken = |reason: String| NoticesError::Tool {
        command: "cargo metadata".to_owned(),
        reason,
    };

    let mut linked: HashSet<&PackageId> = HashSet::new();
    while let Some(id) = pending.pop() {
        if !linked.insert(id) {
            continue;
        }
        let node = nodes
            .get(id)
            .ok_or_else(|| broken(format!("the resolve graph reaches {id}, which has no node")))?;
        for dep in &node.deps {
            let package = packages
                .get(&dep.pkg)
                .ok_or_else(|| broken(format!("{id} depends on {}, which has no package record", dep.pkg)))?;
            let is_normal = dep.dep_kinds.iter().any(|kind| kind.kind == DependencyKind::Normal);
            let is_proc_macro = package.targets.iter().any(|t| t.is_proc_macro());
            if is_normal && !is_proc_macro {
                pending.push(&dep.pkg);
            }
        }
    }

    let mut components = BTreeMap::new();
    for id in linked {
        let package = packages
            .get(id)
            .ok_or_else(|| broken(format!("the resolve graph reaches {id}, which has no package record")))?;
        if metadata.workspace_members.contains(id) {
            continue;
        }
        components.insert(
            (package.name.to_string(), package.version.to_string()),
            component_of(package),
        );
    }
    Ok(components.into_values().collect())
}

fn component_of(package: &Package) -> Component {
    let name = package.name.to_string();
    let version = package.version.to_string();
    let url = match &package.source {
        Some(source) if source.is_crates_io() => Some(format!("https://crates.io/crates/{name}/{version}")),
        _ => package.repository.clone(),
    };
    Component {
        name,
        version,
        origin: Origin::Crate,
        license: package.license.clone(),
        source_dir: package.manifest_path.parent().map(|dir| dir.as_std_path().to_owned()),
        url,
        modified_copy: false,
        replaces: None,
        text_dir: None,
    }
}
