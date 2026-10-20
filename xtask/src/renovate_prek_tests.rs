//! Every version `prek.toml` pins, the `rev` of each hook repository and each exact
//! `additional_dependencies` entry, is one a `regex` custom manager in `.github/renovate.json`
//! extracts, with a datasource this file knows. A pin no manager sees never moves, and a bumped `rev`
//! beside it changes nothing about the tool that runs. A prek manager may use only the keys, the
//! file pattern and the capture groups checked here; anything else fails. Top-level settings that
//! turn a manager off on purpose (`enabled`, `enabledManagers`, `ignorePaths`, `packageRules`) are
//! not checked.

use std::collections::BTreeSet;
use std::fs;

use regex::Regex;

/// `(depName, currentValue)` pairs the regex managers over `prek.toml` extract from its text.
fn extracted(renovate: &serde_json::Value, prek_text: &str) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for manager in renovate["customManagers"].as_array().expect("customManagers") {
        let files: Vec<&str> = manager["managerFilePatterns"]
            .as_array()
            .expect("managerFilePatterns")
            .iter()
            .map(|f| f.as_str().expect("managerFilePatterns entry"))
            .collect();
        if !files.iter().any(|f| f.to_ascii_lowercase().contains("prek")) {
            continue;
        }
        // Renovate's pattern lists (negations, globs, `/re/i`) are not modelled: a prek manager must
        // use the one form this file can check.
        assert_eq!(
            files,
            [PREK_FILE_PATTERN],
            "a manager over prek.toml must select it with exactly `{PREK_FILE_PATTERN}`; update this guard to change that"
        );
        assert_eq!(
            manager["customType"].as_str(),
            Some("regex"),
            "a manager over prek.toml must be a `regex` manager"
        );
        // Any other key (templates, `matchStringsStrategy`, `enabled`, ...) changes what Renovate
        // extracts in ways this file does not model.
        let keys = manager.as_object().expect("manager is an object").keys();
        let unmodelled: Vec<&String> = keys.filter(|k| !PREK_MANAGER_KEYS.contains(&k.as_str())).collect();
        assert!(
            unmodelled.is_empty(),
            "a manager over prek.toml may use only {PREK_MANAGER_KEYS:?}, not {unmodelled:?}; update this guard to change that"
        );
        let datasource_template = match &manager["datasourceTemplate"] {
            serde_json::Value::Null => None,
            template => Some(
                template
                    .as_str()
                    .expect("a prek manager's `datasourceTemplate` must be a string"),
            ),
        };
        for pattern in manager["matchStrings"].as_array().expect("matchStrings") {
            let pattern = pattern.as_str().expect("matchStrings entry");
            let re = Regex::new(pattern).unwrap_or_else(|e| panic!("`{pattern}` is not a valid regex: {e}"));
            // Renovate reads other named groups (`packageName`, `registryUrl`, `versioning`, ...) and
            // they override what is looked up.
            let unmodelled: Vec<&str> = re
                .capture_names()
                .flatten()
                .filter(|g| !PREK_CAPTURE_GROUPS.contains(g))
                .collect();
            assert!(
                unmodelled.is_empty(),
                "`{pattern}` may name only the groups {PREK_CAPTURE_GROUPS:?}, not {unmodelled:?}; update this guard to change that"
            );
            for caps in re.captures_iter(prek_text) {
                let group = |name| {
                    caps.name(name)
                        .unwrap_or_else(|| panic!("`{pattern}` matched without a `{name}` group"))
                        .as_str()
                        .to_string()
                };
                // As in Renovate, a template wins over the group.
                let datasource = datasource_template
                    .or(caps.name("datasource").map(|d| d.as_str()))
                    .unwrap_or_else(|| panic!("`{pattern}` names no datasource"));
                assert!(
                    PREK_DATASOURCES.contains(&datasource),
                    "datasource `{datasource}` is not one of {PREK_DATASOURCES:?}; add it here if it is real"
                );
                found.insert((group("depName"), group("currentValue")));
            }
        }
    }
    found
}

/// The keys a manager over prek.toml may carry: the ones this file checks.
const PREK_MANAGER_KEYS: &[&str] = &[
    "customType",
    "description",
    "managerFilePatterns",
    "matchStrings",
    "datasourceTemplate",
];

/// The capture groups a prek manager's `matchStrings` may name.
const PREK_CAPTURE_GROUPS: &[&str] = &["depName", "currentValue", "datasource"];

/// The Renovate datasources prek.toml pins come from.
const PREK_DATASOURCES: &[&str] = &["github-tags", "npm", "pypi"];

/// The `managerFilePatterns` entry that selects the root `prek.toml`.
const PREK_FILE_PATTERN: &str = r"/^prek\.toml$/";

/// `(package, version)` for each `additional_dependencies` entry pinned exactly (`pkg==1` or the
/// npm `pkg@1`); ranges (`>=`) and bare names are not pins.
fn pinned_additional_dependencies(prek: &toml::Table) -> BTreeSet<(String, String)> {
    let mut pins = BTreeSet::new();
    for repo in prek["repos"].as_array().expect("repos") {
        let Some(hooks) = repo.get("hooks").and_then(|h| h.as_array()) else {
            continue;
        };
        for hook in hooks {
            let Some(deps) = hook.get("additional_dependencies").and_then(|d| d.as_array()) else {
                continue;
            };
            for dep in deps.iter().filter_map(|d| d.as_str()) {
                // An npm scope's leading `@` is part of the name, so split at the last `@`.
                let split = dep
                    .split_once("==")
                    .or_else(|| dep.rsplit_once('@').filter(|(name, _)| !name.is_empty()));
                if let Some((name, version)) = split {
                    pins.insert((name.to_string(), version.to_string()));
                }
            }
        }
    }
    pins
}

/// `(owner/name, rev)` for each hook repository. `local`, `meta` and `builtin` have no `rev`; any
/// other remote must be on GitHub, the only host the Renovate manager reads.
fn pinned_repo_revs(prek: &toml::Table) -> Result<BTreeSet<(String, String)>, String> {
    let mut pins = BTreeSet::new();
    for repo in prek["repos"].as_array().expect("repos") {
        let url = repo
            .get("repo")
            .and_then(|r| r.as_str())
            .expect("a [[repos]] entry has a `repo`");
        if matches!(url, "local" | "meta" | "builtin") {
            continue;
        }
        let path = url
            .strip_prefix("https://github.com/")
            .ok_or_else(|| format!("`{url}` is not a github.com remote, which the Renovate manager cannot read"))?;
        let name = path.strip_suffix(".git").unwrap_or(path);
        let rev = repo
            .get("rev")
            .and_then(|r| r.as_str())
            .ok_or_else(|| format!("`{url}` has no `rev`"))?;
        pins.insert((name.to_string(), rev.to_string()));
    }
    Ok(pins)
}

#[skuld::test]
fn pinned_repo_revs_reads_every_remote_hook_repository() {
    let prek: toml::Table = r#"
        [[repos]]
        repo = "local"
        [[repos]]
        repo = "meta"
        [[repos]]
        repo = "https://github.com/a/b"
        rev = "v1"
        [[repos]]
        repo = "https://github.com/c/d.git"
        rev = "2"
    "#
    .parse()
    .unwrap();
    let expected = [("a/b", "v1"), ("c/d", "2")].map(|(n, r)| (n.to_string(), r.to_string()));
    assert_eq!(pinned_repo_revs(&prek).unwrap(), BTreeSet::from(expected));
}

#[skuld::test]
fn pinned_repo_revs_rejects_a_remote_the_manager_cannot_read() {
    for (repo, rev) in [
        ("https://gitlab.com/a/b", "v1"),
        ("git@github.com:a/b", "v1"),
        ("https://github.com/a/b", ""),
    ] {
        let rev_line = if rev.is_empty() {
            String::new()
        } else {
            format!("rev = \"{rev}\"")
        };
        let prek: toml::Table = format!(
            "[[repos]]
repo = \"{repo}\"
{rev_line}
"
        )
        .parse()
        .unwrap();
        assert!(
            pinned_repo_revs(&prek).is_err(),
            "`{repo}` rev `{rev}` must be rejected"
        );
    }
}

#[skuld::test]
fn every_pin_in_prek_toml_is_extracted_by_a_renovate_manager() {
    let root = crate::repo_root().expect("repo root");
    let renovate: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(".github/renovate.json")).expect("read renovate.json"))
            .expect("parse renovate.json");
    let prek_text = fs::read_to_string(root.join("prek.toml")).expect("read prek.toml");
    let prek: toml::Table = prek_text.parse().expect("parse prek.toml");

    let mut pins = pinned_additional_dependencies(&prek);
    assert!(
        pins.iter().any(|(name, _)| name == "@biomejs/biome"),
        "expected the biome pin among {pins:?}: this test must see an npm pin to mean anything"
    );
    let revs = pinned_repo_revs(&prek).unwrap_or_else(|e| panic!("prek.toml: {e}"));
    assert!(
        !revs.is_empty(),
        "prek.toml pins no hook repository rev: this test must see one to mean anything"
    );
    pins.extend(revs);
    let seen = extracted(&renovate, &prek_text);
    let unmanaged: Vec<_> = pins.difference(&seen).collect();
    assert!(
        unmanaged.is_empty(),
        "no Renovate manager extracts these prek.toml pins (add a pattern to renovate.json, and a `# renovate:` comment for an `additional_dependencies` pin): {unmanaged:?}"
    );
}
