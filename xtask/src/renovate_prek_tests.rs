//! Every version a `prek.toml` hook pins is one a Renovate manager in `.github/renovate.json`
//! extracts. A pin no manager sees never moves, and a bumped `rev` beside it changes nothing about
//! the tool that runs.

use std::collections::BTreeSet;
use std::fs;

use regex::Regex;

/// `(depName, currentValue)` pairs the regex managers over `prek.toml` extract from its text.
fn extracted(renovate: &serde_json::Value, prek_text: &str) -> BTreeSet<(String, String)> {
    let mut found = BTreeSet::new();
    for manager in renovate["customManagers"].as_array().expect("customManagers") {
        let files = manager["managerFilePatterns"].as_array().expect("managerFilePatterns");
        if !files.iter().any(|f| f.as_str().is_some_and(|f| f.contains("prek"))) {
            continue;
        }
        for pattern in manager["matchStrings"].as_array().expect("matchStrings") {
            let pattern = pattern.as_str().expect("matchStrings entry");
            let re = Regex::new(pattern).unwrap_or_else(|e| panic!("`{pattern}` is not a valid regex: {e}"));
            for caps in re.captures_iter(prek_text) {
                let (Some(dep), Some(version)) = (caps.name("depName"), caps.name("currentValue")) else {
                    continue;
                };
                found.insert((dep.as_str().to_string(), version.as_str().to_string()));
            }
        }
    }
    found
}

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

#[skuld::test]
fn every_exact_pin_in_prek_toml_is_extracted_by_a_renovate_manager() {
    let root = crate::repo_root().expect("repo root");
    let renovate: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(".github/renovate.json")).expect("read renovate.json"))
            .expect("parse renovate.json");
    let prek_text = fs::read_to_string(root.join("prek.toml")).expect("read prek.toml");
    let prek: toml::Table = prek_text.parse().expect("parse prek.toml");

    let pins = pinned_additional_dependencies(&prek);
    assert!(
        pins.iter().any(|(name, _)| name == "@biomejs/biome"),
        "expected the biome pin among {pins:?}: this test must see an npm pin to mean anything"
    );
    let seen = extracted(&renovate, &prek_text);
    let unmanaged: Vec<_> = pins.difference(&seen).collect();
    assert!(
        unmanaged.is_empty(),
        "no Renovate manager extracts these prek.toml pins (add a `# renovate:` comment and a pattern): {unmanaged:?}"
    );
}
