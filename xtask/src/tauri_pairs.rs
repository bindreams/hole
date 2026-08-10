//! Tauri ships each plugin as an npm/crate pair, and `npx tauri build` refuses
//! to build when the two sides disagree on major.minor. Both are floating
//! requirements resolved by different lockfiles, so a bump on one side alone is
//! invisible until a bundle build runs — see the DMG break in #679.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde_json::Value;

/// `@tauri-apps/plugin-X` ↔ `tauri-plugin-X` versions that disagree on
/// major.minor, as `("plugin-X", npm, crate)`. Empty means the pair is aligned.
pub fn plugin_version_drift(package_lock: &str, cargo_lock: &str) -> Result<Vec<(String, String, String)>> {
    let npm = npm_plugin_versions(package_lock)?;
    let cargo = cargo_plugin_versions(cargo_lock);

    let mut drift = Vec::new();
    for (plugin, npm_version) in npm {
        let Some(crate_version) = cargo.get(&plugin) else {
            continue;
        };
        if minor_series(&npm_version) != minor_series(crate_version) {
            drift.push((plugin, npm_version, crate_version.clone()));
        }
    }
    Ok(drift)
}

/// Leading `major.minor`, the granularity the Tauri CLI compares at.
fn minor_series(version: &str) -> (&str, &str) {
    let mut parts = version.split('.');
    (parts.next().unwrap_or_default(), parts.next().unwrap_or_default())
}

fn npm_plugin_versions(package_lock: &str) -> Result<BTreeMap<String, String>> {
    let lock: Value = serde_json::from_str(package_lock).context("parse package-lock.json")?;
    let packages = lock.get("packages").and_then(Value::as_object);
    let mut out = BTreeMap::new();
    for (path, entry) in packages.into_iter().flatten() {
        // Keys are install paths; the same package can appear nested.
        let Some(name) = path.rsplit("node_modules/").next() else {
            continue;
        };
        let Some(plugin) = name.strip_prefix("@tauri-apps/") else {
            continue;
        };
        if !plugin.starts_with("plugin-") {
            continue;
        }
        if let Some(version) = entry.get("version").and_then(Value::as_str) {
            out.insert(plugin.to_string(), version.to_string());
        }
    }
    Ok(out)
}

fn cargo_plugin_versions(cargo_lock: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut name = None;
    for line in cargo_lock.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("name = ") {
            name = rest.trim_matches('"').strip_prefix("tauri-").map(str::to_string);
        } else if let Some(rest) = line.strip_prefix("version = ") {
            if let Some(n) = name.take() {
                if n.starts_with("plugin-") {
                    out.insert(n, rest.trim_matches('"').to_string());
                }
            }
        }
    }
    out
}

#[cfg(test)]
#[path = "tauri_pairs_tests.rs"]
mod tauri_pairs_tests;
