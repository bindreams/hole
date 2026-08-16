//! `cargo xtask check-vendoring-integrity` — a `prek` local hook (`always_run`,
//! `pass_filenames = false`, so it runs on every commit in the whole repo, not
//! just vendor-related ones) enforcing consistency of every git-subrepo-vendored
//! dependency under `crates/ex-ray/third_party/`:
//!
//! 1. No unresolved merge-conflict markers in any tracked file under the dep.
//! 2. `VENDORING.md`'s noted version matches `.gitrepo`'s pinned `branch`.
//! 3. The outer `crates/ex-ray/go.mod`'s require line (if any) agrees too.
//! 4. No unresolved-conflict sentinel (`.vendor-conflict`) left behind by
//!    `pull_subrepo::conflict::force_commit_conflicted`'s CI-only policy.
//!
//! Every dep under `crates/ex-ray/third_party/` that has a `.gitrepo` file is
//! discovered dynamically (never hardcoded) — matching
//! `finish_vendor_bump.rs`'s own directory-detection precedent, so a third
//! vendored dep never needs this file edited.

use std::path::Path;

use anyhow::{Context, Result};

use crate::finish_vendor_bump::{find_vendoring_heading_version_range, read_module_path};
use crate::git_util::run_git_raw;
use crate::pull_subrepo::gitrepo_field;

/// Runs every check for every discovered vendored dep and returns every
/// violation found as a human-readable message — empty means clean. A
/// `Vec`, not "the first thing that's wrong": a human resolving a conflict
/// by hand benefits from seeing every problem at once.
pub fn run(repo_root: &Path) -> Result<Vec<String>> {
    let mut violations = Vec::new();
    for dep_name in discover_vendored_deps(repo_root)? {
        let dep_dir_rel = format!("crates/ex-ray/third_party/{dep_name}");
        violations.extend(check_conflict_markers(repo_root, &dep_dir_rel)?);
        violations.extend(check_vendoring_md_version(repo_root, &dep_name, &dep_dir_rel)?);
        violations.extend(check_go_mod_require_version(repo_root, &dep_dir_rel)?);
        violations.extend(check_vendor_conflict_sentinel(repo_root, &dep_name, &dep_dir_rel)?);
    }
    Ok(violations)
}

/// Every immediate subdirectory of `crates/ex-ray/third_party/` that
/// contains a `.gitrepo` file, sorted by name for deterministic output. A
/// missing `crates/ex-ray/third_party/` directory (a hypothetical repo with
/// no vendored deps at all) is not an error — this hook is `always_run`, so
/// it must execute cleanly on every commit in every repo state.
fn discover_vendored_deps(repo_root: &Path) -> Result<Vec<String>> {
    let third_party = repo_root.join("crates/ex-ray/third_party");
    let entries = match std::fs::read_dir(&third_party) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("failed to read {}", third_party.display())),
    };

    let mut deps = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read an entry in {}", third_party.display()))?;
        let path = entry.path();
        if !path.is_dir() || !path.join(".gitrepo").exists() {
            continue;
        }
        let dep_name = path
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow::anyhow!("{} has a non-UTF-8 directory name", path.display()))?
            .to_string();
        deps.push(dep_name);
    }
    deps.sort();
    Ok(deps)
}

/// Check 1: scans every `git ls-files`-tracked file under `dep_dir_rel` for
/// genuine merge-conflict marker triples. Untracked files are out of scope
/// (matches `git ls-files`'s own discovery, not a filesystem walk).
fn check_conflict_markers(repo_root: &Path, dep_dir_rel: &str) -> Result<Vec<String>> {
    // `-z`: NUL-delimited, unquoted paths — same non-ASCII-path-safety
    // rationale as `pull_subrepo::conflict::unmerged_paths`.
    let listing = run_git_raw(repo_root, &["ls-files", "-z", "--", dep_dir_rel])?;
    let mut violations = Vec::new();
    for rel_path in listing.split('\0').filter(|s| !s.is_empty()) {
        let abs_path = repo_root.join(rel_path);
        // Read as bytes, not `read_to_string`: the real vendored trees carry
        // tracked binary files (utls/logo.png, testdata/Client-TLSv1*) that
        // hard-error a UTF-8 read. A binary file cannot carry a text
        // merge-conflict marker, so a byte-level scan finding nothing is
        // simply nothing to report — never a reason to fail the check.
        let bytes = match std::fs::read(&abs_path) {
            Ok(bytes) => bytes,
            // `git ls-files` reports the index, not the worktree — a file deleted with a
            // plain `rm` (not `git rm`) is still tracked but absent on disk. This hook is
            // `always_run`, so that local worktree inconsistency must not become an opaque
            // crash for every commit in the repo; there's nothing to scan, so report nothing.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("failed to read {}", abs_path.display())),
        };
        for line in find_conflict_marker_triples(&bytes) {
            violations.push(format!("{rel_path}:{line}: unresolved merge-conflict markers"));
        }
    }
    Ok(violations)
}

/// Scans `bytes` for genuine conflict-marker triples: a `<<<<<<< ` line
/// (prefix match — real markers carry a trailing ref name), then, scanning
/// forward, an `=======` line (exact whole-line match — a `>=7`-equals-sign
/// divider, e.g. a Markdown setext underline, is a plausible legitimate
/// line that must not match as a prefix or via a longer run), then,
/// scanning further forward, a `>>>>>>> ` line (prefix match again). All
/// three must be found, in order, to report one triple; scanning resumes
/// just past a found triple's `>>>>>>> ` line, so multiple triples in one
/// file are each reported with their own line number. Returns 1-based line
/// numbers of each triple's `<<<<<<< ` line.
fn find_conflict_marker_triples(bytes: &[u8]) -> Vec<usize> {
    let mut lines: Vec<&[u8]> = bytes.split(|&b| b == b'\n').collect();
    // A trailing newline produces one empty trailing "line" after the
    // split — drop it so line numbers match ordinary editor numbering
    // instead of over-counting by one for every newline-terminated file.
    if lines.last() == Some(&&b""[..]) {
        lines.pop();
    }

    let mut violations = Vec::new();
    let mut i = 0;
    while i < lines.len() {
        if lines[i].starts_with(b"<<<<<<< ") {
            if let Some(equals_idx) = (i + 1..lines.len()).find(|&j| is_exact_equals_line(lines[j])) {
                if let Some(end_idx) = (equals_idx + 1..lines.len()).find(|&k| lines[k].starts_with(b">>>>>>> ")) {
                    violations.push(i + 1);
                    i = end_idx + 1;
                    continue;
                }
            }
        }
        i += 1;
    }
    violations
}

fn is_exact_equals_line(line: &[u8]) -> bool {
    let trimmed = line.strip_suffix(b"\r").unwrap_or(line);
    trimmed == b"======="
}

/// Check 2: `VENDORING.md`'s noted version for `dep_name` must match
/// `.gitrepo`'s `branch`. A missing heading is itself a violation, not a
/// skip — a brand-new vendored dep with a `.gitrepo` but no documentation
/// yet must not silently pass (that would let auto-merge fire before
/// `vendor-bump.yaml` ever pulls anything).
fn check_vendoring_md_version(repo_root: &Path, dep_name: &str, dep_dir_rel: &str) -> Result<Vec<String>> {
    let gitrepo_path = repo_root.join(dep_dir_rel).join(".gitrepo");
    let gitrepo_contents =
        std::fs::read_to_string(&gitrepo_path).with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    let Some(branch) = gitrepo_field(&gitrepo_contents, "branch") else {
        return Ok(vec![format!("{dep_dir_rel}/.gitrepo has no `branch = ` line")]);
    };

    let vendoring_md_path = repo_root.join("crates/ex-ray/third_party/VENDORING.md");
    let vendoring_md_contents = std::fs::read_to_string(&vendoring_md_path)
        .with_context(|| format!("failed to read {}", vendoring_md_path.display()))?;

    let version_range = match find_vendoring_heading_version_range(&vendoring_md_contents, dep_name) {
        Ok(range) => range,
        // A malformed heading is itself a real, reportable problem — never
        // a reason to hard-fail this `always_run` hook for the whole repo.
        Err(e) => {
            return Ok(vec![format!(
                "VENDORING.md's heading for `{dep_name}` is malformed: {e:#}"
            )])
        }
    };
    let Some((start, end)) = version_range else {
        return Ok(vec![format!(
            "VENDORING.md has no `## `{dep_name}/` — pinned **...**` heading for `{dep_name}` — every \
             vendored dep must be documented there"
        )]);
    };
    let noted_version = &vendoring_md_contents[start..end];

    if noted_version == branch {
        return Ok(Vec::new());
    }
    Ok(vec![format!(
        "VENDORING.md notes `{dep_name}` as pinned **{noted_version}**, but `{dep_dir_rel}/.gitrepo` has \
         `branch = {branch}` — these must match"
    )])
}

/// Check 3: the outer `crates/ex-ray/go.mod`'s `require` line for this
/// dep's own Go module path (if one exists at all — a dep only reachable
/// transitively through another vendored dep has none, and that's not a
/// violation) must agree with `.gitrepo`'s `branch`. Parses `go.mod` by
/// hand rather than shelling out to `go mod edit -json`: this hook is
/// `always_run` on every commit in the repo, and this repo's other
/// Go-toolchain-touching hooks are all gated to `types = ["go"]` so a
/// contributor without Go installed can still commit — this would be the
/// first exception, with no graceful degradation available for a required
/// check.
fn check_go_mod_require_version(repo_root: &Path, dep_dir_rel: &str) -> Result<Vec<String>> {
    let gitrepo_path = repo_root.join(dep_dir_rel).join(".gitrepo");
    let gitrepo_contents =
        std::fs::read_to_string(&gitrepo_path).with_context(|| format!("failed to read {}", gitrepo_path.display()))?;
    // A missing `branch` field is already reported by check 2 — nothing
    // further to compare here.
    let Some(branch) = gitrepo_field(&gitrepo_contents, "branch") else {
        return Ok(Vec::new());
    };

    let dep_go_mod_path = repo_root.join(dep_dir_rel).join("go.mod");
    // A dep with no `go.mod` at all has no Go module — nothing to compare,
    // same as the `find_go_mod_require_version` "not applicable" case
    // below, not a violation. Checked explicitly (not via `read_module_path`'s
    // own error) so a *malformed* go.mod (present, but no `module` line —
    // genuinely worth a human's attention, unlike a dep that's simply not a
    // Go module) still degrades to a reported violation instead of a hard
    // crash, matching check 2's "malformed heading is real reportable
    // problem" precedent rather than silently swallowing it too.
    if !dep_go_mod_path.exists() {
        return Ok(Vec::new());
    }
    let module_path = match read_module_path(&dep_go_mod_path) {
        Ok(path) => path,
        Err(e) => return Ok(vec![format!("{}: {e:#}", dep_go_mod_path.display())]),
    };
    let ex_ray_go_mod_path = repo_root.join("crates/ex-ray/go.mod");
    let ex_ray_go_mod = std::fs::read_to_string(&ex_ray_go_mod_path)
        .with_context(|| format!("failed to read {}", ex_ray_go_mod_path.display()))?;

    let Some(required_version) = find_go_mod_require_version(&ex_ray_go_mod, &module_path) else {
        return Ok(Vec::new());
    };
    if required_version == branch {
        return Ok(Vec::new());
    }
    Ok(vec![format!(
        "crates/ex-ray/go.mod requires `{module_path}` at `{required_version}`, but \
         `{dep_dir_rel}/.gitrepo` has `branch = {branch}` — these must match"
    )])
}

/// Hand-written `go.mod` `require` parser: finds the version for
/// `module_path`, in either single-line (`require <path> <version>`) or
/// block (`require (\n\t<path> <version>\n)`) form, optionally followed by
/// a trailing `// indirect` comment. `None` if `module_path` has no require
/// line at all (not every vendored dep is directly or indirectly imported
/// by `ex-ray` itself).
fn find_go_mod_require_version(contents: &str, module_path: &str) -> Option<String> {
    let mut in_require_block = false;
    for raw_line in contents.lines() {
        let line = raw_line.trim();
        if in_require_block {
            if line == ")" {
                in_require_block = false;
                continue;
            }
            if let Some(version) = parse_require_entry(line, module_path) {
                return Some(version);
            }
            continue;
        }
        if line == "require (" {
            in_require_block = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("require ") {
            if let Some(version) = parse_require_entry(rest, module_path) {
                return Some(version);
            }
        }
    }
    None
}

/// Parses one `<path> <version>` entry (a single-line `require`'s
/// remainder, or one line of a `require (...)` block), stripping an
/// optional trailing `// ...` comment (e.g. `// indirect`) first. Returns
/// the version only if `path` matches `module_path` exactly.
fn parse_require_entry(entry: &str, module_path: &str) -> Option<String> {
    let entry = entry.split("//").next().unwrap_or(entry).trim();
    let mut parts = entry.split_whitespace();
    let path = parts.next()?;
    let version = parts.next()?;
    (path == module_path).then(|| version.to_string())
}

/// Check 4: a *tracked* `.vendor-conflict` sentinel under `dep_dir_rel` is
/// itself a violation, regardless of its content or what check 1 finds in
/// the same tree — `force_commit_conflicted` writes one for every unmerged
/// path of a CI-only forced conflict commit, and only `finish-vendor-bump`
/// (or a human, once satisfied every listed path is genuinely resolved) may
/// clear it.
fn check_vendor_conflict_sentinel(repo_root: &Path, dep_name: &str, dep_dir_rel: &str) -> Result<Vec<String>> {
    let sentinel_rel = format!("{dep_dir_rel}/.vendor-conflict");
    let tracked = !run_git_raw(repo_root, &["ls-files", "-z", "--", &sentinel_rel])?.is_empty();
    if !tracked {
        return Ok(Vec::new());
    }
    Ok(vec![format!(
        "{sentinel_rel} is present — {dep_name} has an unresolved hand-merge conflict sentinel from a \
         force-committed vendor pull: resolve every path it lists, then run `cargo xtask \
         finish-vendor-bump` (it clears the sentinel once it confirms every listed path was actually \
         touched), or remove the file by hand only once every listed path is confirmed genuinely \
         resolved"
    )])
}
