//! Workspace-wide guard for `.config/nextest.toml`'s `global-net-state`
//! group. Lives in the lib test binary (not the privileged one) so it runs in
//! the ordinary unprivileged pass on every push — which is where a forgotten
//! filter term must be caught, not in the elevated lane that would already be
//! racing.

/// Guard for the COUPLED NAME above, expressed generically so it also catches a
/// human adding the next global-net-state test rather than only this one.
///
/// `.config/nextest.toml`'s `global-net-state` group matches tests by NAME
/// SUBSTRING. A test that mutates global OS network state but whose name no
/// pattern matches silently leaves the group and races the other binaries' tests
/// — a cross-binary data race that shows up as an unrelated flake. This scans
/// the workspace for test functions whose names say they belong to the group and
/// fails if the filter would not pick one up.
///
/// Deliberately unlabelled: it needs no elevation, so it runs in the ordinary
/// `SKULD_LABELS="!tun"` pass on every push — which is where a forgotten filter
/// term needs to be caught, not in the elevated lane that would already be
/// racing.
///
/// The matcher understands the two pattern shapes the filter actually uses:
/// a bare substring, and a `$`-anchored suffix.
///
/// Its own name deliberately avoids the `global_net_state` marker it scans for —
/// otherwise it reports itself, which is a false positive AND masks a real one.
#[skuld::test]
fn nextest_group_filter_covers_every_serialized_net_test() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root is two levels above the crate manifest")
        .to_path_buf();

    let config = std::fs::read_to_string(root.join(".config/nextest.toml")).expect("nextest config must exist");
    let filter_line = config
        .lines()
        .find(|l| l.trim_start().starts_with("filter ="))
        .expect("the global-net-state override must have a filter");

    // Pull the inner regex out of each `test(/.../)` term.
    let patterns: Vec<&str> = filter_line
        .match_indices("test(/")
        .filter_map(|(i, _)| {
            let rest = &filter_line[i + "test(/".len()..];
            rest.find("/)").map(|end| &rest[..end])
        })
        .collect();
    assert!(
        !patterns.is_empty(),
        "could not parse any pattern out of: {filter_line}"
    );

    let matches_filter = |name: &str| {
        patterns.iter().any(|p| match p.strip_suffix('$') {
            Some(suffix) => name.ends_with(suffix),
            None => name.contains(p),
        })
    };

    let mut checked = 0usize;
    for path in rust_sources(&root.join("crates")) {
        let src = std::fs::read_to_string(&path).unwrap_or_default();
        for line in src.lines() {
            let Some(rest) = line.trim_start().strip_prefix("fn ") else {
                continue;
            };
            let name = rest.split(['(', '<']).next().unwrap_or("").trim();
            if !name.contains("global_net_state") {
                continue;
            }
            checked += 1;
            assert!(
                matches_filter(name),
                "test `{name}` ({}) names itself part of the global-net-state group, but no \
                 pattern in .config/nextest.toml's filter matches it — it would run \
                 unserialized against the other binaries' global-network-state tests. \
                 Add a matching `test(/.../)` term.",
                path.display()
            );
        }
    }
    assert!(
        checked > 0,
        "found no global-net-state tests to check — the scan is broken, not the config"
    );
}

fn rust_sources(dir: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == "target" || n == ".tmp") {
                continue;
            }
            out.extend(rust_sources(&path));
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
    out
}
