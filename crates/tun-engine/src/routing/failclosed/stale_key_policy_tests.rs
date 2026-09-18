//! Tripwire: per-variant [`StaleKeyPolicy`] policy lives on the type.
//!
//! CLAUDE.md's rule — *a decision keyed to an enum variant belongs in ONE
//! exhaustive match on that type* — is already test-enforced for `SessionEvent`
//! and `CoverPresence` (`crates/bridge/src/reconciler_tests.rs`), after that
//! shape produced four separate bugs in one change. `StaleKeyPolicy` is the
//! third enum with the same exposure and the same consequence: a site that
//! writes `== StaleKeyPolicy::Fail` silently groups any future variant with
//! `Degrade`, which is the fail-OPEN arm — it keeps a stale filter rather than
//! aborting the engage. Both of `add_filter`'s were exactly that shape.
//!
//! An exhaustive `match` on the type is not the hazard and is not what this
//! forbids: a third variant is a compile error there, which is the whole point.
//! What it forbids is DECIDING from one variant by comparison — `==`, `!=`,
//! `matches!`, a lone match arm, an `if let`/`while let`/let-else — outside the
//! type's own `impl`.
//!
//! `#[cfg]`-free on purpose, for the reason `clearance_tests` and
//! `boot_time_tripwire_tests` both give: `StaleKeyPolicy` is Windows-only, this
//! is a source scan that needs no FWPM, and a guard that runs only where the
//! hazard lives runs nowhere else.
//!
//! ## Disclosed residuals
//!
//! It is a LINE scan, so it sees a decision only where the variant path and
//! the deciding token are both reachable from one line. Two forms are handled
//! explicitly because an ordinary edit produces them — a decision rustfmt
//! wrapped ([`is_bare_variant`]) and a variant import (`use
//! StaleKeyPolicy::Fail;`, flagged at the import since the spend is then
//! unqualified and invisible). One is NOT: binding the variant to a local
//! first (`let fail = StaleKeyPolicy::Fail; … if policy == fail`) puts the
//! decision on a line naming neither the type nor the variant, and separating
//! that from a legitimate construction is dataflow, not lexing. What stands
//! behind it is the same thing that stands behind the other two enums' guards
//! — review, and the fact that the indirection has to be written on purpose.
//!
//! It is also STRUCTURAL: it proves where the rule lives, never what the rule
//! says. That `Fail` aborts and `Degrade` warns is behaviour, and is tested as
//! behaviour in `windows_tests`
//! (`a_refused_pre_delete_fails_a_lockdown_engage_and_degrades_a_transient_one`)
//! — on the Windows lane only, because it needs the type.

use std::ops::Range;
use std::path::{Path, PathBuf};

/// Whether `line` DECIDES from a value rather than merely naming or
/// constructing one.
///
/// Copied from `reconciler_tests`' predicate rather than shared: that module
/// is in a crate this one does not depend on. `=>` and `==`/`!=` are the
/// obvious forms; the rest are the ones that silently slipped past an earlier
/// version of those guards — `matches!`, a match arm split so a bare `Variant`
/// sits alone on its own line (leading or trailing `|`), and the three binding
/// forms, which pattern-match without any of the above tokens.
fn line_decides(line: &str) -> bool {
    let t = line.trim();
    t.contains("=>")
        || t.contains("==")
        || t.contains("!=")
        || t.contains("matches!")
        || t.contains("if let")
        || t.contains("while let")
        || (t.starts_with("let ") && t.contains(" else"))
        || t.ends_with('|')
        || t.starts_with('|')
        || is_bare_variant(t)
}

/// Whether the line is nothing but a variant path, optionally comma-terminated.
///
/// This is what a multi-line `matches!(policy,\n    StaleKeyPolicy::Fail\n)` —
/// or a wrapped `==` operand — looks like once rustfmt has had it: the
/// deciding TOKEN is on a different line from the variant, so none of the
/// predicates above sees either half. Construction does not take this shape:
/// a struct field carries its name (`stale_key: StaleKeyPolicy::Fail,`) and an
/// argument carries its call.
fn is_bare_variant(trimmed: &str) -> bool {
    let t = trimmed.strip_suffix(',').unwrap_or(trimmed);
    t.strip_prefix("StaleKeyPolicy::")
        .is_some_and(|rest| !rest.is_empty() && rest.chars().all(|c| c.is_alphanumeric() || c == '_'))
}

/// The byte range of the item starting at `head`, bounded by its own column-0
/// closing brace — so an exemption cannot drift onto a neighbouring item.
///
/// `None` when the file does not hold the item at all, which is the ordinary
/// answer for every source that is not the one defining the type.
fn item_span(src: &str, head: &str) -> Option<Range<usize>> {
    let start = src.find(head)?;
    let after = &src[start..];
    let len = after.find("\n}\n").map(|i| i + 2).unwrap_or(after.len());
    Some(start..start + len)
}

/// Lines of `src` that decide from a `StaleKeyPolicy` variant, outside the
/// type's own `impl` block.
///
/// Comment lines are skipped so this module's and `windows.rs`'s prose — both
/// of which name the variants at length — are not read as decisions. Crude on
/// purpose, the way `reconciler_tests`' is: a block-comment interior is a
/// possible false ALARM, which is safe, where a silently skipped decision site
/// is not.
///
/// Offsets are tracked from `split_inclusive`, never from `lines()`, so a CRLF
/// checkout cannot shift the exempt span out from under the scan.
fn decision_sites(src: &str) -> Vec<String> {
    let exempt = item_span(src, "impl StaleKeyPolicy {");
    let mut out = Vec::new();
    let mut offset = 0usize;
    for (idx, line) in src.split_inclusive('\n').enumerate() {
        let start = offset;
        offset += line.len();
        let t = line.trim_start();
        // NOT `starts_with('*')`: that also drops real code beginning with a
        // dereference, exactly a line this guard exists to catch.
        if t.starts_with("//") || t.starts_with("/*") {
            continue;
        }
        if !line.contains("StaleKeyPolicy::") {
            continue;
        }
        // A variant IMPORT is flagged wherever it sits, decision token or not:
        // `use StaleKeyPolicy::Fail;` lets every later comparison be written
        // unqualified (`policy == Fail`), which no line-level scan can see.
        // Same evasion `boot_time_tripwire_tests` closes for its own subject by
        // reading the `use` rather than the spend.
        if !t.starts_with("use ") && !line_decides(line) {
            continue;
        }
        if exempt.as_ref().is_some_and(|r| r.contains(&start)) {
            continue;
        }
        out.push(format!("{}: {}", idx + 1, line.trim()));
    }
    out
}

/// A Rust source that ships, as opposed to one that tests it — the same
/// exclusion `boot_time_tripwire_tests` makes, and load-bearing for the same
/// reason: this very file decides from the variants in its own fixtures.
fn is_production_source(path: &Path) -> bool {
    path.file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".rs") && !n.ends_with("_tests.rs"))
}

fn production_sources() -> Vec<PathBuf> {
    let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut found: Vec<PathBuf> = walkdir::WalkDir::new(&src)
        .follow_links(true)
        .into_iter()
        .map(|e| e.expect("walk the crate sources"))
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|p| is_production_source(p))
        .collect();
    found.sort();
    assert!(
        found.iter().any(|p| p.ends_with("routing/failclosed/windows.rs")),
        "the scan found no routing/failclosed/windows.rs under {}; a tripwire that reads nothing \
         passes forever",
        src.display()
    );
    found
}

#[skuld::test]
fn stale_key_policy_lives_on_the_type_not_at_call_sites() {
    let sources = production_sources();
    let mut offenders: Vec<String> = Vec::new();
    let mut asked = 0usize;
    let mut defined = 0usize;
    for path in &sources {
        let text = std::fs::read_to_string(path).expect("read a walked source file");
        defined += usize::from(item_span(&text, "impl StaleKeyPolicy {").is_some());
        asked += text.matches(".refuses_a_stale_key()").count();
        offenders.extend(
            decision_sites(&text)
                .into_iter()
                .map(|site| format!("{}:{site}", path.display())),
        );
    }

    // The scan's own preconditions, both of which a refactor could quietly
    // satisfy the guard by removing: the type must still have an `impl` to
    // exempt, and somebody outside it must still be ASKING. Without the second
    // a build that inlined every comparison back into a match would read as
    // clean.
    assert_eq!(defined, 1, "exactly one source may define `impl StaleKeyPolicy`");
    assert!(
        asked >= 2,
        "no production site asks `StaleKeyPolicy::refuses_a_stale_key`, so this guard has nothing \
         to be the alternative to"
    );

    assert!(
        offenders.is_empty(),
        "StaleKeyPolicy decided outside its own `impl`:\n  {}\n\
         Add a classifier method to `StaleKeyPolicy` (one exhaustive match, in one place) and ask \
         it here instead. `== StaleKeyPolicy::Fail` groups a future third variant with `Degrade` \
         — the arm that KEEPS a stale filter instead of aborting the engage.",
        offenders.join("\n  ")
    );
}

#[skuld::test]
fn the_guard_fires_on_a_call_site_and_stays_quiet_inside_the_type() {
    // Non-vacuity, asserted against the scan rather than by mutating a real
    // source. The first block is what `add_filter` looked like before this
    // landed; the second is the exhaustive match that must stay legal.
    let offending = "\
fn add_filter(policy: StaleKeyPolicy) {
    debug_assert!(boot_time || policy == StaleKeyPolicy::Fail);
    if fresh && policy != StaleKeyPolicy::Degrade {
        strict()
    }
    let x = matches!(policy, StaleKeyPolicy::Fail);
    if let StaleKeyPolicy::Fail = policy {}
}
";
    assert_eq!(decision_sites(offending).len(), 4, "{:?}", decision_sites(offending));

    let sanctioned = "\
impl StaleKeyPolicy {
    fn refuses_a_stale_key(self) -> bool {
        match self {
            StaleKeyPolicy::Fail => true,
            StaleKeyPolicy::Degrade => false,
        }
    }
}
";
    assert!(decision_sites(sanctioned).is_empty());

    // Construction, naming and prose must not trip it, or every call site
    // becomes an offender and the guard gets whitelisted into uselessness.
    let benign = "\
/// Under `StaleKeyPolicy::Degrade` a duplicate add => Ok.
// See StaleKeyPolicy::Fail == the abort arm.
fn f() {
    let p = StaleKeyPolicy::Fail;
    submit(StaleKeyPolicy::Degrade);
    CoverSpec {
        stale_key: StaleKeyPolicy::Fail,
    }
}
";
    assert!(decision_sites(benign).is_empty(), "{:?}", decision_sites(benign));
}

#[skuld::test]
fn the_guard_sees_a_decision_split_across_lines_and_a_variant_import() {
    // The two evasions a line-level scan is naturally blind to, and both are
    // reachable by an ordinary edit rather than by malice: rustfmt WRAPS a
    // long `matches!` or `==`, putting the variant on its own line away from
    // the deciding token, and `use StaleKeyPolicy::Fail;` lets every later
    // comparison be written unqualified.
    let wrapped = "\
fn verdict(policy: StaleKeyPolicy) -> bool {
    matches!(
        policy,
        StaleKeyPolicy::Fail
    )
}
";
    // The `matches!(` line itself names no variant, so it is the WRAPPED one
    // that has to fire — which is the whole point: without `is_bare_variant`
    // neither line carries both halves and the scan sees nothing at all.
    assert_eq!(decision_sites(wrapped), ["4: StaleKeyPolicy::Fail"]);

    let imported = "use super::StaleKeyPolicy::Fail;\nfn f(p: X) -> bool { p == Fail }\n";
    assert_eq!(
        decision_sites(imported),
        ["1: use super::StaleKeyPolicy::Fail;"],
        "the spend is invisible, so the import is what must fire"
    );
}

#[skuld::test]
fn an_exemption_cannot_drift_past_the_impl_it_is_anchored_to() {
    // `item_span` bounds on the type's OWN column-0 closing brace. Without
    // that, an exemption anchored at the `impl` would swallow every decision
    // site below it in the file — which on `windows.rs` is both of the ones
    // this change removed.
    let src = "\
impl StaleKeyPolicy {
    fn refuses_a_stale_key(self) -> bool {
        match self {
            StaleKeyPolicy::Fail => true,
            StaleKeyPolicy::Degrade => false,
        }
    }
}

fn later(policy: StaleKeyPolicy) -> bool {
    policy == StaleKeyPolicy::Fail
}
";
    assert_eq!(
        decision_sites(src),
        ["11: policy == StaleKeyPolicy::Fail"],
        "a site AFTER the impl must still be seen"
    );
}
