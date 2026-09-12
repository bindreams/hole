//! Tripwire: a `FWPM_FILTER_FLAG_BOOTTIME` filter may not be installed
//! without its key being classified `KeyLifetime::BootTime`.
//!
//! Scope is every production source in this crate, recursively — not just
//! `failclosed/`. `failclosed/windows.rs` is NOT the only sanctioned FWPM site
//! in tun-engine: `dns_confine/windows.rs` calls `FwpmFilterAdd0` too, and
//! `clippy.toml` names both. Nothing can reach a boot-time filter through that
//! second one today — `dns_confine::engage` opens its engine
//! `FWPM_SESSION_FLAG_DYNAMIC` and stamps `FWPM_FILTER_FLAGS(0)`, and WFP does
//! not accept a boot-time filter on a dynamic-session object — but that is a
//! property of today's code held up by clippy's site list, not by this file,
//! so the scan does not lean on it.
//!
//! The one exclusion is `failclosed.rs`, which DEFINES `KeyLifetime` and the
//! `proves_empty` fold and therefore names `BootTime` in code by construction.
//! It is excluded from the classification half only — an install there would
//! still fire — and the exclusion is anchored to where the fold actually
//! lives, so moving `proves_empty` fails the guard rather than silently
//! turning the fold's own mention into a classification and letting an
//! unclassified install through (bindreams/hole#1003, #1010).
//!
//! What it scans for is identifiers, in lexed code — so renaming the symbol at
//! its `use` does not hide it (`an_aliased_boot_time_flag_still_fires_the_tripwire`),
//! and neither does spacing, a comment of any shape, or a string literal. The
//! disclosed residual is a flag that names no symbol at all:
//! `FWPM_FILTER_FLAGS(0x4)` written as bits installs a boot-time filter that
//! nothing here can see. Closing that takes a type that cannot hand out the
//! bits without the [`super::KeyLifetime`] — the compile-time coupling #1010
//! is the change that can land it, because introducing it here would put both
//! symbols in production code and leave this guard permanently satisfied.

use std::path::{Path, PathBuf};

use proc_macro2::{Delimiter, Group, TokenStream, TokenTree};

/// The crate's production sources on disk, sorted.
///
/// Symlinks are followed. `rustc` resolves `mod boottime;` through one, so a
/// symlinked source ships; a scan that skipped it would disagree with the
/// compiler about what is in the binary. (`WalkDir` does not follow links by
/// default, and an unfollowed symlink's `file_type()` is neither file nor dir,
/// so the default configuration drops it before `is_production_source` is
/// asked.) An I/O error is a panic, not an empty result: a scan that read
/// nothing must never read as a scan that found nothing.
fn production_sources_under(dir: &Path) -> Vec<PathBuf> {
    let mut found: Vec<PathBuf> = walkdir::WalkDir::new(dir)
        .follow_links(true)
        .into_iter()
        .map(|e| e.expect("walk the crate sources"))
        .filter(|e| e.file_type().is_file())
        .map(walkdir::DirEntry::into_path)
        .filter(|p| is_production_source(p))
        .collect();
    found.sort();
    found
}

/// A Rust source that ships, as opposed to one that tests it. The exclusion is
/// load-bearing: `windows_tests.rs` and this very module name both boot-time
/// symbols, so a scan that took the whole tree would read an install out of
/// test code.
fn is_production_source(path: &Path) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    name.ends_with(".rs") && !name.ends_with("_tests.rs")
}

/// One source's executing tokens: what the compiler acts on, with every form
/// of non-executing text gone.
///
/// The failclosed modules' docs discuss the boot-time flag by name, and a
/// guard that counted prose would fire on documentation alone — the fastest
/// way to get a tripwire deleted rather than obeyed. Lexing is what decides
/// which mentions those are, because there are four kinds and a line filter
/// recognises one: `//` owning a line, `//` trailing a line of code,
/// `/* ... */`, and a string literal. The lexer drops the first three
/// outright; `///` and `//!` survive it as `#[doc = "..."]` attributes, which
/// [`flatten`] drops; and every predicate below reads identifiers, so a
/// literal is never examined. A missed one is not a false alarm but a silent
/// pass — it makes the classification half read true with no classification
/// arm in existence, which satisfies the equality over an UNCLASSIFIED
/// boot-time install.
///
/// A lex failure is a panic, for the reason [`production_sources_under`]
/// gives: a scan that read nothing must never read as a scan that found
/// nothing.
fn tokens(path: &Path) -> Vec<TokenTree> {
    let text = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    let stream: TokenStream = text.parse().unwrap_or_else(|e| panic!("lex {}: {e}", path.display()));
    let mut out = Vec::new();
    flatten(stream, &mut out);
    out
}

/// `stream`'s tokens depth-first, with doc attributes dropped.
///
/// Flattened rather than walked as a tree so an adjacency is visible wherever
/// it sits, including inside a macro's delimiters — `matches!(k,
/// KeyLifetime::BootTime)` classifies just as much as a bare match arm does.
fn flatten(stream: TokenStream, out: &mut Vec<TokenTree>) {
    let mut it = stream.into_iter().peekable();
    while let Some(tt) = it.next() {
        if matches!(&tt, TokenTree::Punct(p) if p.as_char() == '#') {
            let bang = it.next_if(|t| matches!(t, TokenTree::Punct(p) if p.as_char() == '!'));
            if it
                .peek()
                .is_some_and(|t| matches!(t, TokenTree::Group(g) if is_doc_attr(g)))
            {
                it.next();
                continue;
            }
            out.push(tt);
            out.extend(bang);
            continue;
        }
        match tt {
            TokenTree::Group(g) => flatten(g.stream(), out),
            other => out.push(other),
        }
    }
}

/// Whether a group is the body of a `#[doc = "..."]` attribute — a `///` or
/// `//!` comment as the lexer rewrote it.
fn is_doc_attr(g: &Group) -> bool {
    g.delimiter() == Delimiter::Bracket
        && matches!(g.stream().into_iter().next(), Some(TokenTree::Ident(i)) if i == "doc")
}

/// Whether executing code names this identifier.
///
/// An identifier, not a spelling: `use ... FWPM_FILTER_FLAG_BOOTTIME as
/// BOOT_FLAG` names it at the import whichever file spends the alias, and
/// `KeyLifetime :: BootTime` is the same three tokens however it is spaced.
fn names(tokens: &[TokenTree], ident: &str) -> bool {
    tokens.iter().any(|t| matches!(t, TokenTree::Ident(i) if i == ident))
}

/// Whether executing code defines a function by this name.
fn defines_fn(tokens: &[TokenTree], name: &str) -> bool {
    tokens
        .windows(2)
        .any(|w| matches!(&w[0], TokenTree::Ident(i) if i == "fn") && matches!(&w[1], TokenTree::Ident(i) if i == name))
}

/// The sources that DEFINE the lifetime fold, found by the definition rather
/// than by a path.
///
/// This is what anchors the classification half's one exclusion. `proves_empty`
/// is the function that decides what an empty answer proves for each
/// `KeyLifetime`, so its file's `KeyLifetime::BootTime` mentions are the
/// definition of the rule, not a classification of any key.
fn decision_sites(sources: &[PathBuf]) -> Vec<PathBuf> {
    sources
        .iter()
        .filter(|p| defines_fn(&tokens(p), "proves_empty"))
        .cloned()
        .collect()
}

/// `(installs_boot_time, classifies_boot_time)` across `sources`.
///
/// The install half spans every source given; the classification half skips
/// `decision_site`, for the reason [`decision_sites`] gives. Asymmetric on
/// purpose: an install in the file that defines the fold must still fire.
///
/// The classification half looks for the bare `BootTime` rather than the
/// qualified path: a variant reached through a `use` of it is a classification
/// too, and an over-wide classification half can only fail this guard loudly,
/// while an over-narrow one passes it in silence.
fn boot_time_halves(sources: &[PathBuf], decision_site: &Path) -> (bool, bool) {
    let installs = sources.iter().any(|p| names(&tokens(p), "FWPM_FILTER_FLAG_BOOTTIME"));
    let classifies = sources
        .iter()
        .filter(|p| p.as_path() != decision_site)
        .any(|p| names(&tokens(p), "BootTime"));
    (installs, classifies)
}

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Where the fold is expected to live. Asserted, never assumed.
fn decision_site() -> PathBuf {
    crate_src().join("routing").join("failclosed.rs")
}

/// Relative, slash-normalised names, for readable fixture assertions.
fn relative(dir: &Path, found: Vec<PathBuf>) -> Vec<String> {
    let mut names: Vec<String> = found
        .into_iter()
        .map(|p| {
            p.strip_prefix(dir)
                .expect("under the fixture root")
                .to_string_lossy()
                .replace('\\', "/")
        })
        .collect();
    names.sort();
    names
}

#[skuld::test]
fn a_boot_time_flag_cannot_be_introduced_without_classifying_its_key() {
    // A tripwire, deliberately, and not a proof — the fact it guards spans a
    // runtime `FilterSpec` (what `add_filter` stamps) and a static sweep array
    // (what `release_all` classifies), and no type in this module holds both.
    //
    // What it catches is the one mistake that is silent AND harmful: adding a
    // `FWPM_FILTER_FLAG_BOOTTIME` filter (bindreams/hole#998, #1010) while
    // leaving its key tagged `KeyLifetime::Persistent`. `release_all` would
    // then report proof it does not have, and the MSI would delete `hole.exe`
    // on the strength of it (bindreams/hole#1003). Both halves are absent
    // today; whoever adds the first must add the other.
    //
    // The scan is the crate's source tree, not one hardcoded file: an add that
    // landed in a new submodule (`failclosed/windows/boottime.rs`) — or at the
    // other sanctioned FWPM site, `dns_confine/windows.rs` — would otherwise
    // leave both halves false, the equality holding, and the mis-tag shipping.
    let src = crate_src();
    let sources = production_sources_under(&src);
    assert!(
        sources.iter().any(|p| p.ends_with("routing/failclosed/windows.rs")),
        "the scan found no routing/failclosed/windows.rs under {}; a tripwire that reads nothing \
         passes forever",
        src.display()
    );

    // The classification half excludes exactly one file, and this is what
    // keeps that exclusion honest. Move `proves_empty` into a scanned source
    // and its own `KeyLifetime::BootTime` arm would make `classifies`
    // permanently true — after which an UNCLASSIFIED boot-time install
    // satisfies the equality below and passes in silence. That is the worst
    // failure this guard has, so it is the one it refuses to reach.
    let site = decision_site();
    assert_eq!(
        decision_sites(&sources),
        vec![site.clone()],
        "`fn proves_empty` — the fold this guard's one exclusion is scoped to — is not where the \
         exclusion says it is; re-anchor `decision_site()` before trusting the halves below"
    );

    let (installs_boot_time, classifies_boot_time) = boot_time_halves(&sources, &site);
    assert_eq!(
        installs_boot_time, classifies_boot_time,
        "the crate's sources install boot-time filters ({installs_boot_time}) but classify \
         boot-time keys ({classifies_boot_time}); a sweep that deletes a boot-time key while \
         calling it Persistent reports a proof of removal it never observed"
    );
}

#[skuld::test]
fn the_scan_reaches_a_nested_source_and_never_a_test_file() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::create_dir_all(dir.join("windows")).expect("mkdir");
    for name in [
        "windows.rs",
        "macos.rs",
        "windows/boottime.rs",
        "windows_tests.rs",
        "windows/boottime_privileged_tests.rs",
        "notes.md",
    ] {
        std::fs::write(dir.join(name), "").expect("write");
    }

    assert_eq!(
        relative(dir, production_sources_under(dir)),
        vec!["macos.rs", "windows.rs", "windows/boottime.rs"]
    );
}

#[cfg(unix)]
#[skuld::test]
fn the_scan_reads_a_source_that_is_a_symlink() {
    // `rustc` resolves `mod boottime;` through a symlink, so a symlinked
    // source ships. `WalkDir` does not follow links by default, and an
    // unfollowed symlink's `file_type()` is neither file nor dir — so the
    // default configuration drops it before `is_production_source` is ever
    // asked. The compiler and the tripwire then disagree about what ships.
    // The `include_str!` form this scan replaced followed links; the move is
    // what opened the gap.
    //
    // `#[cfg(unix)]` because creating a symlink on Windows needs
    // SeCreateSymbolicLinkPrivilege or Developer Mode. What is under test is
    // the `WalkDir` configuration, which is not platform-specific.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().join("failclosed");
    std::fs::create_dir_all(dir.join("windows")).expect("mkdir");
    std::fs::write(dir.join("windows.rs"), "let l = KeyLifetime::Persistent;").expect("write");
    // The target sits outside the scanned tree, so the scan can reach its
    // contents only by following the link.
    let target = root.path().join("boottime-source");
    std::fs::write(&target, "*f |= FWPM_FILTER_FLAG_BOOTTIME.0;").expect("write");
    std::os::unix::fs::symlink(&target, dir.join("windows/boottime.rs")).expect("symlink");

    let sources = production_sources_under(&dir);
    assert_eq!(
        relative(&dir, sources.clone()),
        vec!["windows.rs", "windows/boottime.rs"],
        "a symlinked .rs is a source the compiler reads, so the scan reads it too"
    );
    assert_eq!(boot_time_halves(&sources, &dir.join("failclosed.rs")), (true, false));
}

#[skuld::test]
fn the_tripwire_fires_on_a_flag_added_in_a_new_submodule() {
    // The #1010 shape, landed one directory deeper than #1010 lands it.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::create_dir_all(dir.join("windows")).expect("mkdir");
    std::fs::write(dir.join("windows.rs"), "let l = KeyLifetime::Persistent;").expect("write");
    std::fs::write(dir.join("windows/boottime.rs"), "flags |= FWPM_FILTER_FLAG_BOOTTIME.0;").expect("write");
    // The trap: classifying it in a test is not classifying it.
    std::fs::write(
        dir.join("windows_tests.rs"),
        "assert_eq!(k.lifetime, KeyLifetime::BootTime);",
    )
    .expect("write");

    assert_eq!(
        boot_time_halves(&production_sources_under(dir), &dir.join("failclosed.rs")),
        (true, false)
    );
}

#[skuld::test]
fn a_boot_time_symbol_named_only_in_prose_does_not_fire_the_tripwire() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "//! A `FWPM_FILTER_FLAG_BOOTTIME` key answers FWP_E_FILTER_NOT_FOUND.\n\
         /// See [`KeyLifetime::BootTime`].\n\
         fn f() {}\n",
    )
    .expect("write");

    assert_eq!(
        boot_time_halves(&production_sources_under(dir), &dir.join("failclosed.rs")),
        (false, false)
    );
}

#[skuld::test]
fn a_boot_time_symbol_in_a_trailing_comment_does_not_fire_the_tripwire() {
    // A comment does not have to own its line. The line filter this scan
    // replaced only recognised one that did, so a trailing `// ...` made the
    // classification half read true with no classification arm in existence —
    // and an UNCLASSIFIED boot-time install then satisfied the equality.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "let flags = 0; // FWPM_FILTER_FLAG_BOOTTIME is not set here\n\
         let l = KeyLifetime::Persistent; // not KeyLifetime::BootTime\n",
    )
    .expect("write");

    assert_eq!(
        boot_time_halves(&production_sources_under(dir), &dir.join("failclosed.rs")),
        (false, false)
    );
}

#[skuld::test]
fn a_boot_time_symbol_in_a_block_comment_does_not_fire_the_tripwire() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "/* FWPM_FILTER_FLAG_BOOTTIME */\n\
         fn f() {}\n\
         /* a /* nested */ note about KeyLifetime::BootTime */\n",
    )
    .expect("write");

    assert_eq!(
        boot_time_halves(&production_sources_under(dir), &dir.join("failclosed.rs")),
        (false, false)
    );
}

#[skuld::test]
fn a_boot_time_symbol_in_a_string_literal_does_not_fire_the_tripwire() {
    // The third way a symbol appears in text that does not execute. A key's
    // operator-facing `label` is a string sitting right beside its lifetime,
    // so this is the one a real edit is most likely to produce.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "let label = \"FWPM_FILTER_FLAG_BOOTTIME\";\n\
         let doc = \"see KeyLifetime::BootTime\";\n",
    )
    .expect("write");

    assert_eq!(
        boot_time_halves(&production_sources_under(dir), &dir.join("failclosed.rs")),
        (false, false)
    );
}

#[skuld::test]
fn an_aliased_boot_time_flag_still_fires_the_tripwire() {
    // Renaming the symbol at the `use` does not hide it: the import names it
    // in full, and the install half spans every production source with no
    // exclusion, so the `use` line is scanned whether or not it sits in the
    // file that spends the alias.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("imports.rs"),
        "use windows::Win32::NetworkManagement::WindowsFilteringPlatform::\n\
         FWPM_FILTER_FLAG_BOOTTIME as BOOT_FLAG;\n",
    )
    .expect("write");
    std::fs::write(dir.join("windows.rs"), "flags |= BOOT_FLAG.0;\n").expect("write");

    assert_eq!(
        boot_time_halves(&production_sources_under(dir), &dir.join("failclosed.rs")),
        (true, false)
    );
}

#[skuld::test]
fn the_fold_is_found_by_its_definition_and_never_by_prose() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(dir.join("failclosed.rs"), "pub fn proves_empty(&self) -> bool { true }").expect("write");
    std::fs::write(
        dir.join("windows.rs"),
        "/// Whether `fn proves_empty` says so.\nfn g() {}",
    )
    .expect("write");

    assert_eq!(
        relative(dir, decision_sites(&production_sources_under(dir))),
        vec!["failclosed.rs"]
    );
}

#[skuld::test]
fn a_fold_that_moved_is_not_mistaken_for_a_classification() {
    // The vacuity trigger this guard is built against. `proves_empty`'s
    // `(KeyLifetime::BootTime, KeyOutcome::NotFound)` arm names the variant
    // without classifying any key. If that arm ever sat in a scanned source
    // and were counted, `classifies` would be permanently true and an
    // UNCLASSIFIED boot-time install would satisfy the equality — a silent
    // pass, on the guard that gates #1010's merge.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "flags |= FWPM_FILTER_FLAG_BOOTTIME.0;\n\
         fn proves_empty(&self) -> bool { matches!(self.0, KeyLifetime::BootTime) }\n",
    )
    .expect("write");
    let sources = production_sources_under(dir);

    // Scoped to where the fold actually is, the install stands alone.
    assert_eq!(boot_time_halves(&sources, &dir.join("windows.rs")), (true, false));
    // Scoped anywhere else, the fold's own mention masks it — which is why the
    // main test asserts `decision_sites` before it asserts the halves.
    assert_eq!(boot_time_halves(&sources, &dir.join("elsewhere.rs")), (true, true));
    assert_eq!(relative(dir, decision_sites(&sources)), vec!["windows.rs"]);
}
