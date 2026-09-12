//! Tripwire: the `FWPM_FILTER_FLAG_BOOTTIME` bit may be produced in exactly
//! one place, the one that cannot produce it without a
//! [`super::KeyLifetime`].
//!
//! ## What this guarded before, and why that form retired
//!
//! It used to assert an equality: the crate's production sources install
//! boot-time filters iff they classify boot-time keys. That was a tripwire for
//! a mistake with no compile-time answer — installing
//! `FWPM_FILTER_FLAG_BOOTTIME` while leaving the key tagged
//! `KeyLifetime::Persistent`, after which `release_all` reports a proof of
//! removal it never observed and the MSI deletes `hole.exe` on the strength of
//! it (bindreams/hole#1003).
//!
//! bindreams/hole#1010 gave it a compile-time answer, which is also what
//! killed the equality form. `FilterLifetime` (`failclosed/windows.rs`) is a newtype
//! over `KeyLifetime` whose only flag accessor reads the very variant the
//! sweep records, and the twins' key, layer and lifetime come from one table
//! both `build_lockdown_spec` and `swept_lockdown_keys` read. Installing a
//! boot-time filter without classifying its key stopped being a mistake and
//! became a thing you cannot say. But it also put BOTH symbols in production
//! code permanently: `installs` and `classifies` are now both true and both
//! stay true, so the equality holds no matter what a later change does — and
//! a guard that can no longer fail in the direction that matters is worse than
//! no guard, because it still reads like evidence. The equality is gone rather
//! than left standing. This file's own doc predicted that and said to make the
//! call here.
//!
//! ## What it guards now
//!
//! The property the type CANNOT enforce: that the type is the only way in.
//! `FilterLifetime::filter_flags` couples the bit to the classification for
//! everyone who goes through it; nothing stops a future source from naming
//! `FWPM_FILTER_FLAG_BOOTTIME` itself and going around. So the scan asserts
//! the flag is named by exactly one production source, the one that defines
//! that mapping — found by its definition, never by a path, so moving it
//! re-anchors the guard instead of silently widening it.
//!
//! That subsumes the old equality for the hazard it existed for. A boot-time
//! filter reaching the firewall through `FilterLifetime` carries its
//! classification by construction; one reaching it any other way names the
//! flag and fires this.
//!
//! ## The residual the old doc disclosed, and where it went
//!
//! `FWPM_FILTER_FLAGS(0x4)` written as bits names no flag symbol at all, so
//! the scan above cannot see it. Three things now stand between that and a
//! boot-time filter, and the second test here is the first of them:
//!
//! 1. The raw flags type may be named only by the source that defines the
//!    mapping, plus any source that opens its FWPM engine
//!    `FWPM_SESSION_FLAG_DYNAMIC` — WFP does not accept a boot-time filter on
//!    a dynamic-session object, so bits written there cannot reach the boot
//!    window. The exemption is anchored to that flag rather than to a path, so
//!    `dns_confine/windows.rs` falls back under the rule if it ever stops
//!    naming it. **Its granularity is the FILE, not the session**, and that is
//!    the residual: a source keeps the exemption for every raw-bit write in it
//!    as long as it opens one dynamic session somewhere, so a second,
//!    non-dynamic engine added to the same file would write `0x4` unseen.
//!    Narrowing that needs the scan to tie a flags construction to the engine
//!    it is spent on, which is dataflow, not lexing — out of reach of a
//!    tripwire, and the reason 2 and 3 below are not optional.
//! 2. `FwpmFilterAdd0` is clippy-`disallowed_methods` with exactly those two
//!    sanctioned sites, so bits materialised in a third source have nowhere to
//!    be spent.
//! 3. Inside the one non-dynamic site, `add_filter` takes its flags from
//!    `f.lifetime.filter_flags()` and there is no other assignment to
//!    `FWPM_FILTER0::flags`.
//!
//! Clippy cannot close 1 on its own, and this was measured rather than
//! assumed: `disallowed_types` fires on a type in a signature but NOT on a
//! bare tuple-struct construction expression, which is the shape the residual
//! takes.
//!
//! ## Scope
//!
//! Every production source in this crate, recursively — not just
//! `failclosed/`. `failclosed/windows.rs` is NOT the only sanctioned FWPM site
//! in tun-engine: `dns_confine/windows.rs` calls `FwpmFilterAdd0` too, and
//! `clippy.toml` names both.
//!
//! What it scans for is identifiers, in lexed code — so renaming the symbol at
//! its `use` does not hide it (`an_aliased_boot_time_flag_still_fires_the_tripwire`),
//! and neither does spacing, a comment of any shape, or a string literal. The
//! failclosed modules' docs discuss both symbols at length, and a guard that
//! counted prose would fire on documentation alone — the fastest way to get a
//! tripwire deleted rather than obeyed.

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
/// load-bearing: `windows_tests.rs` and this very module name the boot-time
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
/// Lexing is what decides which mentions are prose, because there are four
/// kinds and a line filter recognises one: `//` owning a line, `//` trailing a
/// line of code, `/* ... */`, and a string literal. The lexer drops the first
/// three outright; `///` and `//!` survive it as `#[doc = "..."]` attributes,
/// which [`flatten`] drops; and every predicate below reads identifiers, so a
/// literal is never examined. A missed one is not a false alarm but a silent
/// pass — it would put a source in the "names the flag" set on the strength of
/// a comment, and the assertions below are set equalities.
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
/// Flattened rather than walked as a tree so a mention is visible wherever it
/// sits, including inside a macro's delimiters.
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
/// BOOT_FLAG` names it at the import whichever file spends the alias.
fn names(tokens: &[TokenTree], ident: &str) -> bool {
    tokens.iter().any(|t| matches!(t, TokenTree::Ident(i) if i == ident))
}

/// Whether executing code defines a function by this name.
fn defines_fn(tokens: &[TokenTree], name: &str) -> bool {
    tokens
        .windows(2)
        .any(|w| matches!(&w[0], TokenTree::Ident(i) if i == "fn") && matches!(&w[1], TokenTree::Ident(i) if i == name))
}

/// The sources naming `ident` in executing code, in scan order.
fn sources_naming(sources: &[PathBuf], ident: &str) -> Vec<PathBuf> {
    sources.iter().filter(|p| names(&tokens(p), ident)).cloned().collect()
}

/// The sources that DEFINE the lifetime-to-flag mapping, found by the
/// definition rather than by a path.
///
/// This is what both assertions are anchored to. `FilterLifetime::filter_flags`
/// is the function that turns a [`super::KeyLifetime`] into
/// `FWPM_FILTER0::flags`; moving it must re-anchor this guard, not quietly
/// leave it pointing at a file that no longer produces the bits.
fn flag_producer_sites(sources: &[PathBuf]) -> Vec<PathBuf> {
    sources
        .iter()
        .filter(|p| defines_fn(&tokens(p), "filter_flags"))
        .cloned()
        .collect()
}

/// The sources that open an FWPM engine with a DYNAMIC session, found by the
/// session flag rather than by a path.
///
/// A dynamic session's objects die with the process and WFP does not accept a
/// boot-time filter on one, so raw flag bits written there cannot reach the
/// boot window. That is why `dns_confine/windows.rs` may name
/// `FWPM_FILTER_FLAGS` — and anchoring on the flag rather than on its path is
/// what makes the exemption expire if it ever stops being dynamic.
///
/// Whole-file granularity, stated because it is the guard's residual: this
/// exempts every raw-bit write in a source that opens ONE dynamic session, not
/// only the writes spent on that session. See the module doc's residual list
/// for what stands behind it.
fn dynamic_session_sites(sources: &[PathBuf]) -> Vec<PathBuf> {
    sources_naming(sources, "FWPM_SESSION_FLAG_DYNAMIC")
}

fn crate_src() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Where the mapping is expected to live. Asserted, never assumed.
fn flag_producer_site() -> PathBuf {
    crate_src().join("routing").join("failclosed").join("windows.rs")
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

/// The scan's own precondition: it read the file the guard is about. A
/// tripwire that reads nothing passes forever.
fn scanned_sources() -> Vec<PathBuf> {
    let src = crate_src();
    let sources = production_sources_under(&src);
    assert!(
        sources.iter().any(|p| p.ends_with("routing/failclosed/windows.rs")),
        "the scan found no routing/failclosed/windows.rs under {}; a tripwire that reads nothing \
         passes forever",
        src.display()
    );
    sources
}

#[skuld::test]
fn the_boot_time_flag_is_named_only_where_a_key_lifetime_produces_it() {
    // The one mistake that is silent AND harmful: getting
    // `FWPM_FILTER_FLAG_BOOTTIME` into the firewall without the
    // `KeyLifetime::BootTime` that tells `release_all` what a not-found delete
    // on that key proves (bindreams/hole#998, #1003, #1010). Going through
    // `FilterLifetime` makes that impossible; this is the guard on the "going
    // through" part.
    let sources = scanned_sources();

    // Anchored to where the mapping actually is. Move `filter_flags` and this
    // fails loudly rather than leaving the assertion below pointing at a file
    // that no longer couples anything.
    let site = flag_producer_site();
    assert_eq!(
        flag_producer_sites(&sources),
        vec![site.clone()],
        "`fn filter_flags` — the lifetime-to-flag mapping this guard is anchored to — is not \
         where the anchor says it is; re-anchor `flag_producer_site()` before trusting the \
         assertion below"
    );

    assert_eq!(
        sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME"),
        vec![site],
        "a production source other than the one defining `FilterLifetime::filter_flags` names \
         the boot-time flag, so it can install a boot-time filter without a `KeyLifetime` — and \
         a sweep that deletes such a key while calling it Persistent reports a proof of removal \
         it never observed"
    );
}

#[skuld::test]
fn the_raw_flag_bits_are_named_only_where_they_cannot_reach_the_boot_window() {
    // The residual the equality form disclosed and could not see:
    // `FWPM_FILTER_FLAGS(0x4)` names no flag symbol. Clippy cannot cover it —
    // `disallowed_types` fires on a type in a signature but not on a bare
    // tuple-struct construction expression (measured, not assumed) — so the
    // set of sources that can materialise the bits is pinned here instead.
    let sources = scanned_sources();

    let mut allowed = flag_producer_sites(&sources);
    allowed.extend(dynamic_session_sites(&sources));
    allowed.sort();
    allowed.dedup();
    assert!(
        !allowed.is_empty(),
        "neither anchor matched any source, which would make the assertion below vacuous"
    );

    assert_eq!(
        sources_naming(&sources, "FWPM_FILTER_FLAGS"),
        allowed,
        "a production source materialises raw WFP filter flags without either defining the \
         `KeyLifetime` mapping or running a DYNAMIC session (where WFP refuses a boot-time \
         filter outright); bits written there can carry 0x4 with nothing to classify the key"
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
    //
    // `#[cfg(unix)]` because creating a symlink on Windows needs
    // SeCreateSymbolicLinkPrivilege or Developer Mode. What is under test is
    // the `WalkDir` configuration, which is not platform-specific.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path().join("failclosed");
    std::fs::create_dir_all(dir.join("windows")).expect("mkdir");
    std::fs::write(dir.join("windows.rs"), "fn filter_flags() {}").expect("write");
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
    assert_eq!(
        relative(&dir, sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME")),
        vec!["windows/boottime.rs"]
    );
}

#[skuld::test]
fn the_tripwire_fires_on_a_flag_named_in_a_new_submodule() {
    // The shape the type cannot prevent: a source that reaches for the flag
    // itself instead of going through `FilterLifetime`, landing one directory
    // deeper than the mapping.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::create_dir_all(dir.join("windows")).expect("mkdir");
    std::fs::write(dir.join("windows.rs"), "fn filter_flags() {}").expect("write");
    std::fs::write(dir.join("windows/boottime.rs"), "flags |= FWPM_FILTER_FLAG_BOOTTIME.0;").expect("write");
    // The trap: naming it in a test is not naming it in a source that ships.
    std::fs::write(
        dir.join("windows_tests.rs"),
        "assert_eq!(k.lifetime, KeyLifetime::BootTime);",
    )
    .expect("write");

    let sources = production_sources_under(dir);
    assert_eq!(relative(dir, flag_producer_sites(&sources)), vec!["windows.rs"]);
    assert_eq!(
        relative(dir, sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME")),
        vec!["windows/boottime.rs"],
        "the flag is named somewhere other than the mapping, which is what must fire"
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

    let sources = production_sources_under(dir);
    assert!(sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME").is_empty());
}

#[skuld::test]
fn a_boot_time_symbol_in_a_trailing_comment_does_not_fire_the_tripwire() {
    // A comment does not have to own its line. The line filter this scan
    // replaced only recognised one that did.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "let flags = 0; // FWPM_FILTER_FLAG_BOOTTIME is not set here\n\
         let l = KeyLifetime::Persistent; // not KeyLifetime::BootTime\n",
    )
    .expect("write");

    let sources = production_sources_under(dir);
    assert!(sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME").is_empty());
}

#[skuld::test]
fn a_boot_time_symbol_in_a_block_comment_does_not_fire_the_tripwire() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "/* FWPM_FILTER_FLAG_BOOTTIME */\n\
         fn f() {}\n\
         /* a /* nested */ note about FWPM_FILTER_FLAGS */\n",
    )
    .expect("write");

    let sources = production_sources_under(dir);
    assert!(sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME").is_empty());
    assert!(sources_naming(&sources, "FWPM_FILTER_FLAGS").is_empty());
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
         let doc = \"see FWPM_FILTER_FLAGS\";\n",
    )
    .expect("write");

    let sources = production_sources_under(dir);
    assert!(sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME").is_empty());
    assert!(sources_naming(&sources, "FWPM_FILTER_FLAGS").is_empty());
}

#[skuld::test]
fn an_aliased_boot_time_flag_still_fires_the_tripwire() {
    // Renaming the symbol at the `use` does not hide it: the import names it
    // in full, and the scan spans every production source, so the `use` line
    // is read whether or not it sits in the file that spends the alias.
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("imports.rs"),
        "use windows::Win32::NetworkManagement::WindowsFilteringPlatform::\n\
         FWPM_FILTER_FLAG_BOOTTIME as BOOT_FLAG;\n",
    )
    .expect("write");
    std::fs::write(dir.join("windows.rs"), "flags |= BOOT_FLAG.0;\n").expect("write");

    let sources = production_sources_under(dir);
    assert_eq!(
        relative(dir, sources_naming(&sources, "FWPM_FILTER_FLAG_BOOTTIME")),
        vec!["imports.rs"]
    );
}

#[skuld::test]
fn the_mapping_is_found_by_its_definition_and_never_by_prose() {
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("windows.rs"),
        "fn filter_flags(self) -> FWPM_FILTER_FLAGS { todo!() }",
    )
    .expect("write");
    std::fs::write(
        dir.join("macos.rs"),
        "/// Whether `fn filter_flags` says so.\nfn g() {}",
    )
    .expect("write");

    assert_eq!(
        relative(dir, flag_producer_sites(&production_sources_under(dir))),
        vec!["windows.rs"]
    );
}

#[skuld::test]
fn a_dynamic_session_is_exempt_from_the_raw_bits_rule_and_a_static_one_is_not() {
    // The exemption is anchored to the dynamic session, not to a path: a
    // source that writes raw flag bits keeps the exemption only while it names
    // the flag that makes WFP refuse a boot-time filter on its objects. Stop
    // being dynamic and the exemption stops with it. (Whole-file granularity —
    // see `dynamic_session_sites` for the residual that leaves.)
    let root = tempfile::tempdir().expect("tempdir");
    let dir = root.path();
    std::fs::write(
        dir.join("dynamic.rs"),
        "let session = FWPM_SESSION0 { flags: FWPM_SESSION_FLAG_DYNAMIC, ..Default::default() };\n\
         let flags = FWPM_FILTER_FLAGS(0);\n",
    )
    .expect("write");
    std::fs::write(dir.join("persistent.rs"), "let flags = FWPM_FILTER_FLAGS(0x4);\n").expect("write");

    let sources = production_sources_under(dir);
    assert_eq!(relative(dir, dynamic_session_sites(&sources)), vec!["dynamic.rs"]);
    assert_eq!(
        relative(dir, sources_naming(&sources, "FWPM_FILTER_FLAGS")),
        vec!["dynamic.rs", "persistent.rs"],
        "`persistent.rs` names the bits with no dynamic session and no mapping, which is what \
         must fire"
    );
}
