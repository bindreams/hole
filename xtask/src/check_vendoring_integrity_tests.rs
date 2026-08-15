//! Tests for `check_vendoring_integrity` — fixture-repo style (a small real
//! repo with a `.gitrepo`, a `VENDORING.md`, and an outer `go.mod`), running
//! `check_vendoring_integrity::run` against it for real, not a mock.

use std::path::Path;
use std::process::Command;

use crate::finish_vendor_bump::test_support::create_passing_v2ray_core_stub;
use crate::{check_vendoring_integrity, finish_vendor_bump, pull_subrepo};

const GITREPO_TEMPLATE: &str = "[subrepo]\n\
\tremote = https://example.com/upstream\n\
\tbranch = {branch}\n\
\tcommit = 0000000000000000000000000000000000000000\n\
\tparent = 0000000000000000000000000000000000000000\n\
\tmethod = merge\n\
\tcmdver = 0.4.9\n";

/// A minimal real repo under construction: `crates/ex-ray/go.mod` +
/// `crates/ex-ray/third_party/VENDORING.md`, plus zero or more vendored
/// deps, each added via `dep`. Every write stages the file; call
/// `commit_all` once the fixture is fully assembled.
struct RepoBuilder {
    dir: tempfile::TempDir,
}

impl RepoBuilder {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "--initial-branch=main", "--quiet"]);
        // Fixtures never intend platform-dependent line-ending mutation —
        // a checkout inside these tests (e.g. resolving an allowlisted
        // conflict to upstream's content) must not silently smudge LF to
        // CRLF on a Windows runner with a global `core.autocrlf=true`
        // (GitHub's windows-latest default) and desync from what the test
        // literally wrote/asserts.
        git(dir.path(), &["config", "core.autocrlf", "false"]);
        git(dir.path(), &["config", "user.email", "fixture@example.com"]);
        git(dir.path(), &["config", "user.name", "fixture"]);
        Self { dir }
    }

    fn root(&self) -> &Path {
        self.dir.path()
    }

    fn write(&self, rel: &str, content: impl AsRef<[u8]>) -> &Self {
        let path = self.root().join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, content).unwrap();
        self
    }

    fn ex_ray_go_mod(&self, content: &str) -> &Self {
        self.write("crates/ex-ray/go.mod", content)
    }

    fn vendoring_md(&self, content: &str) -> &Self {
        self.write("crates/ex-ray/third_party/VENDORING.md", content)
    }

    /// Adds a vendored dep at `crates/ex-ray/third_party/<name>`: a
    /// `.gitrepo` pinned to `branch` and a `go.mod` declaring `module_path`.
    fn dep(&self, name: &str, branch: &str, module_path: &str) -> &Self {
        self.write(
            &format!("crates/ex-ray/third_party/{name}/.gitrepo"),
            GITREPO_TEMPLATE.replace("{branch}", branch),
        );
        self.write(
            &format!("crates/ex-ray/third_party/{name}/go.mod"),
            format!("module {module_path}\n\ngo 1.25\n"),
        );
        self
    }

    fn commit_all(&self) {
        git(self.root(), &["add", "-A"]);
        git(self.root(), &["commit", "-m", "fixture"]);
    }
}

fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run git {args:?} in {}: {e}", cwd.display()));
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}

/// Default clean-shape ex-ray go.mod: requires and replaces `widget` at
/// `v1.0.0`, matching `widget`'s default `.gitrepo` branch below.
fn clean_ex_ray_go_mod() -> String {
    "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v1.0.0\n\n\
     replace example.com/widget => ./third_party/widget\n"
        .to_string()
}

fn clean_vendoring_md() -> String {
    "# Vendoring\n\n## `widget/` — pinned **v1.0.0** ([upstream](https://example.com))\n".to_string()
}

#[skuld::test]
fn fully_clean_tree_has_no_violations() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn conflict_markers_in_a_tracked_file_are_reported_with_file_and_line() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.write(
        "crates/ex-ray/third_party/widget/patched.go",
        "package widget\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> upstream\n",
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0].contains("crates/ex-ray/third_party/widget/patched.go:2"),
        "{violations:?}"
    );
}

#[skuld::test]
fn conflict_markers_in_an_untracked_file_are_not_reported() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    // Written AFTER commit_all, never `git add`ed — untracked.
    fx.write(
        "crates/ex-ray/third_party/widget/scratch.go",
        "package widget\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> upstream\n",
    );

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn a_tracked_binary_file_does_not_error_or_false_positive() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    // Invalid UTF-8 bytes, matching the shape of the real logo.png/
    // testdata/Client-* fixtures — must not hard-error a byte scan, and
    // must not spuriously "contain" a marker triple.
    fx.write(
        "crates/ex-ray/third_party/widget/logo.png",
        [0xffu8, 0xfe, 0x00, 0x01, 0x02, 0x89, 0x50, 0x4e, 0x47],
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn vendoring_md_version_mismatch_is_reported_naming_both_values() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.vendoring_md("# Vendoring\n\n## `widget/` — pinned **v0.9.0** ([upstream](https://example.com))\n");
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0].contains("v0.9.0") && violations[0].contains("v1.0.0"),
        "{violations:?}"
    );
}

#[skuld::test]
fn a_dep_with_no_vendoring_md_heading_is_reported_not_skipped() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.vendoring_md("# Vendoring\n\nNothing documented yet.\n");
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].contains("widget"), "{violations:?}");
}

#[skuld::test]
fn go_mod_direct_require_version_mismatch_is_reported() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(
        "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v0.9.0\n\n\
         replace example.com/widget => ./third_party/widget\n",
    );
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0].contains("v0.9.0") && violations[0].contains("v1.0.0"),
        "{violations:?}"
    );
}

#[skuld::test]
fn go_mod_indirect_require_version_mismatch_is_still_reported() {
    // The real utls/crates/ex-ray/go.mod shape: `// indirect`, mismatched —
    // indirect vs. direct must not matter to this check.
    let fx = RepoBuilder::new();
    fx.dep("utls", "v1.8.2", "github.com/refraction-networking/utls");
    fx.vendoring_md("# Vendoring\n\n## `utls/` — pinned **v1.8.2** ([upstream](https://example.com))\n");
    fx.ex_ray_go_mod(
        "module example.com/ex-ray\n\ngo 1.25\n\n\
         require (\n\tgithub.com/refraction-networking/utls v1.8.0 // indirect\n)\n",
    );
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(
        violations[0].contains("v1.8.0") && violations[0].contains("v1.8.2"),
        "{violations:?}"
    );
}

#[skuld::test]
fn go_mod_with_no_require_line_for_the_dep_is_not_a_violation() {
    // Synthetic fixture dep: reachable only transitively, no require line
    // of its own in the outer go.mod at all.
    let fx = RepoBuilder::new();
    fx.dep("transitive-only", "v2.0.0", "example.com/transitive-only");
    fx.vendoring_md("# Vendoring\n\n## `transitive-only/` — pinned **v2.0.0** ([upstream](https://example.com))\n");
    fx.ex_ray_go_mod("module example.com/ex-ray\n\ngo 1.25\n");
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn two_deps_one_clean_one_violating_reports_only_the_violating_one() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.dep("gadget", "v2.0.0", "example.com/gadget");
    fx.write(
        "crates/ex-ray/third_party/VENDORING.md",
        "# Vendoring\n\n\
         ## `widget/` — pinned **v1.0.0** ([upstream](https://example.com))\n\n\
         ## `gadget/` — pinned **v1.9.0** ([upstream](https://example.com))\n",
    );
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].contains("gadget"), "{violations:?}");
    assert!(!violations[0].contains("widget"), "{violations:?}");
}

#[skuld::test]
fn a_repo_with_zero_vendored_deps_is_clean_no_error() {
    let fx = RepoBuilder::new();
    fx.write("crates/ex-ray/go.mod", "module example.com/ex-ray\n\ngo 1.25\n");
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn two_simultaneous_violations_on_one_dep_both_appear() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.write(
        "crates/ex-ray/third_party/widget/patched.go",
        "package widget\n<<<<<<< HEAD\nours\n=======\ntheirs\n>>>>>>> upstream\n",
    );
    // Mismatched VENDORING.md note, alongside the marker conflict above —
    // proves run() accumulates rather than short-circuits.
    fx.vendoring_md("# Vendoring\n\n## `widget/` — pinned **v0.9.0** ([upstream](https://example.com))\n");
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 2, "{violations:?}");
    assert!(violations.iter().any(|v| v.contains("patched.go")), "{violations:?}");
    assert!(violations.iter().any(|v| v.contains("v0.9.0")), "{violations:?}");
}

#[skuld::test]
fn two_separate_conflict_triples_in_one_file_both_reported_with_distinct_lines() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.write(
        "crates/ex-ray/third_party/widget/patched.go",
        "package widget\n\
         <<<<<<< HEAD\n\
         ours one\n\
         =======\n\
         theirs one\n\
         >>>>>>> upstream\n\
         unrelated line\n\
         <<<<<<< HEAD\n\
         ours two\n\
         =======\n\
         theirs two\n\
         >>>>>>> upstream\n",
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 2, "{violations:?}");
    assert!(violations[0].contains(":2:"), "{violations:?}");
    assert!(violations[1].contains(":8:"), "{violations:?}");
}

#[skuld::test]
fn marker_text_not_at_line_start_is_not_reported() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.write(
        "crates/ex-ray/third_party/widget/example.go",
        "package widget\n\n// example: a line like \"<<<<<<< HEAD\" embedded mid-comment\n\
         // and \"=======\" and \">>>>>>> theirs\" too, none at true line start\n",
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn a_standalone_equals_divider_alone_is_not_reported() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.write(
        "crates/ex-ray/third_party/widget/NOTES.md",
        "Setext Heading\n=============\n\nBody text.\n",
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn an_unrelated_start_marker_followed_by_a_legitimate_divider_with_no_end_marker_is_not_reported() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.write(
        "crates/ex-ray/third_party/widget/EXAMPLE.md",
        "Example conflict marker syntax:\n<<<<<<< HEAD\n\nUnrelated divider further down:\n=======\n\nNo end marker anywhere after this.\n",
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations, Vec::<String>::new());
}

#[skuld::test]
fn a_realistic_conflict_with_real_hunk_content_on_both_sides_is_detected() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    fx.write(
        "crates/ex-ray/third_party/widget/patched.go",
        "package widget\n\
         <<<<<<< HEAD\n\
         func Ours() int {\n\
         \treturn 1\n\
         }\n\
         =======\n\
         func Theirs() int {\n\
         \treturn 2\n\
         }\n\
         >>>>>>> upstream/main\n",
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].contains("patched.go:2:"), "{violations:?}");
}

#[skuld::test]
fn a_tracked_vendor_conflict_sentinel_is_reported_regardless_of_check_1() {
    let fx = RepoBuilder::new();
    fx.dep("widget", "v1.0.0", "example.com/widget");
    // Clean tree otherwise — no marker text anywhere — proves check 4 fires
    // independently of check 1, not as a refinement of it.
    fx.write(
        "crates/ex-ray/third_party/widget/.vendor-conflict",
        "some/path\tdeadbeef\n",
    );
    fx.vendoring_md(&clean_vendoring_md());
    fx.ex_ray_go_mod(&clean_ex_ray_go_mod());
    fx.commit_all();

    let violations = check_vendoring_integrity::run(fx.root()).unwrap();
    assert_eq!(violations.len(), 1, "{violations:?}");
    assert!(violations[0].contains(".vendor-conflict"), "{violations:?}");
    assert!(violations[0].contains("widget"), "{violations:?}");
}

// The `always_run` hazard, end-to-end, with the real `prek` hook actually
// installed ===========================================================================================================
//
// `git subrepo pull`'s own internal `git commit` (and this module's/
// `finish_vendor_bump`'s own repo-root commits) touch only *part* of the
// `.gitrepo`/`VENDORING.md`/`go.mod` consistency `check-vendoring-integrity`
// enforces at each intermediate step. These two tests install a fixture
// `prek.toml` whose `check-vendoring-integrity` hook always fails (deciding
// "reject" is unconditional and deterministic — much stronger evidence the
// `SKIP` routing works than running the real, currently-clean check would
// be) and drive real `pull_subrepo`/`finish_vendor_bump` sequences through
// it: every commit they make must still succeed.

/// A minimal upstream Go module repo tagged `v1.0.0` and `v1.1.0` —
/// `conflicting`: whether `v1.1.0`'s content of `patched.go` conflicts with
/// the downstream fixture's own local patch to the same file.
fn build_upstream(dir: &Path, conflicting: bool) {
    std::fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "--initial-branch=main", "--quiet"]);
    // Fixtures never intend platform-dependent line-ending mutation —
    // a checkout inside these tests (e.g. resolving an allowlisted
    // conflict to upstream's content) must not silently smudge LF to
    // CRLF on a Windows runner with a global `core.autocrlf=true`
    // (GitHub's windows-latest default) and desync from what the test
    // literally wrote/asserts.
    git(dir, &["config", "core.autocrlf", "false"]);
    git(dir, &["config", "user.email", "fixture@example.com"]);
    git(dir, &["config", "user.name", "fixture"]);
    std::fs::write(dir.join("go.mod"), "module example.com/widget\n\ngo 1.25\n").unwrap();
    std::fs::write(
        dir.join("patched.go"),
        "package widget\n\nfunc Value() int { return 1 }\n",
    )
    .unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-m", "v1"]);
    git(dir, &["tag", "v1.0.0"]);

    if conflicting {
        std::fs::write(
            dir.join("patched.go"),
            "package widget\n\nfunc Value() int { return 2 } // upstream changed\n",
        )
        .unwrap();
    } else {
        std::fs::write(dir.join("README.md"), "docs\n").unwrap();
    }
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-m", "v2"]);
    git(dir, &["tag", "v1.1.0"]);
}

/// A downstream fixture repo shaped like the real `hole` repo's own
/// `crates/ex-ray/` vendoring layout: `go.mod`/`main.go` requiring +
/// replacing `widget`, `VENDORING.md` documenting it at `v1.0.0`, and
/// `widget` itself cloned in via a real `git subrepo clone`.
/// `patch_conflicting`: whether a local downstream commit also edits
/// `patched.go`, setting up a real (non-allowlisted) conflict against a
/// `conflicting` upstream.
fn build_downstream_with_widget(dir: &Path, upstream: &Path, patch_conflicting: bool) {
    std::fs::create_dir_all(dir).unwrap();
    git(dir, &["init", "--initial-branch=main", "--quiet"]);
    // Fixtures never intend platform-dependent line-ending mutation —
    // a checkout inside these tests (e.g. resolving an allowlisted
    // conflict to upstream's content) must not silently smudge LF to
    // CRLF on a Windows runner with a global `core.autocrlf=true`
    // (GitHub's windows-latest default) and desync from what the test
    // literally wrote/asserts.
    git(dir, &["config", "core.autocrlf", "false"]);
    git(dir, &["config", "user.email", "fixture@example.com"]);
    git(dir, &["config", "user.name", "fixture"]);
    std::fs::create_dir_all(dir.join("crates/ex-ray/third_party")).unwrap();
    std::fs::write(
        dir.join("crates/ex-ray/go.mod"),
        "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v1.0.0\n\n\
         replace example.com/widget => ./third_party/widget\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("crates/ex-ray/main.go"),
        "package main\n\nimport _ \"example.com/widget\"\n\nfunc main() {}\n",
    )
    .unwrap();
    std::fs::write(
        dir.join("crates/ex-ray/third_party/VENDORING.md"),
        "# Vendoring\n\n## `widget/` — pinned **v1.0.0** ([upstream](https://example.com))\n",
    )
    .unwrap();
    git(dir, &["add", "-A"]);
    git(dir, &["commit", "-m", "initial"]);

    git(
        dir,
        &[
            "subrepo",
            "clone",
            upstream.to_str().unwrap(),
            "crates/ex-ray/third_party/widget",
            "-b",
            "v1.0.0",
        ],
    );

    if patch_conflicting {
        std::fs::write(
            dir.join("crates/ex-ray/third_party/widget/patched.go"),
            "package widget\n\nfunc Value() int { return 99 } // our local patch\n",
        )
        .unwrap();
        git(dir, &["add", "-A"]);
        git(dir, &["commit", "-m", "patch: local change to patched.go"]);
    }
}

/// Installs a fixture `prek.toml` with an unconditionally-failing
/// `check-vendoring-integrity` hook (much stronger evidence the `SKIP`
/// routing works than the real, currently-clean check would be) alongside a
/// second, always-passing hook — mirroring the real repo's own
/// multi-hook `prek.toml` shape: `prek` errors with "no hooks found after
/// filtering with the given selectors" when `SKIP` filters out literally
/// every hook in the file (confirmed empirically against `prek` 0.3.6),
/// which a single-hook fixture would hit spuriously. Commits this file
/// itself before installing the hook, so that commit isn't hook-guarded.
fn install_always_failing_check_vendoring_integrity_hook(dir: &Path) {
    std::fs::write(
        dir.join("prek.toml"),
        "[[repos]]\n\
         repo = \"local\"\n\
         \n\
         [[repos.hooks]]\n\
         id = \"check-vendoring-integrity\"\n\
         name = \"check vendored deps for conflict markers and version drift\"\n\
         entry = \"bash -c 'exit 1'\"\n\
         language = \"system\"\n\
         pass_filenames = false\n\
         always_run = true\n\
         \n\
         [[repos.hooks]]\n\
         id = \"always-pass\"\n\
         name = \"always pass\"\n\
         entry = \"bash -c 'exit 0'\"\n\
         language = \"system\"\n\
         pass_filenames = false\n\
         always_run = true\n",
    )
    .unwrap();
    git(dir, &["add", "-A"]);
    git(
        dir,
        &[
            "commit",
            "-m",
            "test: install an always-failing check-vendoring-integrity hook",
        ],
    );

    let status = Command::new("prek")
        .args(["install"])
        .current_dir(dir)
        .status()
        .unwrap_or_else(|e| panic!("failed to run `prek install`: {e}"));
    assert!(status.success(), "`prek install` failed");
}

#[skuld::test]
fn always_run_hazard_end_to_end_clean_path() {
    let dir = tempfile::tempdir().unwrap();
    // Long-form path, not `dir.path()` directly: `std::env::temp_dir()` can
    // return an 8.3 short-name component (e.g. `BINDRE~1`) on some Windows
    // machines, which confuses `prek`'s own git-root path comparison
    // ("Workspace root ... is not under git root ...").
    let root = dunce::canonicalize(dir.path()).unwrap();
    let upstream = root.join("upstream");
    let downstream = root.join("downstream");
    build_upstream(&upstream, false);
    build_downstream_with_widget(&downstream, &upstream, false);
    create_passing_v2ray_core_stub(&downstream);
    git(&downstream, &["add", "-A"]);
    git(
        &downstream,
        &["commit", "-m", "test: add v2ray-core stub for identity checks"],
    );

    install_always_failing_check_vendoring_integrity_hook(&downstream);

    let outcome = pull_subrepo::run(&downstream, "crates/ex-ray/third_party/widget", "v1.1.0")
        .expect("pull-subrepo's own intermediate commits must succeed despite the always-failing hook");
    assert!(matches!(outcome, pull_subrepo::Outcome::Clean), "expected a clean pull");

    let identity = finish_vendor_bump::run(&downstream, "crates/ex-ray/third_party/widget", "widget", "v1.1.0")
        .expect("finish-vendor-bump's own commits must succeed despite the always-failing hook");
    assert!(
        matches!(identity, finish_vendor_bump::IdentityCheckOutcome::Passed),
        "expected the minimal fixture to pass identity checks: {identity:?}"
    );

    let gitrepo = std::fs::read_to_string(downstream.join("crates/ex-ray/third_party/widget/.gitrepo")).unwrap();
    assert!(gitrepo.contains("branch = v1.1.0"), "{gitrepo}");
    let vendoring_md = std::fs::read_to_string(downstream.join("crates/ex-ray/third_party/VENDORING.md")).unwrap();
    assert!(vendoring_md.contains("pinned **v1.1.0**"), "{vendoring_md}");
}

#[skuld::test]
fn always_run_hazard_end_to_end_conflicted_path() {
    let dir = tempfile::tempdir().unwrap();
    // Long-form path, not `dir.path()` directly: `std::env::temp_dir()` can
    // return an 8.3 short-name component (e.g. `BINDRE~1`) on some Windows
    // machines, which confuses `prek`'s own git-root path comparison
    // ("Workspace root ... is not under git root ...").
    let root = dunce::canonicalize(dir.path()).unwrap();
    let upstream = root.join("upstream");
    let downstream = root.join("downstream");
    build_upstream(&upstream, true);
    build_downstream_with_widget(&downstream, &upstream, true);
    create_passing_v2ray_core_stub(&downstream);
    git(&downstream, &["add", "-A"]);
    git(
        &downstream,
        &["commit", "-m", "test: add v2ray-core stub for identity checks"],
    );

    install_always_failing_check_vendoring_integrity_hook(&downstream);

    let outcome = pull_subrepo::run(&downstream, "crates/ex-ray/third_party/widget", "v1.1.0")
        .expect("a real conflict is a reported Outcome, not an Err, even with the hook installed");
    assert!(
        matches!(outcome, pull_subrepo::Outcome::Conflicted { .. }),
        "expected a real conflict"
    );

    pull_subrepo::force_commit_conflicted(&downstream, "crates/ex-ray/third_party/widget", "v1.1.0").expect(
        "force_commit_conflicted's and handle_conflict's own finishing commits must succeed despite the \
         always-failing hook",
    );

    let gitrepo = std::fs::read_to_string(downstream.join("crates/ex-ray/third_party/widget/.gitrepo")).unwrap();
    assert!(gitrepo.contains("branch = v1.1.0"), "{gitrepo}");
}
