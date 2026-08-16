//! Shared test fixture infrastructure for `finish_vendor_bump_tests.rs`.
//!
//! Most tests that drive `finish_vendor_bump::run` end-to-end need the same
//! shape: a vendored Go module (`crates/ex-ray/third_party/widget`),
//! `crates/ex-ray`'s own go.mod/main.go requiring + replacing it, and
//! VENDORING.md's version note for it, committed into a fresh git repo.
//! `FixtureBuilder` builds that shape with sensible defaults matching the
//! happy path — override only the fields a given test actually varies.

use std::path::{Path, PathBuf};
use std::process::Command;

pub(crate) struct Fixture {
    pub(crate) dir: tempfile::TempDir,
}

impl Fixture {
    pub(crate) fn root(&self) -> &Path {
        self.dir.path()
    }

    pub(crate) fn ex_ray_dir(&self) -> PathBuf {
        self.root().join("crates/ex-ray")
    }

    pub(crate) fn vendoring_dir(&self) -> PathBuf {
        self.root().join("crates/ex-ray/third_party")
    }
}

struct ExtraDep {
    name: &'static str,
    go_mod: String,
    main_go: String,
}

/// Builds a `Fixture` matching the shape most `finish_vendor_bump` tests
/// need: a single vendored Go module (`widget`) required + replaced by
/// `crates/ex-ray`, imported by its `main.go`, pinned in VENDORING.md at
/// `v1.0.0`.
pub(crate) struct FixtureBuilder {
    dep_go_mod: String,
    dep_main_go: String,
    dep_gitrepo: Option<String>,
    extra_deps: Vec<ExtraDep>,
    vendoring_md: String,
    ex_ray_go_mod: String,
    ex_ray_main_go: String,
    ex_ray_main_test_go: Option<String>,
    ex_ray_go_sum: Option<String>,
    v2ray_core_stub: bool,
}

impl Default for FixtureBuilder {
    fn default() -> Self {
        Self {
            dep_go_mod: "module example.com/widget\n\ngo 1.25\n".to_string(),
            dep_main_go: "package widget\n".to_string(),
            dep_gitrepo: None,
            extra_deps: Vec::new(),
            vendoring_md: "# Vendoring\n\n## `widget/` — pinned **v1.0.0** ([upstream](https://example.com))\n"
                .to_string(),
            ex_ray_go_mod: "module example.com/ex-ray\n\ngo 1.25\n\nrequire example.com/widget v1.0.0\n\n\
                             replace example.com/widget => ./third_party/widget\n"
                .to_string(),
            ex_ray_main_go: "package main\n\nimport _ \"example.com/widget\"\n\nfunc main() {}\n".to_string(),
            ex_ray_main_test_go: None,
            ex_ray_go_sum: None,
            v2ray_core_stub: false,
        }
    }
}

impl FixtureBuilder {
    pub(crate) fn dep_go_mod(mut self, content: impl Into<String>) -> Self {
        self.dep_go_mod = content.into();
        self
    }

    pub(crate) fn dep_gitrepo(mut self, content: impl Into<String>) -> Self {
        self.dep_gitrepo = Some(content.into());
        self
    }

    /// Adds a second vendored module at `crates/ex-ray/third_party/<name>` —
    /// for tests exercising a `require`/`replace` block form with more than
    /// one entry, or a `go mod tidy`-driven MVS conflict between two
    /// vendored deps.
    pub(crate) fn extra_dep(
        mut self,
        name: &'static str,
        go_mod: impl Into<String>,
        main_go: impl Into<String>,
    ) -> Self {
        self.extra_deps.push(ExtraDep {
            name,
            go_mod: go_mod.into(),
            main_go: main_go.into(),
        });
        self
    }

    pub(crate) fn ex_ray_go_mod(mut self, content: impl Into<String>) -> Self {
        self.ex_ray_go_mod = content.into();
        self
    }

    pub(crate) fn ex_ray_main_go(mut self, content: impl Into<String>) -> Self {
        self.ex_ray_main_go = content.into();
        self
    }

    pub(crate) fn ex_ray_main_test_go(mut self, content: impl Into<String>) -> Self {
        self.ex_ray_main_test_go = Some(content.into());
        self
    }

    pub(crate) fn go_sum(mut self, content: impl Into<String>) -> Self {
        self.ex_ray_go_sum = Some(content.into());
        self
    }

    /// Adds a minimal, always-passing `crates/ex-ray/third_party/v2ray-core`
    /// stub — needed by every test driving `run()`/`run_identity_checks`
    /// through to `IdentityCheckOutcome::Passed`, since that scoped check
    /// runs unconditionally regardless of which dep is actually being
    /// bumped (see `finish_vendor_bump::run_identity_checks`'s doc comment).
    pub(crate) fn v2ray_core_stub(mut self) -> Self {
        self.v2ray_core_stub = true;
        self
    }

    pub(crate) fn build(self) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        let ex_ray = root.join("crates/ex-ray");
        let vendoring_dir = root.join("crates/ex-ray/third_party");
        let widget = vendoring_dir.join("widget");

        std::fs::create_dir_all(&widget).unwrap();
        std::fs::create_dir_all(&ex_ray).unwrap();

        std::fs::write(widget.join("go.mod"), &self.dep_go_mod).unwrap();
        std::fs::write(widget.join("main.go"), &self.dep_main_go).unwrap();
        if let Some(gitrepo) = &self.dep_gitrepo {
            std::fs::write(widget.join(".gitrepo"), gitrepo).unwrap();
        }

        for extra in &self.extra_deps {
            let extra_dir = vendoring_dir.join(extra.name);
            std::fs::create_dir_all(&extra_dir).unwrap();
            std::fs::write(extra_dir.join("go.mod"), &extra.go_mod).unwrap();
            std::fs::write(extra_dir.join("main.go"), &extra.main_go).unwrap();
        }

        std::fs::write(vendoring_dir.join("VENDORING.md"), &self.vendoring_md).unwrap();
        std::fs::write(ex_ray.join("go.mod"), &self.ex_ray_go_mod).unwrap();
        std::fs::write(ex_ray.join("main.go"), &self.ex_ray_main_go).unwrap();
        if let Some(main_test_go) = &self.ex_ray_main_test_go {
            std::fs::write(ex_ray.join("main_test.go"), main_test_go).unwrap();
        }
        if let Some(go_sum) = &self.ex_ray_go_sum {
            std::fs::write(ex_ray.join("go.sum"), go_sum).unwrap();
        }

        if self.v2ray_core_stub {
            create_passing_v2ray_core_stub(root);
        }

        git(root, &["init", "--initial-branch=main", "--quiet"]);

        // Fixtures never intend platform-dependent line-ending mutation —

        // a checkout inside these tests (e.g. resolving an allowlisted

        // conflict to upstream's content) must not silently smudge LF to

        // CRLF on a Windows runner with a global `core.autocrlf=true`

        // (GitHub's windows-latest default) and desync from what the test

        // literally wrote/asserts.

        git(root, &["config", "core.autocrlf", "false"]);
        git(root, &["config", "user.email", "fixture@example.com"]);
        git(root, &["config", "user.name", "fixture"]);
        git(root, &["add", "-A"]);
        git(root, &["commit", "-m", "initial"]);

        Fixture { dir }
    }
}

/// `run_identity_checks` unconditionally runs a scoped `go test` inside
/// `crates/ex-ray/third_party/v2ray-core`, regardless of which dep is
/// actually being bumped — so every test driving the full `run()` sequence
/// through to `IdentityCheckOutcome::Passed` needs this minimal,
/// always-passing stub alongside whatever it's actually bumping.
pub(crate) fn create_passing_v2ray_core_stub(dir: &Path) {
    let v2ray_core = dir.join("crates/ex-ray/third_party/v2ray-core");
    std::fs::create_dir_all(&v2ray_core).unwrap();
    std::fs::write(v2ray_core.join("go.mod"), "module example.com/v2ray-core\n\ngo 1.25\n").unwrap();
    for pkg in ["tls", "quic", "hysteria2", "transportcommon"] {
        let pkg_dir = v2ray_core.join("transport/internet").join(pkg);
        std::fs::create_dir_all(&pkg_dir).unwrap();
        std::fs::write(pkg_dir.join(format!("{pkg}.go")), format!("package {pkg}\n")).unwrap();
    }
}

pub(crate) fn git(cwd: &Path, args: &[&str]) {
    let status = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .status()
        .unwrap_or_else(|e| panic!("failed to run git {args:?} in {}: {e}", cwd.display()));
    assert!(status.success(), "git {args:?} failed in {}", cwd.display());
}
