#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["PyYAML>=6", "pathspec>=0.12"]
# ///
"""Generate per-track release notes for Hole's four release tracks.

Reads a per-track config from `.github/release-<track>.yaml`, walks
squash-commits in the range `<previous-track-tag>..<head>`, filters by
the file globs the config declares, categorizes by Conventional Commit
type, and writes markdown to stdout.

Usage:
    uv run scripts/generate-release-notes.py <track> --new-tag <tag>
    uv run scripts/generate-release-notes.py <track> --new-tag <tag> --head <ref>

`<track>` is one of `hole`, `galoshes`, `garter`, `ex-ray`.

The previous tag is auto-discovered as the highest-versioned tag
matching `releases/<track>/v*` that's an ancestor of `<head>` (default
HEAD). If none exists, the config's `initial_release:` body is emitted.

Run from the repo root or pass `--repo-root`.

## Include-path glob semantics

Patterns are matched via `pathspec` using gitignore semantics, with one
local convention: a pattern WITHOUT a `/` is anchored to the repo root
(so `Cargo.toml` matches only `./Cargo.toml`, not `./crates/foo/Cargo.toml`).
This preserves intuitive "workspace-Cargo.toml" semantics for bare
filenames. Patterns containing `/` use gitignore as-is, which means `**`
is a first-class recursive wildcard and trailing `/` denotes
directory-only. See `build_path_spec` for the normalization rule.
"""

import argparse
import dataclasses
import re
import subprocess
import sys
from pathlib import Path

import pathspec
import yaml

CONVENTIONAL_COMMIT_RE = re.compile(r"^(?P<type>[a-z]+)(?:\((?P<scope>[^)]+)\))?!?:\s*(?P<desc>.+)$")
PR_NUMBER_RE = re.compile(r"\(#(\d+)\)\s*$")
TAG_VERSION_RE = re.compile(r"^releases/[^/]+/v(\d+)\.(\d+)\.(\d+)(?:-(.+))?$")


@dataclasses.dataclass
class TrackConfig:
    initial_release: str
    include_paths: list[str]
    categories: list["Category"]


@dataclasses.dataclass
class Category:
    title: str
    types: list[str]


@dataclasses.dataclass
class Commit:
    sha: str
    subject: str
    files: list[str]
    pr_number: int | None
    type: str | None
    desc: str


# Loading ==============================================================================================================


def load_config(repo_root: Path, track: str) -> TrackConfig:
    track_path = repo_root / ".github" / f"release-{track}.yaml"
    with open(track_path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)

    # Per-track configs must NOT redeclare categories — the schema lives
    # in the shared file. Reject loudly so a forgotten removal doesn't
    # silently revert to per-track schemas.
    if "categories" in raw:
        raise RuntimeError(
            f"{track_path} declares `categories:` but the shared schema "
            f"lives in .github/release-categories.yaml. Remove the block."
        )

    shared_path = repo_root / ".github" / "release-categories.yaml"
    with open(shared_path, encoding="utf-8") as f:
        shared = yaml.safe_load(f)

    return TrackConfig(
        initial_release=raw.get("initial_release", "").strip(),
        include_paths=list(raw.get("include_paths", [])),
        categories=[Category(title=c["title"], types=list(c.get("types", []))) for c in shared.get("categories", [])],
    )


# Git plumbing =========================================================================================================


def git(repo_root: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed (exit {result.returncode}): {result.stderr.strip()}")
    return result.stdout


def find_previous_tag(repo_root: Path, track: str, head: str) -> str | None:
    """Highest-versioned `releases/<track>/v*` tag that's an ancestor of head.

    Uses a single `git for-each-ref --merged=<head>` to retrieve all
    ancestor tags in one subprocess call. Previously walked all tags
    matching the glob and ran `git merge-base --is-ancestor` per tag.
    """
    listed = git(
        repo_root,
        "for-each-ref",
        f"--merged={head}",
        "--format=%(refname:short)",
        f"refs/tags/releases/{track}/v*",
    )
    tags = [t.strip().removeprefix("refs/tags/") for t in listed.splitlines() if t.strip()]

    # Sort key: (major, minor, patch, bare-discriminator, pre-release).
    # Bare X.Y.Z sorts ABOVE X.Y.Z-hole.N per semver precedence; the
    # discriminator (1 for bare, 0 for pre-release) ensures this.
    candidates: list[tuple[tuple[int, int, int, int, str], str]] = []
    for tag in tags:
        m = TAG_VERSION_RE.match(tag)
        if not m:
            continue
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        pre = m.group(4) or ""
        sort_key = (major, minor, patch, 1 if not pre else 0, pre)
        candidates.append((sort_key, tag))

    if not candidates:
        return None
    candidates.sort(reverse=True)
    return candidates[0][1]


def list_commits(repo_root: Path, range_spec: str) -> list[Commit]:
    """Walk commits in `range_spec` (e.g. `tag..HEAD` or just `HEAD`).

    Returns Commit list ordered newest-first.
    """
    if ".." not in range_spec:
        log_args = ["log", "--no-merges", "--format=%H%x09%s", range_spec]
    else:
        log_args = ["log", "--no-merges", "--format=%H%x09%s", range_spec]
    out = git(repo_root, *log_args)

    commits: list[Commit] = []
    for line in out.splitlines():
        if not line:
            continue
        sha, _, subject = line.partition("\t")
        files = git(repo_root, "show", "--no-renames", "--name-only", "--format=", sha).splitlines()
        files = [f.strip() for f in files if f.strip()]

        pr_match = PR_NUMBER_RE.search(subject)
        pr_number = int(pr_match.group(1)) if pr_match else None

        cc_match = CONVENTIONAL_COMMIT_RE.match(subject)
        commit_type = cc_match.group("type") if cc_match else None
        # Use the full subject (minus PR-number suffix) for display so the
        # type/scope prefix is visible in the rendered bullet.
        desc_display = PR_NUMBER_RE.sub("", subject).strip()

        commits.append(
            Commit(
                sha=sha,
                subject=subject,
                files=files,
                pr_number=pr_number,
                type=commit_type,
                desc=desc_display,
            )
        )
    return commits


# Filtering & categorization ===========================================================================================


def build_path_spec(globs: list[str]) -> pathspec.PathSpec:
    """Compile a list of include-path globs into a PathSpec.

    Local convention: a pattern without `/` (a bare filename like
    `Cargo.toml`) is anchored to the repo root before being handed to
    pathspec. This preserves "workspace-Cargo.toml means root only"
    semantics — without it, gitignore would match the filename at any
    depth and a `crates/galoshes/Cargo.toml` change would surface in
    the hole-track release notes via the hole-track's bare-pattern
    include for the workspace Cargo.toml.

    Patterns containing `/` are passed through unchanged — gitignore
    semantics (with `**` recursion, trailing-`/` directory-only) apply.
    """
    normalized = ["/" + g if "/" not in g.rstrip("/") else g for g in globs]
    return pathspec.PathSpec.from_lines("gitignore", normalized)


def categorize(commits: list[Commit], categories: list[Category]) -> dict[str, list[Commit]]:
    """Place each commit under the first category whose `types` list
    contains the commit's type. Commits with no type, or whose type
    matches no listed category, fall into the catch-all category
    (whose `types` is `[]`) if one exists; otherwise they're dropped.

    Returns dict keyed by category title preserving the config's order.
    """
    out: dict[str, list[Commit]] = {c.title: [] for c in categories}
    catchall_title = next((c.title for c in categories if not c.types), None)

    for commit in commits:
        placed = False
        for cat in categories:
            if commit.type and commit.type in cat.types:
                out[cat.title].append(commit)
                placed = True
                break
        if not placed and catchall_title is not None:
            out[catchall_title].append(commit)

    return out


# Rendering ============================================================================================================


def render_bullet(commit: Commit) -> str:
    """Render a single commit as a bullet line."""
    line = commit.desc
    if commit.pr_number is not None:
        line += f" (#{commit.pr_number})"
    return f"- {line}"


def render_notes(
    grouped: dict[str, list[Commit]],
    new_tag: str,
    previous_tag: str,
    repo_url: str,
) -> str:
    # `main` handles the first-of-track case (previous_tag is None) and
    # returns before calling this, so `previous_tag` is always a real tag here.
    parts: list[str] = []

    # Non-empty category list rendered as `## <title>` followed by bullets.
    has_any = any(commits for commits in grouped.values())
    if not has_any:
        parts.append(
            f"_No commits in this range touched files in this track. "
            f"(Range: `{previous_tag}` → `{new_tag}`.)_"
        )
    else:
        for title, commits in grouped.items():
            if not commits:
                continue
            parts.append(f"## {title}")
            for commit in commits:
                parts.append(render_bullet(commit))
            parts.append("")  # blank line between sections

    parts.append(f"**Full Changelog**: {repo_url}/compare/{previous_tag}...{new_tag}")
    return "\n".join(parts).rstrip() + "\n"


# Entry point ==========================================================================================================


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("track", choices=["hole", "galoshes", "garter", "ex-ray"])
    parser.add_argument("--new-tag", required=True, help="Tag being released (e.g. releases/hole/v0.2.0)")
    parser.add_argument("--head", default="HEAD", help="Git ref representing the new release commit (default: HEAD)")
    parser.add_argument(
        "--repo-root",
        type=Path,
        default=None,
        help="Path to repo root (default: discovered via `git rev-parse --show-toplevel`)",
    )
    parser.add_argument(
        "--repo-url",
        default="https://github.com/bindreams/hole",
        help="Repository URL for `Full Changelog` link",
    )
    args = parser.parse_args()

    repo_root = args.repo_root
    if repo_root is None:
        repo_root = Path(
            subprocess.run(
                ["git", "rev-parse", "--show-toplevel"],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.strip()
        )

    config = load_config(repo_root, args.track)
    previous_tag = find_previous_tag(repo_root, args.track, args.head)

    if previous_tag is None:
        # First-of-track release: emit the configured stub instead of
        # walking history. Avoids the "every PR ever merged" problem.
        body = config.initial_release or f"Initial release of the `{args.track}` track."
        sys.stdout.write(body.rstrip() + "\n")
        return 0

    range_spec = f"{previous_tag}..{args.head}"
    commits = list_commits(repo_root, range_spec)
    path_spec = build_path_spec(config.include_paths)
    filtered = [c for c in commits if any(path_spec.match_file(f) for f in c.files)]
    grouped = categorize(filtered, config.categories)
    body = render_notes(grouped, new_tag=args.new_tag, previous_tag=previous_tag, repo_url=args.repo_url)
    sys.stdout.write(body)
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Tests (pytest) =======================================================================================================


def test_conventional_commit_re_matches_type() -> None:
    m = CONVENTIONAL_COMMIT_RE.match("feat(bridge): add DoH support")
    assert m is not None
    assert m.group("type") == "feat"
    assert m.group("scope") == "bridge"
    assert m.group("desc") == "add DoH support"


def test_conventional_commit_re_matches_no_scope() -> None:
    m = CONVENTIONAL_COMMIT_RE.match("fix: protocol-aware port allocation")
    assert m is not None
    assert m.group("type") == "fix"
    assert m.group("scope") is None


def test_conventional_commit_re_rejects_non_conventional() -> None:
    assert CONVENTIONAL_COMMIT_RE.match("Just some description") is None


def test_conventional_commit_re_accepts_breaking_marker() -> None:
    m = CONVENTIONAL_COMMIT_RE.match("feat(api)!: rename endpoint")
    assert m is not None
    assert m.group("type") == "feat"


def test_pr_number_extraction():
    # PR_NUMBER_RE is anchored at end-of-string (`(#\d+)\s*$`), so only the
    # last parenthesized PR ref is captured even when multiple appear.
    m = PR_NUMBER_RE.search("foo bar (#123)")
    assert m is not None
    assert m.group(1) == "123"
    assert PR_NUMBER_RE.search("no number here") is None
    m = PR_NUMBER_RE.search("revert PR (#1) for cause (#2)")
    assert m is not None
    assert m.group(1) == "2"


def test_tag_version_re():
    m = TAG_VERSION_RE.match("releases/hole/v1.2.3")
    assert m is not None
    assert m.groups() == ("1", "2", "3", None)
    m = TAG_VERSION_RE.match("releases/ex-ray/v0.1.0")
    assert m is not None
    assert m.groups() == ("0", "1", "0", None)


def test_path_spec_basic():
    spec = build_path_spec([
        "crates/hole/**",
        ".github/workflows/draft-release-hole.yaml",
        "crates/ex-ray/**",
    ])
    assert spec.match_file("crates/hole/src/main.rs")
    assert spec.match_file("crates/hole/Cargo.toml")
    assert not spec.match_file("crates/galoshes/src/main.rs")
    assert spec.match_file(".github/workflows/draft-release-hole.yaml")
    assert spec.match_file("crates/ex-ray/main.go")


def test_path_spec_workspace_engineering_patterns():
    """Lock in the post-pathspec-migration behavior for the include-path
    patterns actually used by `release-*.yaml` configs.

    The critical case is bare filenames (e.g. `Cargo.toml`): without
    `build_path_spec`'s root-anchoring normalization, gitignore would
    match such patterns at any depth, and a `crates/galoshes/Cargo.toml`
    change would leak into the hole-track release notes.
    """
    spec = build_path_spec([
        "crates/hole/**",
        "crates/common/**",
        "crates/ex-ray/**",
        ".github/workflows/draft-release-hole.yaml",
        "Cargo.toml",
        "Cargo.lock",
        "xtask/**",
        "xtask-lib/**",
        "scripts/generate-release-notes.py",
        "build.yaml",
        "prek.toml",
        "clippy.toml",
    ])
    cases = [
        ("crates/hole/src/main.rs", True),
        ("crates/hole/Cargo.toml", True),
        ("crates/galoshes/src/main.rs", False),
        ("crates/ex-ray/main.go", True),
        ("crates/ex-ray/sub/dir/file.go", True),
        (".github/workflows/draft-release-hole.yaml", True),
        (".github/workflows/draft-release-galoshes.yaml", False),
        ("Cargo.toml", True),
        ("Cargo.lock", True),
        ("xtask/src/lib.rs", True),
        ("xtask-lib/src/version.rs", True),
        ("scripts/generate-release-notes.py", True),
        ("scripts/sign-release.py", False),
        ("scripts/dev.py", False),
        ("prek.toml", True),
        ("clippy.toml", True),
        ("README.md", False),
        # Anchoring: bare filenames match ONLY at the repo root, not at
        # arbitrary depth. Without normalization these would all be True
        # under raw gitignore — the boy-scout fix for the migration bug.
        ("crates/galoshes/Cargo.toml", False),
        ("crates/garter/Cargo.toml", False),
        ("crates/mock-plugin/Cargo.toml", False),
        ("crates/galoshes/prek.toml", False),
        # crates/ex-ray/go.mod IS matched, but via the
        # `crates/ex-ray/**` pattern (not via root-anchored `Cargo.toml`).
        ("crates/ex-ray/go.mod", True),
    ]
    for path, expected in cases:
        assert spec.match_file(path) == expected, f"path={path!r} expected={expected}"


def test_path_spec_root_anchors_bare_filenames():
    """Standalone regression test for build_path_spec's anchoring rule.
    A pattern WITHOUT `/` is treated as a root-only filename match."""
    spec = build_path_spec(["Cargo.toml"])
    assert spec.match_file("Cargo.toml")
    assert not spec.match_file("crates/foo/Cargo.toml")
    assert not spec.match_file("a/b/Cargo.toml")

    # Patterns WITH `/` use raw gitignore semantics — recursive globs.
    spec2 = build_path_spec(["crates/**"])
    assert spec2.match_file("crates/foo/bar.rs")
    assert not spec2.match_file("xtask/foo.rs")


def test_categorize_first_match_wins():
    cats = [
        Category("Features", ["feat"]),
        Category("Fixes", ["fix"]),
        Category("Other", []),
    ]
    commits = [
        Commit(sha="a", subject="feat: x", files=[], pr_number=None, type="feat", desc="feat: x"),
        Commit(sha="b", subject="fix: y", files=[], pr_number=None, type="fix", desc="fix: y"),
        Commit(sha="c", subject="something", files=[], pr_number=None, type=None, desc="something"),
    ]
    grouped = categorize(commits, cats)
    assert [c.sha for c in grouped["Features"]] == ["a"]
    assert [c.sha for c in grouped["Fixes"]] == ["b"]
    assert [c.sha for c in grouped["Other"]] == ["c"]


def test_categorize_no_catchall_drops_uncategorized():
    cats = [Category("Features", ["feat"])]
    commits = [Commit(sha="a", subject="?", files=[], pr_number=None, type=None, desc="?")]
    grouped = categorize(commits, cats)
    assert grouped == {"Features": []}


def test_integration_filtering_against_real_history():
    """End-to-end: run the script as a subprocess against real repo
    history and assert include-path filtering works.

    The negative-assertion probe is range-constrained to the SAME range
    the script walks (previous-ex-ray-tag..HEAD), so a "hole-only"
    commit outside that range doesn't make the probe vacuously pass.

    Per CLAUDE.md "Tests must never silently skip on missing dependencies":
    `uv` and tags are both CI-provisioned, so absence fails loudly.
    """
    import shutil
    import pytest
    if shutil.which("uv") is None:
        pytest.fail("uv not on PATH; CI must provision it (CLAUDE.md coding-style rule).")
    repo_root = Path(__file__).resolve().parent.parent
    prev_tag = find_previous_tag(repo_root, "ex-ray", "HEAD")
    if prev_tag is None:
        pytest.fail(
            "No releases/ex-ray/v* ancestor of HEAD; CI must "
            "fetch tags (fetch-depth: 0 or `git fetch --tags`)."
        )

    script = repo_root / "scripts" / "generate-release-notes.py"
    result = subprocess.run(
        ["uv", "run", str(script), "ex-ray", "--new-tag", "releases/ex-ray/v999.0.0", "--head", "HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    )
    out = result.stdout
    assert out.strip(), "Empty output"
    assert "## " in out or "_No commits in this range" in out, f"Unexpected shape: {out[:200]}"
    assert "**Full Changelog**:" in out, f"Missing Full Changelog link: {out[-200:]}"

    # Negative assertion: a commit that touches ONLY hole-track paths
    # within the same range must NOT appear in ex-ray notes.
    # Iterate recent commits in range, find one whose every file matches
    # hole's include_paths but no ex-ray include_paths.
    hole_spec = build_path_spec(load_config(repo_root, "hole").include_paths)
    ex_ray_spec = build_path_spec(load_config(repo_root, "ex-ray").include_paths)
    all_commits = subprocess.run(
        ["git", "log", "--format=%H", "--no-merges", f"{prev_tag}..HEAD"],
        cwd=repo_root,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    for sha in all_commits:
        files = subprocess.run(
            ["git", "show", "--no-renames", "--name-only", "--format=", sha],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.splitlines()
        files = [f for f in files if f.strip()]
        if not files:
            continue
        hole_only = all(hole_spec.match_file(f) and not ex_ray_spec.match_file(f) for f in files)
        if not hole_only:
            continue
        subject = subprocess.run(
            ["git", "log", "--format=%s", "-1", sha],
            cwd=repo_root,
            capture_output=True,
            text=True,
            check=True,
        ).stdout.strip()
        m = re.search(r"\(#(\d+)\)\s*$", subject)
        if not m:
            continue
        pr_num = m.group(1)
        assert not re.search(rf"#{pr_num}\b", out), (
            f"ex-ray notes contain hole-only PR #{pr_num} ({sha[:8]}); "
            f"include-path filtering may be broken. Subject: {subject}"
        )
        return
    # No qualifying hole-only commit in range. Common; not a failure.


def test_shared_categories_file_loaded():
    """load_config returns categories from the shared file for every track."""
    repo_root = Path(__file__).resolve().parent.parent
    shared = yaml.safe_load((repo_root / ".github" / "release-categories.yaml").read_text())
    expected_titles = [c["title"] for c in shared["categories"]]
    for track in ["hole", "galoshes", "garter", "ex-ray"]:
        config = load_config(repo_root, track)
        assert [c.title
                for c in config.categories] == expected_titles, (f"Track {track} categories don't match shared file")


def test_per_track_configs_dont_duplicate_categories():
    """Per-track files must not redeclare categories (single source of truth)."""
    repo_root = Path(__file__).resolve().parent.parent
    for track in ["hole", "galoshes", "garter", "ex-ray"]:
        raw = yaml.safe_load((repo_root / ".github" / f"release-{track}.yaml").read_text())
        assert "categories" not in raw, (
            f"release-{track}.yaml must not declare `categories:`; "
            f"shared schema lives in .github/release-categories.yaml"
        )


def test_categories_cover_all_semantic_pr_types():
    """Every type in semantic-pr.yaml is reachable by the categorizer:
    either in an explicit category, or via the "Other" catch-all
    (category with empty types list).

    A catch-all category is an acceptable runtime fallback. This test
    enforces that if the "Other" catch-all is removed, every semantic-pr
    type must have an explicit category.
    """
    repo_root = Path(__file__).resolve().parent.parent
    semantic = yaml.safe_load((repo_root / ".github/workflows/semantic-pr.yaml").read_text())
    types_block = semantic["jobs"]["validate"]["steps"][0]["with"]["types"]
    declared_types = {t.strip() for t in types_block.splitlines() if t.strip()}

    shared = yaml.safe_load((repo_root / ".github" / "release-categories.yaml").read_text())
    explicit_types = {t for cat in shared["categories"] for t in cat.get("types", [])}
    has_catchall = any(not cat.get("types") for cat in shared["categories"])

    if has_catchall:
        return  # catch-all absorbs any uncovered type; invariant holds
    missing = declared_types - explicit_types
    assert not missing, (
        f"No catch-all category exists and these types from semantic-pr.yaml "
        f"have no explicit category: {sorted(missing)}. Either add them to "
        f"an explicit category or re-add the 'Other' catch-all."
    )


def _init_test_repo(tmp_path):
    """Create a minimal git repo with controlled tag/branch history for testing."""
    subprocess.run(["git", "init", "-q", "-b", "main", str(tmp_path)], check=True)
    subprocess.run(["git", "config", "user.email", "t@t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=tmp_path, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=tmp_path, check=True)
    return tmp_path


def _commit(repo: Path, message: str) -> str:
    (repo / "f").write_text(message)
    subprocess.run(["git", "add", "f"], cwd=repo, check=True)
    subprocess.run(["git", "commit", "-q", "-m", message], cwd=repo, check=True)
    return subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()


def test_find_previous_tag_no_tags(tmp_path):
    repo = _init_test_repo(tmp_path)
    _commit(repo, "c1")
    assert find_previous_tag(repo, "hole", "HEAD") is None


def test_find_previous_tag_one_tag(tmp_path):
    repo = _init_test_repo(tmp_path)
    _commit(repo, "c1")
    subprocess.run(["git", "tag", "releases/hole/v1.0.0"], cwd=repo, check=True)
    _commit(repo, "c2")
    assert find_previous_tag(repo, "hole", "HEAD") == "releases/hole/v1.0.0"


def test_find_previous_tag_picks_highest_ancestor(tmp_path):
    repo = _init_test_repo(tmp_path)
    _commit(repo, "c1")
    subprocess.run(["git", "tag", "releases/hole/v1.0.0"], cwd=repo, check=True)
    _commit(repo, "c2")
    subprocess.run(["git", "tag", "releases/hole/v1.1.0"], cwd=repo, check=True)
    _commit(repo, "c3")
    subprocess.run(["git", "tag", "releases/hole/v2.0.0"], cwd=repo, check=True)
    _commit(repo, "c4")
    assert find_previous_tag(repo, "hole", "HEAD") == "releases/hole/v2.0.0"


def test_find_previous_tag_ignores_non_ancestor(tmp_path):
    repo = _init_test_repo(tmp_path)
    c1 = _commit(repo, "c1")
    subprocess.run(["git", "checkout", "-q", "-b", "side"], cwd=repo, check=True)
    _commit(repo, "side1")
    subprocess.run(["git", "tag", "releases/hole/v9.9.9"], cwd=repo, check=True)
    subprocess.run(["git", "checkout", "-q", "main"], cwd=repo, check=True)
    subprocess.run(["git", "tag", "releases/hole/v1.0.0", c1], cwd=repo, check=True)
    _commit(repo, "c2")
    # HEAD on main shouldn't see side branch's v9.9.9
    assert find_previous_tag(repo, "hole", "HEAD") == "releases/hole/v1.0.0"


def test_find_previous_tag_bare_beats_prerelease(tmp_path):
    """Per semver: 1.3.3 > 1.3.3-rc.1. Tests the sorting logic for any track
    that might have pre-release tags (TAG_VERSION_RE supports arbitrary pre-release
    suffixes for forward-compatibility)."""
    repo = _init_test_repo(tmp_path)
    _commit(repo, "c1")
    subprocess.run(["git", "tag", "releases/ex-ray/v1.3.3-rc.1"], cwd=repo, check=True)
    _commit(repo, "c2")
    subprocess.run(["git", "tag", "releases/ex-ray/v1.3.3"], cwd=repo, check=True)
    _commit(repo, "c3")
    assert find_previous_tag(repo, "ex-ray", "HEAD") == "releases/ex-ray/v1.3.3"


def test_find_previous_tag_higher_prerelease_iteration(tmp_path):
    """Lexical sort puts rc.2 > rc.1 (and would put rc.10 < rc.2 — fragility noted)."""
    repo = _init_test_repo(tmp_path)
    _commit(repo, "c1")
    subprocess.run(["git", "tag", "releases/ex-ray/v1.3.3-rc.1"], cwd=repo, check=True)
    _commit(repo, "c2")
    subprocess.run(["git", "tag", "releases/ex-ray/v1.3.3-rc.2"], cwd=repo, check=True)
    _commit(repo, "c3")
    assert find_previous_tag(repo, "ex-ray", "HEAD") == "releases/ex-ray/v1.3.3-rc.2"


def test_find_previous_tag_skips_malformed_tags(tmp_path):
    repo = _init_test_repo(tmp_path)
    _commit(repo, "c1")
    # Malformed tags matching the glob — should be silently skipped.
    subprocess.run(["git", "tag", "releases/hole/v1"], cwd=repo, check=True)
    subprocess.run(["git", "tag", "releases/hole/vmalformed"], cwd=repo, check=True)
    subprocess.run(["git", "tag", "releases/hole/v1.0.0"], cwd=repo, check=True)
    _commit(repo, "c2")
    assert find_previous_tag(repo, "hole", "HEAD") == "releases/hole/v1.0.0"
