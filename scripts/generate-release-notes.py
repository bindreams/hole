#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = ["PyYAML>=6"]
# ///
"""Generate per-track release notes for Hole's four release tracks.

Reads a per-track config from `.github/release-<track>.yaml`, walks
squash-commits in the range `<previous-track-tag>..<head>`, filters by
the file globs the config declares, categorizes by Conventional Commit
type, and writes markdown to stdout.

Usage:
    uv run scripts/generate-release-notes.py <track> --new-tag <tag>
    uv run scripts/generate-release-notes.py <track> --new-tag <tag> --head <ref>

`<track>` is one of `hole`, `galoshes`, `garter`, `v2ray-plugin`.

The previous tag is auto-discovered as the highest-versioned tag
matching `releases/<track>/v*` that's an ancestor of `<head>` (default
HEAD). If none exists, the config's `initial_release:` body is emitted.

Run from the repo root or pass `--repo-root`.
"""

import argparse
import dataclasses
import fnmatch
import re
import subprocess
import sys
import typing as t
from pathlib import Path

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
    path = repo_root / ".github" / f"release-{track}.yaml"
    with open(path, encoding="utf-8") as f:
        raw = yaml.safe_load(f)
    return TrackConfig(
        initial_release=raw.get("initial_release", "").strip(),
        include_paths=list(raw.get("include_paths", [])),
        categories=[Category(title=c["title"], types=list(c.get("types", []))) for c in raw.get("categories", [])],
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
    """Highest-versioned `releases/<track>/v*` tag that's an ancestor of HEAD."""
    listed = git(repo_root, "tag", "--list", f"releases/{track}/v*")
    tags = [t.strip() for t in listed.splitlines() if t.strip()]

    # Sort key: (major, minor, patch, bare-discriminator, pre-release).
    # The bare-discriminator is 1 for `X.Y.Z` and 0 for `X.Y.Z-pre`; this
    # encodes the semver rule that bare > pre-release at the same M.M.P.
    candidates: list[tuple[tuple[int, int, int, int, str], str]] = []
    for tag in tags:
        m = TAG_VERSION_RE.match(tag)
        if not m:
            continue
        # Verify ancestor-of-head via merge-base --is-ancestor (exit code).
        result = subprocess.run(
            ["git", "merge-base", "--is-ancestor", tag, head],
            cwd=repo_root,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            continue
        major, minor, patch = int(m.group(1)), int(m.group(2)), int(m.group(3))
        pre = m.group(4) or ""
        # Sort key: (major, minor, patch, pre-or-empty). Bare X.Y.Z sorts
        # ABOVE X.Y.Z-hole.N per semver precedence (no pre > with pre).
        # We encode that as: bare → ("",), pre → (pre,). Tuple comparison
        # treats "" as less than any non-empty string, so we invert:
        # use a discriminator (1 for bare, 0 for pre-release).
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


def matches_paths(commit_files: list[str], globs: list[str]) -> bool:
    """True if any commit file matches any glob (fnmatch semantics).

    Globs use `**` for recursive match. We expand `**/` and `/**` by
    rewriting the pattern to fnmatch's equivalent.
    """
    for path in commit_files:
        for g in globs:
            if _fnmatch_recursive(path, g):
                return True
    return False


def _fnmatch_recursive(path: str, glob: str) -> bool:
    # fnmatch doesn't natively support `**`. We rewrite `**` to `*` and
    # rely on fnmatch's `*` matching path separators in fnmatch (it
    # doesn't actually distinguish `/` from other chars, unlike shell
    # glob). So `crates/hole/**` matches `crates/hole/src/main.rs`
    # because the trailing `*` from `**` matches the whole `src/main.rs`.
    # Edge: a glob ending in `/**` should also match the directory
    # itself. We approximate by also matching the trimmed form.
    if glob.endswith("/**"):
        prefix = glob[:-len("/**")]
        return fnmatch.fnmatchcase(path, prefix) or fnmatch.fnmatchcase(path, prefix + "/*") or fnmatch.fnmatchcase(
            path, glob.replace("**", "*")
        )
    normalized = glob.replace("**", "*")
    return fnmatch.fnmatchcase(path, normalized)


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
    previous_tag: str | None,
    repo_url: str,
) -> str:
    parts: list[str] = []

    if previous_tag is None:
        # Caller should have already emitted initial_release stub; this
        # branch is defensive.
        return f"Initial release {new_tag}.\n"

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
    parser.add_argument("track", choices=["hole", "galoshes", "garter", "v2ray-plugin"])
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
    filtered = [c for c in commits if matches_paths(c.files, config.include_paths)]
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
    m = TAG_VERSION_RE.match("releases/v2ray-plugin/v1.3.3-hole.1")
    assert m is not None
    assert m.groups() == ("1", "3", "3", "hole.1")


def test_fnmatch_recursive_basic(tmp_path):
    assert _fnmatch_recursive("crates/hole/src/main.rs", "crates/hole/**")
    assert _fnmatch_recursive("crates/hole/Cargo.toml", "crates/hole/**")
    assert not _fnmatch_recursive("crates/galoshes/src/main.rs", "crates/hole/**")
    assert _fnmatch_recursive(".github/workflows/draft-release-hole.yaml", ".github/workflows/draft-release-hole.yaml")
    assert _fnmatch_recursive("external/v2ray-plugin/main.go", "external/v2ray-plugin/**")


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


def test_matches_paths_globs():
    assert matches_paths(["crates/hole/src/main.rs"], ["crates/hole/**"])
    assert matches_paths(["a", "crates/hole/src/main.rs"], ["crates/hole/**"])
    assert not matches_paths(["crates/galoshes/src/main.rs"], ["crates/hole/**"])
    assert matches_paths(["external/v2ray-plugin/main.go"], ["external/v2ray-plugin/**"])
