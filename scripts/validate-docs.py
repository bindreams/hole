#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# ///
"""Build the documentation site and check what the build cannot.

Builds `docs/` with warnings promoted to errors, then verifies the landing page's
versions line carries the real manifest versions and that no substitution was
left unrendered. Also checks every `{src}` link in `docs/`: its path must be
tracked in the repository and, for a Markdown target, its `#anchor` must match a
heading there (GitHub's slug rules). Every README link that starts with
`https://hole.readthedocs.io/en/latest/` must be the site root or `<page>.html`,
where `docs/<page>.md` is tracked in the repository.

Usage:
    uv run scripts/validate-docs.py
    uv run scripts/validate-docs.py --fetch-only
    uv run scripts/validate-docs.py --links-only

`--fetch-only` resolves and downloads the build's tools and builds nothing, so CI
can run the fetch under a retry without retrying a docs failure. `--links-only`
runs the `{src}` and README link checks without the build: those read files
anywhere in the repository, so the pre-commit hook for them runs on every commit.
"""

import re
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "docs"))
from _versions import SUBSTITUTIONS, manifest_versions  # noqa: E402

# Must match the versions line in docs/index.md byte-for-byte once formatted.
VERSIONS_LINE = (
    "Component versions: hole {hole_version}, galoshes {galoshes_version}, "
    "garter {garter_version}, ex-ray {exray_version}."
)

# Only this project's own substitutions. A general `{{` match fails a correct
# build: a page documenting `${{ github.ref }}` emits it verbatim.
SUBSTITUTION_RE = re.compile(r"\{\{\s*(?:" + "|".join(SUBSTITUTIONS) + r")\s*\}\}")

# Code samples may show the substitution syntax on purpose.
CODE_REGION_RE = re.compile(r"<(pre|code)\b[^>]*>.*?</\1>", re.DOTALL | re.IGNORECASE)

# A `{src}` role: {src}`path`, {src}`path#anchor` or {src}`title <path#anchor>`.
SRC_ROLE_RE = re.compile(r"\{src\}`([^`]+)`")
SRC_TITLED_RE = re.compile(r"^.*?<([^<>]+)>$", re.DOTALL)

# A README link into the published site: the page path after `/en/latest/`, if any.
SITE_LINK_RE = re.compile(r"https://hole\.readthedocs\.io/en/latest/([^\s)#>]*)")

HEADING_RE = re.compile(r"^ {0,3}#{1,6}[ \t]+(.*?)[ \t]*$")
FENCE_RE = re.compile(r"^ {0,3}(`{3,}|~{3,})[ \t]*(.*?)[ \t]*$")

# Sphinx writes these itself; their contents are not ours to check.
GENERATED_PAGES = frozenset({"search.html", "genindex.html"})


def unrendered_substitutions(html: str) -> list[str]:
    """This project's own substitutions left literal in one page, in order."""
    return SUBSTITUTION_RE.findall(CODE_REGION_RE.sub("", html))


def check_rendered(out_dir: Path, versions: dict[str, str]) -> list[str]:
    """Problems found in a built HTML tree. Empty means the output is good."""
    index = out_dir / "index.html"
    if not index.is_file():
        return [f"{index}: missing -- the build produced no landing page"]

    problems = []
    expected = VERSIONS_LINE.format(**versions)
    if expected not in index.read_text(encoding="utf-8"):
        problems.append(f"{index}: versions line missing or stale, expected: {expected}")

    for page in sorted(out_dir.rglob("*.html")):
        if page.name in GENERATED_PAGES:
            continue
        for literal in unrendered_substitutions(page.read_text(encoding="utf-8")):
            problems.append(f"{page}: substitution left unrendered: {literal}")
    return problems


def outside_fences(text: str) -> Iterator[tuple[int, str]]:
    """Yield `(line number, line)` for each line of Markdown outside a code block.

    A fence whose info string opens with `{` is a MyST directive, not code: its
    body is Markdown (a `{glossary}` holds the page's `{src}` links) and is yielded.
    """
    open_fences: list[tuple[str, int, bool]] = []  # (fence char, fence length, is code)
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if match and open_fences:
            char, length, _ = open_fences[-1]
            if match.group(1)[0] == char and len(match.group(1)) >= length and not match.group(2):
                open_fences.pop()
                continue
        if match and not (open_fences and open_fences[-1][2]):
            fence = match.group(1)
            open_fences.append((fence[0], len(fence), not match.group(2).startswith("{")))
            continue
        if not any(is_code for _, _, is_code in open_fences):
            yield number, line


def heading_slugs(markdown: str) -> set[str]:
    """The anchors GitHub generates for the headings of one Markdown file.

    Lowercase, punctuation other than `-` and `_` dropped, spaces to `-`; a
    repeated heading gets `-1`, `-2`, ... appended.
    """
    slugs: set[str] = set()
    seen: dict[str, int] = {}
    for _, line in outside_fences(markdown):
        heading = HEADING_RE.match(line)
        if not heading:
            continue
        text = re.sub(r"[ \t]+#+$", "", heading.group(1))
        text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)  # a link contributes its text
        slug = re.sub(r"[^\w\- ]", "", text.lower()).replace(" ", "-")
        count = seen.get(slug, 0)
        seen[slug] = count + 1
        slugs.add(slug if count == 0 else f"{slug}-{count}")
    return slugs


def src_link_problems(repo_root: Path, tracked: frozenset[str]) -> list[str]:
    """Problems with the `{src}` links of every page under `docs/`.

    `tracked` holds the repository's file paths, `/`-separated. A target names a
    tracked file or a directory holding one; a `.md` target's `#anchor` must be
    a heading slug of that file.
    """
    problems = []
    for page in sorted((repo_root / "docs").rglob("*.md")):
        where = page.relative_to(repo_root).as_posix()
        for number, line in outside_fences(page.read_text(encoding="utf-8")):
            for role in SRC_ROLE_RE.finditer(line):
                titled = SRC_TITLED_RE.match(role.group(1))
                target = titled.group(1) if titled else role.group(1)
                path, _, anchor = target.strip().partition("#")
                is_dir = any(name.startswith(path.rstrip("/") + "/") for name in tracked)
                if path not in tracked and not is_dir:
                    problems.append(f"{where}:{number}: {{src}} path is not tracked in the repository: {path}")
                elif anchor and path.endswith(".md") and path in tracked:
                    headings = heading_slugs((repo_root / path).read_text(encoding="utf-8"))
                    if anchor not in headings:
                        problems.append(f"{where}:{number}: {{src}} anchor matches no heading in {path}: #{anchor}")
    return problems


def readme_link_problems(repo_root: Path, tracked: frozenset[str]) -> list[str]:
    """Problems with the README's links into the published site.

    `<page>.html` must have a tracked `docs/<page>.md` source; the bare site root
    maps to `docs/index.md`. Any other link under the site's base is a problem.
    """
    problems = []
    readme = (repo_root / "README.md").read_text(encoding="utf-8")
    for number, line in enumerate(readme.splitlines(), start=1):
        for link in SITE_LINK_RE.finditer(line):
            page = link.group(1)
            if page.endswith(".html"):
                source = f"docs/{page.removesuffix('.html')}.md"
            elif page == "":
                source = "docs/index.md"
            else:
                problems.append(f"README.md:{number}: site link is not a page or the site root: {link.group(0)}")
                continue
            if source not in tracked:
                problems.append(
                    f"README.md:{number}: site link's page source {source} is not tracked in the repository: {link.group(0)}"
                )
    return problems


def tracked_files() -> frozenset[str]:
    """Paths of the files in the git index (staged files included)."""
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, check=True, capture_output=True, text=True, encoding="utf-8"
    )
    return frozenset(listing.stdout.split("\0")) - {""}


def sphinx_command(*sphinx_args: str) -> list[str]:
    """The `uv run` invocation of `sphinx-build` with the pinned docs requirements.

    Every caller shares the exact `uv` flags: the environment a fetch-only call
    resolves is the one the build then reuses from uv's cache.
    """
    return [
        "uv",
        "run",
        "--no-project",
        "--python",
        "3.13",
        "--with-requirements",
        str(REPO_ROOT / "docs" / "requirements.txt"),
        "--",
        "sphinx-build",
        *sphinx_args,
    ]


def main() -> int:
    if sys.argv[1:] not in ([], ["--fetch-only"], ["--links-only"]):
        print(f"usage: {Path(sys.argv[0]).name} [--fetch-only | --links-only]", file=sys.stderr)
        return 2

    if sys.argv[1:] == ["--fetch-only"]:
        return subprocess.run(sphinx_command("--version"), cwd=REPO_ROOT).returncode

    tracked = tracked_files()
    problems = src_link_problems(REPO_ROOT, tracked) + readme_link_problems(REPO_ROOT, tracked)
    if sys.argv[1:] == ["--links-only"]:
        for problem in problems:
            print(problem, file=sys.stderr)
        return 1 if problems else 0

    # A fresh output directory every run. Reusing one lets Sphinx build
    # incrementally -- it skips re-reading unchanged pages, so a broken
    # cross-reference passes here while a cold Read the Docs build fails -- and
    # leaves deleted pages behind for check_rendered to trip over.
    with tempfile.TemporaryDirectory(prefix="hole-docs-") as out:
        out_dir = Path(out)
        # Sphinx is pinned in docs/requirements.txt alone, so it stays out of
        # this script's own dependencies. Output is inherited: capturing it
        # would silence the warnings this script exists to surface.
        build = subprocess.run(
            sphinx_command("-W", "-b", "html", str(REPO_ROOT / "docs"), str(out_dir)),
            cwd=REPO_ROOT,
        )
        if build.returncode != 0:
            print("\n".join(problems), file=sys.stderr)
            return build.returncode

        problems += check_rendered(out_dir, manifest_versions(REPO_ROOT))

    for problem in problems:
        print(problem, file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())

# Tests (pytest) =======================================================================================================


def test_manifest_versions_reads_all_four_manifests() -> None:
    versions = manifest_versions(REPO_ROOT)

    assert set(versions) == set(SUBSTITUTIONS)
    for name, version in versions.items():
        assert isinstance(version, str), f"{name} is {type(version)}, not str"
        assert version, f"{name} is empty"


def test_manifest_versions_raises_on_missing_manifest(tmp_path: Path) -> None:
    import pytest

    with pytest.raises(FileNotFoundError):
        manifest_versions(tmp_path)


def test_unrendered_substitutions_finds_literal() -> None:
    assert unrendered_substitutions("<p>{{ hole_version }}</p>") == ["{{ hole_version }}"]


def test_unrendered_substitutions_preserves_order() -> None:
    html = "<p>{{ garter_version }} then {{ hole_version }}</p>"

    assert unrendered_substitutions(html) == ["{{ garter_version }}", "{{ hole_version }}"]


def test_unrendered_substitutions_ignores_foreign_templates() -> None:
    html = "<p>run: echo ${{ github.ref }} on ${{ matrix.os }}</p>"

    assert unrendered_substitutions(html) == []


def test_unrendered_substitutions_ignores_code_blocks() -> None:
    """A page may legitimately document the substitution syntax."""
    html = "<p>Write <code>{{ hole_version }}</code> like:</p><pre>Hole {{ hole_version }} is out.</pre>"

    assert unrendered_substitutions(html) == []


def test_check_rendered_reports_a_secondary_page(tmp_path: Path) -> None:
    versions = dict.fromkeys(SUBSTITUTIONS, "1.2.3")
    (tmp_path / "index.html").write_text(f"<p>{VERSIONS_LINE.format(**versions)}</p>", encoding="utf-8")
    (tmp_path / "license.html").write_text("<p>{{ hole_version }}</p>", encoding="utf-8")

    problems = check_rendered(tmp_path, versions)

    assert len(problems) == 1
    assert "license.html" in problems[0]


def test_check_rendered_skips_sphinx_generated_pages(tmp_path: Path) -> None:
    """search.html and genindex.html are Sphinx's, not ours to police."""
    versions = dict.fromkeys(SUBSTITUTIONS, "1.2.3")
    (tmp_path / "index.html").write_text(f"<p>{VERSIONS_LINE.format(**versions)}</p>", encoding="utf-8")
    (tmp_path / "search.html").write_text("<p>{{ hole_version }}</p>", encoding="utf-8")

    assert check_rendered(tmp_path, versions) == []


def test_check_rendered_accepts_good_output(tmp_path: Path) -> None:
    versions = dict.fromkeys(SUBSTITUTIONS, "1.2.3")
    (tmp_path / "index.html").write_text(f"<p>{VERSIONS_LINE.format(**versions)}</p>", encoding="utf-8")

    assert check_rendered(tmp_path, versions) == []


def test_check_rendered_rejects_missing_versions_line(tmp_path: Path) -> None:
    """The case a bare version-substring search cannot catch.

    furo renders `html_title` -- which carries the hole version -- on every page,
    so the version strings are present even with the versions line deleted.
    """
    versions = dict.fromkeys(SUBSTITUTIONS, "1.2.3")
    (tmp_path / "index.html").write_text("<title>Hole 1.2.3</title>", encoding="utf-8")

    problems = check_rendered(tmp_path, versions)

    assert len(problems) == 1
    assert "index.html" in problems[0]


def test_sphinx_command_appends_args_after_the_pinned_requirements() -> None:
    command = sphinx_command("--version")

    assert command[:2] == ["uv", "run"]
    requirements = command[command.index("--with-requirements") + 1]
    assert Path(requirements) == REPO_ROOT / "docs" / "requirements.txt"
    assert command[-2:] == ["sphinx-build", "--version"]
    # The fetch and the build resolve the same environment only with the same flags.
    assert sphinx_command("-W", "-b", "html")[: len(command) - 1] == command[:-1]


def _write_repo(root: Path, files: dict[str, str]) -> frozenset[str]:
    """Write `files` under `root`; return the non-docs ones as the tracked set."""
    _write_files(root, files)
    return frozenset(name for name in files if not name.startswith("docs/"))


def _write_files(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")


def test_heading_slugs_follow_github_rules() -> None:
    markdown = "# CLI (dev/admin commands)\n## Lockdown mode\n## Lockdown mode\n## [Link](#x) `code_x` & more\n"

    assert heading_slugs(markdown) == {"cli-devadmin-commands", "lockdown-mode", "lockdown-mode-1", "link-code_x--more"}


def test_heading_slugs_ignore_fenced_code() -> None:
    assert heading_slugs("```sh\n# a comment\n```\n# Real\n") == {"real"}


def test_src_links_accept_files_directories_and_anchors(tmp_path: Path) -> None:
    page = "{src}`x/y.rs` {src}`dir` {src}`T <T.md#some-heading>` {src}`x/y.rs#L10`\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page, "x/y.rs": "", "dir/f": "", "T.md": "## Some heading\n"})

    assert src_link_problems(tmp_path, tracked) == []


def test_src_links_report_a_missing_path_and_a_wrong_anchor(tmp_path: Path) -> None:
    page = "{src}`nope.rs`\n{src}`T <T.md#other>`\n```\n{src}`ignored.rs`\n```\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page, "T.md": "## Some heading\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 2
    assert "a.md:1" in problems[0] and "nope.rs" in problems[0]
    assert "a.md:2" in problems[1] and "#other" in problems[1]


def test_src_links_are_read_inside_directives_but_not_inside_code(tmp_path: Path) -> None:
    page = "```{glossary}\nterm\n  {src}`nope.rs`\n```\n\n```sh\n{src}`ignored.rs`\n```\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "a.md:3" in problems[0]


def test_readme_links_accept_pages_and_the_site_root(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "[a](https://hole.readthedocs.io/en/latest/) [b](https://hole.readthedocs.io/en/latest/reference/cli.html#x)\n",
        encoding="utf-8",
    )

    assert readme_link_problems(tmp_path, frozenset({"docs/index.md", "docs/reference/cli.md"})) == []


def test_readme_links_report_a_page_that_is_not_tracked(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text(
        "ok\n[a](https://hole.readthedocs.io/en/latest/reference/gone.html)\n", encoding="utf-8"
    )

    problems = readme_link_problems(tmp_path, frozenset({"docs/index.md"}))

    assert len(problems) == 1
    assert "README.md:2" in problems[0] and "docs/reference/gone.md" in problems[0]
