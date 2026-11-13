#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# ///
"""Build the documentation site and check what the build cannot.

Builds `docs/` with warnings promoted to errors, then verifies the landing page's
versions line carries the real manifest versions and that no substitution was
left unrendered. Also checks every `{src}` link in `docs/`: its path must be
tracked in the repository and, for a Markdown target, its `#anchor` must match a
heading there (GitHub's slug rules). A fence left open at the end of a page, or
in a Markdown target, is a problem too, since the rest of the file goes
unchecked. Every README link that starts with
`https://hole.readthedocs.io/en/latest/` must be the site root or `<page>.html`,
where `docs/<page>.md` is tracked in the repository.

Usage:
    uv run scripts/validate-docs.py
    uv run scripts/validate-docs.py --fetch-only
    uv run scripts/validate-docs.py --links-only

`--fetch-only` resolves and downloads the build's tools and builds nothing, so CI
can run the fetch under a retry without retrying a docs failure. `--links-only`
runs the `{src}` and README link checks without the build.
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
# Sphinx's `explicit_title_re`, which its extlinks role splits a target with. The
# target is used as written: no strip, and `<path>` without a title is a path.
SRC_TITLED_RE = re.compile(r"^(.+?)\s*(?<!\x00)<([^<]*?)>$", re.DOTALL)

# A README link into the published site: the page path after `/en/latest/`, if any.
SITE_LINK_RE = re.compile(r"https://hole\.readthedocs\.io/en/latest/([^\s)#>]*)")

HEADING_RE = re.compile(r"^ {0,3}#{1,6}[ \t]+(.*?)[ \t]*$")
SETEXT_RE = re.compile(r"^ {0,3}(?:=+|-+)[ \t]*$")
# A line that starts a block other than a paragraph, so it cannot be a setext heading's text.
BLOCK_START_RE = re.compile(r"^ {0,3}(?:>|[-*+][ \t]|\d+[.)][ \t]|(?:[-*_][ \t]*){3,}$)")
HTML_COMMENT_RE = re.compile(r"<!--.*?(?:-->|\Z)", re.DOTALL)
HTML_TAG_RE = re.compile(r"<[^>]*>")
# A backtick fence's info string holds no backtick: "```x``` is code" is a code span.
FENCE_RE = re.compile(r"^ {0,3}(`{3,}(?=[^`]*$)|~{3,})[ \t]*(.*?)[ \t]*$")

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


def scan_fences(text: str, directives: bool = True) -> tuple[list[tuple[int, str]], list[int]]:
    """Split Markdown into the lines outside code blocks and the fences left open.

    Returns `(number, line)` for each line outside a code block, and the line
    number of every fence still open at the end of the text. With `directives`,
    a fence whose info string opens with `{` is a MyST directive, not code: its
    body is Markdown (a `{glossary}` holds the page's `{src}` links) and is
    returned. Without it every fence is code, as on GitHub.
    """
    outside: list[tuple[int, str]] = []
    open_fences: list[tuple[str, int, bool, int]] = []  # (fence char, fence length, is code, line number)
    for number, line in enumerate(text.splitlines(), start=1):
        match = FENCE_RE.match(line)
        if match and open_fences:
            char, length, _, _ = open_fences[-1]
            if match.group(1)[0] == char and len(match.group(1)) >= length and not match.group(2):
                open_fences.pop()
                continue
        if match and not (open_fences and open_fences[-1][2]):
            fence = match.group(1)
            open_fences.append((fence[0], len(fence), not (directives and match.group(2).startswith("{")), number))
            continue
        if not any(is_code for _, _, is_code, _ in open_fences):
            outside.append((number, line))
    return outside, [number for _, _, _, number in open_fences]


def paragraphs(lines: list[tuple[int, str]]) -> Iterator[tuple[int, str]]:
    """Yield `(first line number, text)` for each run of consecutive non-blank lines."""
    run: list[str] = []
    first = previous = 0
    for number, line in lines:
        if run and (number != previous + 1 or not line.strip()):
            yield first, "\n".join(run)
            run = []
        if line.strip():
            if not run:
                first = number
            run.append(line)
        previous = number
    if run:
        yield first, "\n".join(run)


def github_slug(title: str) -> str:
    """The anchor GitHub derives from one heading's text, before collision suffixes.

    Markdown links and HTML tags are read; emphasis, entities and autolinks are
    not, so an anchor to a heading holding one needs checking by hand.
    """
    title = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", title)  # a link contributes its text
    title = HTML_TAG_RE.sub("", title)
    return re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")


def heading_slugs(markdown: str) -> set[str]:
    """The anchors GitHub generates for the headings of one Markdown file.

    Follows github-slugger (see `github_slug` for what it leaves out): lowercase,
    HTML tags and punctuation other than `-` and `_` dropped, spaces to `-`; a
    slug already taken gets the next free `-1`, `-2`, ... suffix. ATX and setext
    headings count; code blocks (every fence is one on GitHub) and HTML comments
    do not.
    """
    lines, _ = scan_fences(markdown, directives=False)
    text = HTML_COMMENT_RE.sub("", "\n".join(line for _, line in lines))
    occurrences: dict[str, int] = {}
    paragraph: list[str] = []
    for line in text.splitlines():
        heading = HEADING_RE.match(line)
        if SETEXT_RE.match(line) and paragraph:
            title = " ".join(paragraph)
        elif heading:
            title = re.sub(r"[ \t]+#+$", "", heading.group(1))
        else:
            if line.strip() and not BLOCK_START_RE.match(line):
                paragraph.append(line.strip())
            else:
                paragraph = []
            continue
        paragraph = []
        base = slug = github_slug(title)
        while slug in occurrences:
            occurrences[base] += 1
            slug = f"{base}-{occurrences[base]}"
        occurrences[slug] = 0
    return set(occurrences)


def target_defects(markdown: str) -> list[str]:
    """What hides the headings after it in one Markdown target, as GitHub reads it.

    An unclosed fence or HTML comment swallows the rest of the file, so a later
    heading would be reported as missing for the wrong reason.
    """
    lines, open_fences = scan_fences(markdown, directives=False)
    defects = [f"{number}: fence is never closed" for number in open_fences]
    text = "\n".join(line for _, line in lines)
    for comment in HTML_COMMENT_RE.finditer(text):
        if not comment.group().endswith("-->"):
            number = lines[text.count("\n", 0, comment.start())][0]
            defects.append(f"{number}: HTML comment is never closed")
    return defects


def src_link_problems(repo_root: Path, tracked: frozenset[str]) -> list[str]:
    """Problems with the `{src}` links of every page under `docs/`.

    `tracked` holds the repository's file paths, `/`-separated. A target names a
    tracked file or a directory holding one; a `.md` target's `#anchor` must be
    a heading slug of that file.
    """
    problems = []
    defective: set[str] = set()  # targets already reported as unreadable past a point
    for page in sorted((repo_root / "docs").rglob("*.md")):
        where = page.relative_to(repo_root).as_posix()
        outside, unclosed = scan_fences(page.read_text(encoding="utf-8"))
        for number in unclosed:
            problems.append(f"{where}:{number}: fence is never closed: the rest of the page is unchecked")
        for first, text in paragraphs(outside):
            for role in SRC_ROLE_RE.finditer(text):
                number = first + text.count("\n", 0, role.start())
                titled = SRC_TITLED_RE.match(role.group(1))
                target = titled.group(2) if titled else role.group(1)
                path, _, anchor = target.partition("#")
                is_dir = any(name.startswith(path.rstrip("/") + "/") for name in tracked)
                if path not in tracked and not is_dir:
                    problems.append(f"{where}:{number}: {{src}} path is not tracked in the repository: {path}")
                elif anchor and path.endswith(".md") and path in tracked:
                    target_file = repo_root / path
                    if not target_file.is_file():
                        problems.append(f"{where}:{number}: {{src}} path is tracked but missing on disk: {path}")
                    else:
                        markdown = target_file.read_text(encoding="utf-8")
                        defects = target_defects(markdown)
                        if defects and path not in defective:
                            defective.add(path)
                            problems.extend(
                                f"{path}:{defect}: the headings after it are unchecked" for defect in defects
                            )
                        if not defects and anchor not in heading_slugs(markdown):
                            problems.append(f"{where}:{number}: {{src}} anchor matches no heading in {path}: #{anchor}")
    return problems


def readme_link_problems(repo_root: Path, tracked: frozenset[str]) -> list[str]:
    """Problems with the README's links into the published site.

    `<page>.html` must have a tracked `docs/<page>.md` source; the bare site root
    maps to `docs/index.md`. Any other link under the site's base is a problem.
    """
    problems = []
    readme_file = repo_root / "README.md"
    if not readme_file.is_file():
        return ["README.md: missing on disk"]
    readme = readme_file.read_text(encoding="utf-8")
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


def report(problems: list[str]) -> None:
    for problem in problems:
        print(problem, file=sys.stderr)


def main() -> int:
    if sys.argv[1:] not in ([], ["--fetch-only"], ["--links-only"]):
        print(f"usage: {Path(sys.argv[0]).name} [--fetch-only | --links-only]", file=sys.stderr)
        return 2

    if sys.argv[1:] == ["--fetch-only"]:
        return subprocess.run(sphinx_command("--version"), cwd=REPO_ROOT).returncode

    tracked = tracked_files()
    problems = src_link_problems(REPO_ROOT, tracked) + readme_link_problems(REPO_ROOT, tracked)
    if sys.argv[1:] == ["--links-only"]:
        report(problems)
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
            report(problems)
            return build.returncode

        problems += check_rendered(out_dir, manifest_versions(REPO_ROOT))

    report(problems)
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


def test_heading_slugs_take_the_next_free_suffix() -> None:
    assert heading_slugs("# a\n# a-1\n# a\n") == {"a", "a-1", "a-2"}


def test_heading_slugs_drop_html_tags_and_commented_headings_and_read_setext() -> None:
    markdown = "# Foo <kbd>Ctrl</kbd>\n<!--\n# hidden\n-->\nTitle\n=====\n\nSub\n---\n"

    assert heading_slugs(markdown) == {"foo-ctrl", "title", "sub"}


def test_a_backtick_run_with_a_backtick_after_it_is_not_a_fence() -> None:
    outside, unclosed = scan_fences("```x``` is code\n{src}`nope.rs`\n")

    assert [number for number, _ in outside] == [1, 2]
    assert unclosed == []


def test_an_unclosed_fence_is_reported(tmp_path: Path) -> None:
    tracked = _write_repo(tmp_path, {"docs/a.md": "text\n```sh\n{src}`nope.rs`\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "a.md:2" in problems[0] and "never closed" in problems[0]


def test_src_links_that_wrap_across_lines_are_checked_at_their_first_line(tmp_path: Path) -> None:
    tracked = _write_repo(tmp_path, {"docs/a.md": "intro\n\nsee {src}`the CLI\n<nope/cli.rs>` here\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "a.md:3" in problems[0] and "nope/cli.rs" in problems[0]


def test_a_tracked_markdown_target_missing_on_disk_is_a_problem_not_a_crash(tmp_path: Path) -> None:
    _write_files(tmp_path, {"docs/a.md": "{src}`T <T.md#x>`\n"})

    problems = src_link_problems(tmp_path, frozenset({"T.md"}))

    assert len(problems) == 1
    assert "missing on disk" in problems[0]


def test_src_links_accept_files_directories_and_anchors(tmp_path: Path) -> None:
    page = "{src}`x/y.rs` {src}`dir` {src}`T <T.md#some-heading>` {src}`x/y.rs#L10`\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page, "x/y.rs": "", "dir/f": "", "T.md": "## Some heading\n"})

    assert src_link_problems(tmp_path, tracked) == []


def test_src_targets_are_split_the_way_sphinx_splits_them(tmp_path: Path) -> None:
    page = "{src}`<x/y.rs>` {src}`T < x/y.rs >` {src}`T <x/y.rs>`\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page, "x/y.rs": ""})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 2
    assert "<x/y.rs>" in problems[0]
    assert " x/y.rs " in problems[1]


def test_every_fence_in_a_github_target_is_code() -> None:
    markdown = "# Real\n\n```{code-block} sh\n# Lockdown mode\n```\n\n## Lockdown mode\n"

    assert heading_slugs(markdown) == {"real", "lockdown-mode"}


def test_an_unclosed_fence_or_comment_in_a_target_is_reported_not_misread_as_a_missing_heading(tmp_path: Path) -> None:
    files = {"docs/a.md": "{src}`T <T.md#late>` {src}`T <T.md#late>`\n", "T.md": "# Early\n<!--\n# Late\n"}
    tracked = _write_repo(tmp_path, files)

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "T.md:2: HTML comment is never closed" in problems[0]
    assert target_defects("# a\n```sh\n# b\n") == ["2: fence is never closed"]


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
