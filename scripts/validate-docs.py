# /// script
# requires-python = ">=3.13"
# ///
"""Build the documentation site and check what the build cannot.

Builds `docs/` with warnings promoted to errors, then verifies the landing page's
versions line carries the real manifest versions and that no substitution was
left unrendered. Also checks every `{src}` link in `docs/`: its path must be
tracked in the repository and, for a Markdown target, its `#anchor` must match a
heading there (GitHub's slug rules). A code fence that is never closed is
reported in a page, a target and the README. Markdown is read with the parser the
build itself uses, so it comes from `docs/requirements.txt` and not from this
script: pages as MyST reads them, targets and the README as GitHub does. Every README link that starts with
`https://hole.readthedocs.io/en/latest/` must be the site root or `<page>.html`,
where `docs/<page>.md` is tracked in the repository.

Usage, from the repository root:
    uv run --with-requirements docs/requirements.txt scripts/validate-docs.py
    uv run --with-requirements docs/requirements.txt scripts/validate-docs.py --fetch-only
    uv run --with-requirements docs/requirements.txt scripts/validate-docs.py --links-only

`--fetch-only` builds nothing: `uv` has resolved and downloaded the requirements
by the time it runs, so CI can run the fetch under a retry without retrying a
docs failure. `--links-only` runs the `{src}` and README link checks without the
build.
"""

import functools
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

from markdown_it import MarkdownIt
from markdown_it.renderer import RendererHTML
from markdown_it.token import Token
from myst_parser.config.main import MdParserConfig
from myst_parser.parsers.mdit import create_md_parser

REPO_ROOT = Path(__file__).resolve().parent.parent

sys.path.insert(0, str(REPO_ROOT / "docs"))
import conf as docs_conf  # noqa: E402
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

# A `{src}` role is {src}`path`, {src}`path#anchor` or {src}`title <path#anchor>`.
# Sphinx's `explicit_title_re`, which its extlinks role splits a target with. The
# target is used as written: no strip, and `<path>` without a title is a path.
SRC_TITLED_RE = re.compile(r"^(.+?)\s*(?<!\x00)<([^<]*?)>$", re.DOTALL)

# A README link into the published site: the page path after `/en/latest/`, if any.
SITE_LINK_RE = re.compile(r"https://hole\.readthedocs\.io/en/latest/([^\s)#<>\"']*)")

# Directives whose body is not Markdown: a role written in one is not a role. The
# docutils, Sphinx, MyST, sphinx-design and sphinxcontrib-mermaid directives the
# docs build registers whose body is code, RST, CSV or a list of document names.
LITERAL_DIRECTIVES = frozenset({
    "code",
    "code-block",
    "code-cell",
    "csv-table",
    "date",
    "eval-rst",
    "line-block",
    "literalinclude",
    "math",
    "mermaid",
    "meta",
    "parsed-literal",
    "productionlist",
    "raw",
    "replace",
    "role",
    "sourcecode",
    "toctree",
})

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


def github_parser() -> MarkdownIt:
    """A parser that reads Markdown as GitHub does (CommonMark and tables)."""
    return MarkdownIt("commonmark").enable("table")


def myst_parser() -> MarkdownIt:
    """The docs build's own MyST parser, configured from `docs/conf.py`."""
    config = MdParserConfig(enable_extensions=set(docs_conf.myst_enable_extensions))
    return create_md_parser(config, RendererHTML)


def split_lines(text: str) -> list[str]:
    """The lines of `text` as markdown-it numbers them."""
    return re.split(r"\r\n|\r|\n", text)


def fence_unclosed(fence: Token, lines: list[str]) -> bool:
    """Whether a fence token ended without a closing fence line.

    The parser ends such a fence at the end of the file or of its container, so
    its last line is not a fence of the same character and at least the same length.
    """
    start, end = fence.map or (0, 0)
    closing = rf"[\s>]*{re.escape(fence.markup[0])}{{{len(fence.markup)},}}\s*"
    return end - start < 2 or not re.fullmatch(closing, lines[end - 1])


def leaf_tokens(parser: MarkdownIt, text: str, directives: bool, offset: int = 0) -> Iterator[tuple[int, Token]]:
    """Parse `text` and yield `(line, token)` for every token that holds content.

    That is each inline child and each block leaf. Lines are 1-based. A line
    inside a paragraph counts its soft and hard breaks, so it is one line too
    early after a code span or role that wrapped. A fence that is never closed
    also yields a token of type `unclosed_fence` on its opening line. With
    `directives`, `parser` is the MyST parser and a MyST directive fence (info
    string `{name}`) is read too: its argument as inline Markdown and its body as
    Markdown, unless the body is literal (`LITERAL_DIRECTIVES`); the nested lines
    are offset to the page's.
    """
    lines = split_lines(text)
    for token in parser.parse(text):
        if token.map is None:
            continue
        line = offset + token.map[0] + 1
        if token.type == "inline":
            for child in token.children or []:
                yield line, child
                if child.type in ("softbreak", "hardbreak"):
                    line += 1
            continue
        yield line, token
        if token.type != "fence":
            continue
        if fence_unclosed(token, lines):
            yield line, Token("unclosed_fence", "", 0)
        if directives and token.info.startswith("{"):
            name, _, argument = token.info[1:].partition("}")
            if name in LITERAL_DIRECTIVES:
                continue
            for inline in parser.parseInline(argument.strip()):
                for child in inline.children or []:
                    yield line, child
            yield from leaf_tokens(parser, token.content, directives, line)


def plain_text(children: list[Token]) -> str:
    """The text of inline tokens as a reader sees it: no markup, no HTML tags.

    A code span's characters and an image's alt text count; a soft break is a space.
    """
    parts = []
    for child in children:
        if child.type == "html_inline":
            continue
        if child.type == "image":
            parts.append(plain_text(child.children or []))
        elif child.type in ("softbreak", "hardbreak"):
            parts.append(" ")
        else:
            parts.append(child.content)
    return "".join(parts)


def github_slug(title: str) -> str:
    """The anchor GitHub derives from a heading's plain text, before collision suffixes."""
    return re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")


class Target(NamedTuple):
    """What a `{src}` link needs of a Markdown file it points at."""

    slugs: frozenset[str]
    unclosed_fences: tuple[int, ...]  # 1-based opening lines


@functools.cache
def read_target(markdown_file: Path) -> Target:
    """The anchors GitHub generates for the headings of one Markdown file, and its unclosed fences.

    Follows github-slugger: the slug of the heading's plain text (`plain_text`),
    then, for a slug already taken, the next free `-1`, `-2`, ... suffix. The file
    is read once per run.
    """
    text = markdown_file.read_text(encoding="utf-8")
    lines = split_lines(text)
    tokens = github_parser().parse(text)
    occurrences: dict[str, int] = {}
    for heading, inline in zip(tokens, tokens[1:]):
        if heading.type != "heading_open":
            continue
        base = slug = github_slug(plain_text(inline.children or []))
        while slug in occurrences:
            occurrences[base] += 1
            slug = f"{base}-{occurrences[base]}"
        occurrences[slug] = 0
    unclosed = tuple(
        token.map[0] + 1 for token in tokens if token.type == "fence" and token.map and fence_unclosed(token, lines)
    )
    return Target(frozenset(occurrences), unclosed)


def unclosed_fence_problem(where: str) -> str:
    return f"{where}: code fence is never closed; it hides the rest of the file"


def src_link_problems(repo_root: Path, tracked: frozenset[str]) -> list[str]:
    """Problems with the `{src}` links of every page under `docs/`.

    `tracked` holds the repository's file paths, `/`-separated. A target names a
    tracked file or a directory holding one; a `.md` target's `#anchor` must be
    a heading slug of that file. A fence never closed is a problem in a page and,
    once, in each Markdown target read for an anchor.
    """
    problems = []
    parser = myst_parser()
    anchored: set[str] = set()
    for page in sorted((repo_root / "docs").rglob("*.md")):
        where = page.relative_to(repo_root).as_posix()
        for number, token in leaf_tokens(parser, page.read_text(encoding="utf-8"), directives=True):
            if token.type == "unclosed_fence":
                problems.append(unclosed_fence_problem(f"{where}:{number}"))
                continue
            if token.type != "myst_role" or token.meta["name"] != "src":
                continue
            titled = SRC_TITLED_RE.match(token.content)
            target = titled.group(2) if titled else token.content
            path, _, anchor = target.partition("#")
            is_dir = any(name.startswith(path.rstrip("/") + "/") for name in tracked)
            if path not in tracked and not is_dir:
                problems.append(f"{where}:{number}: {{src}} path is not tracked in the repository: {path!r}")
            elif anchor and path.endswith(".md") and path in tracked:
                target_file = repo_root / path
                if not target_file.is_file():
                    problems.append(f"{where}:{number}: {{src}} path is tracked but missing on disk: {path!r}")
                    continue
                anchored.add(path)
                if anchor not in read_target(target_file).slugs:
                    problems.append(f"{where}:{number}: {{src}} anchor matches no heading in {path!r}: {anchor!r}")
    for path in sorted(anchored):
        for number in read_target(repo_root / path).unclosed_fences:
            problems.append(unclosed_fence_problem(f"{path}:{number}"))
    return problems


def readme_link_problems(repo_root: Path, tracked: frozenset[str]) -> list[str]:
    """Problems with the README's links into the published site.

    `<page>.html` must have a tracked `docs/<page>.md` source; the bare site root
    maps to `docs/index.md`. Any other link under the site's base is a problem.
    Link destinations, plain text and raw HTML are read, once each; code, and the
    text of a link (which is not itself a link), are not.
    """
    problems = []
    readme_file = repo_root / "README.md"
    if not readme_file.is_file():
        return ["README.md: missing on disk"]
    in_link = False
    for number, token in leaf_tokens(github_parser(), readme_file.read_text(encoding="utf-8"), directives=False):
        if token.type == "unclosed_fence":
            problems.append(unclosed_fence_problem(f"README.md:{number}"))
            continue
        if token.type in ("link_open", "link_close"):
            in_link = token.type == "link_open"
        if token.type in ("link_open", "image"):
            text = token.attrGet("href") or token.attrGet("src") or ""
        elif token.type in ("text", "html_inline", "html_block") and not in_link:
            text = token.content
        else:
            continue
        for link in SITE_LINK_RE.finditer(str(text)):
            page = link.group(1)
            if page.endswith(".html"):
                source = f"docs/{page.removesuffix('.html')}.md"
            elif page == "":
                source = "docs/index.md"
            else:
                problems.append(f"README.md:{number}: site link is not a page or the site root: {link.group(0)!r}")
                continue
            if source not in tracked:
                problems.append(
                    f"README.md:{number}: site link's page source {source!r} is not tracked in the repository: "
                    f"{link.group(0)!r}"
                )
    return problems


def tracked_files() -> frozenset[str]:
    """Paths of the files in the git index (staged files included)."""
    listing = subprocess.run(
        ["git", "ls-files", "-z"], cwd=REPO_ROOT, check=True, capture_output=True, text=True, encoding="utf-8"
    )
    return frozenset(listing.stdout.split("\0")) - {""}


def report(problems: list[str]) -> None:
    for problem in problems:
        print(problem, file=sys.stderr)


def main() -> int:
    if sys.argv[1:] not in ([], ["--fetch-only"], ["--links-only"]):
        print(f"usage: {Path(sys.argv[0]).name} [--fetch-only | --links-only]", file=sys.stderr)
        return 2

    if sys.argv[1:] == ["--fetch-only"]:
        return 0

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
        # Output is inherited: capturing it would silence the warnings this
        # script exists to surface.
        # This interpreter holds the docs requirements, Sphinx included.
        build = subprocess.run(
            [sys.executable, "-m", "sphinx", "-W", "-b", "html", str(REPO_ROOT / "docs"), str(out_dir)],
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


def _write_repo(root: Path, files: dict[str, str]) -> frozenset[str]:
    """Write `files` under `root`; return the non-docs ones as the tracked set."""
    _write_files(root, files)
    return frozenset(name for name in files if not name.startswith("docs/"))


def _write_files(root: Path, files: dict[str, str]) -> None:
    for name, text in files.items():
        (root / name).parent.mkdir(parents=True, exist_ok=True)
        (root / name).write_text(text, encoding="utf-8")


def _slugs(tmp_path: Path, markdown: str) -> frozenset[str]:
    """The slugs of `markdown`, written to a file of its own under `tmp_path`."""
    _write_files(tmp_path, {"t.md": markdown})
    return read_target(tmp_path / "t.md").slugs


def test_heading_slugs_follow_github_rules(tmp_path: Path) -> None:
    markdown = "# CLI (dev/admin commands)\n## Lockdown mode\n## Lockdown mode\n## [Link](#x) `code_x` & more\n"

    assert _slugs(tmp_path, markdown) == {
        "cli-devadmin-commands",
        "lockdown-mode",
        "lockdown-mode-1",
        "link-code_x--more",
    }


def test_heading_slugs_ignore_fenced_code(tmp_path: Path) -> None:
    assert _slugs(tmp_path, "```sh\n# a comment\n```\n# Real\n") == {"real"}


def test_heading_slugs_ignore_a_fence_inside_a_list_item(tmp_path: Path) -> None:
    markdown = "1. step\n\n   ```sh\n   # a comment\n   ```\n\n- item\n\n      # indented code\n\n# Real\n"

    assert _slugs(tmp_path, markdown) == {"real"}


def test_heading_slugs_take_the_next_free_suffix(tmp_path: Path) -> None:
    assert _slugs(tmp_path, "# a\n# a-1\n# a\n") == {"a", "a-1", "a-2"}


def test_heading_slugs_read_setext_headings(tmp_path: Path) -> None:
    assert _slugs(tmp_path, "Title\n=====\n\nSub\n---\n\n- list\n---\n") == {"title", "sub"}


def test_heading_slugs_use_the_rendered_text_of_the_heading(tmp_path: Path) -> None:
    markdown = (
        "# Foo <kbd>Ctrl</kbd>\n"
        "## *Emphasis* and __strong__\n"
        "## Fish &amp; chips &copy;\n"
        "## See <https://a.b/c>\n"
        "## An ![alt text](x.png) image\n"
        "## Inline <!-- gone --> comment\n"
    )

    assert _slugs(tmp_path, markdown) == {
        "foo-ctrl",
        "emphasis-and-strong",
        "fish--chips-",
        "see-httpsabc",
        "an-alt-text-image",
        "inline--comment",
    }


def test_heading_slugs_skip_html_comments_and_stop_at_an_unclosed_one(tmp_path: Path) -> None:
    markdown = "<!--\n# hidden\n-->\n<!-- one line -->\n# Real\n<!--\n# swallowed\n"

    assert _slugs(tmp_path, markdown) == {"real"}


def test_an_unclosed_fence_hides_the_rest_of_a_target(tmp_path: Path) -> None:
    assert _slugs(tmp_path, "# Early\n```sh\n# Late\n") == {"early"}


def test_every_fence_in_a_github_target_is_code(tmp_path: Path) -> None:
    markdown = "# Real\n\n```{code-block} sh\n# Lockdown mode\n```\n\n## Lockdown mode\n"

    assert _slugs(tmp_path, markdown) == {"real", "lockdown-mode"}


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


def test_a_target_is_parsed_once_per_run(tmp_path: Path) -> None:
    page = "{src}`T <T.md#a>` {src}`T <T.md#b>`\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page, "docs/b.md": page, "T.md": "# A\n# B\n"})
    before = read_target.cache_info().misses

    assert src_link_problems(tmp_path, tracked) == []

    assert read_target.cache_info().misses == before + 1


def test_src_links_report_a_missing_path_and_a_wrong_anchor(tmp_path: Path) -> None:
    page = "{src}`nope.rs`\n{src}`T <T.md#other>`\n```\n{src}`ignored.rs`\n```\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page, "T.md": "## Some heading\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 2
    assert "a.md:1" in problems[0] and "'nope.rs'" in problems[0]
    assert "a.md:2" in problems[1] and "'other'" in problems[1]


def test_src_links_are_read_inside_directives_but_not_inside_code(tmp_path: Path) -> None:
    page = (
        "```{glossary}\nterm\n  {src}`nope.rs`\n```\n\n"
        "```sh\n{src}`ignored.rs`\n```\n\n"
        "```{code-block} sh\n{src}`ignored.rs`\n```\n\n"
        "```{mermaid}\n{src}`ignored.rs`\n```\n"
    )
    tracked = _write_repo(tmp_path, {"docs/a.md": page})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "a.md:3" in problems[0]


def test_src_links_are_read_in_nested_directives_and_lists_and_quotes(tmp_path: Path) -> None:
    page = (
        "````{note}\n```{glossary}\nterm\n  {src}`one.rs`\n```\n````\n\n"
        "- item\n\n  ```{glossary}\n  term\n    {src}`two.rs`\n  ```\n\n"
        "> {src}`three.rs`\n"
    )
    tracked = _write_repo(tmp_path, {"docs/a.md": page})

    problems = src_link_problems(tmp_path, tracked)

    assert [problem.split(": ")[0] for problem in problems] == ["docs/a.md:4", "docs/a.md:12", "docs/a.md:15"]


def test_src_roles_in_comments_and_code_spans_are_not_roles(tmp_path: Path) -> None:
    page = "<!-- {src}`one.rs` -->\n\n% {src}`two.rs`\n\n``{src}`three.rs` ``\n\n    {src}`four.rs`\n\n{ref}`five`\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page})

    assert src_link_problems(tmp_path, tracked) == []


def test_src_roles_after_front_matter_are_checked(tmp_path: Path) -> None:
    tracked = _write_repo(tmp_path, {"docs/a.md": "---\ntitle: {src}`ignored.rs`\n---\n\n{src}`nope.rs`\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "a.md:5" in problems[0]


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


def test_readme_links_ignore_code_and_read_html_and_bare_urls(tmp_path: Path) -> None:
    site = "https://hole.readthedocs.io/en/latest/reference/gone.html"
    (tmp_path / "README.md").write_text(
        f'`{site}`\n\n```sh\ncurl {site}\n```\n\nbare {site}\n\n<a href="{site}">x</a>\n', encoding="utf-8"
    )

    problems = readme_link_problems(tmp_path, frozenset({"docs/index.md"}))

    assert [problem.split(": ")[0] for problem in problems] == ["README.md:7", "README.md:9"]


def test_the_parsers_come_from_the_docs_build() -> None:
    """The build's own parser, not a pin of this script's."""
    assert myst_parser().options["myst_config"].enable_extensions == set(docs_conf.myst_enable_extensions)
    assert "myst_role" in myst_parser().inline.ruler.get_all_rules()


def test_site_links_end_at_a_quote_in_html(tmp_path: Path) -> None:
    site = "https://hole.readthedocs.io/en/latest/"
    (tmp_path / "README.md").write_text(
        f'<a href="{site}">root</a> <a href="{site}reference/cli.html">page</a> <a href=\'{site}\'>single</a>\n',
        encoding="utf-8",
    )

    assert readme_link_problems(tmp_path, frozenset({"docs/index.md", "docs/reference/cli.md"})) == []


def test_an_autolink_is_reported_once(tmp_path: Path) -> None:
    site = "https://hole.readthedocs.io/en/latest/reference/gone.html"
    (tmp_path / "README.md").write_text(f"<{site}>\n\n[{site}]({site})\n", encoding="utf-8")

    problems = readme_link_problems(tmp_path, frozenset({"docs/index.md"}))

    assert [problem.split(": ")[0] for problem in problems] == ["README.md:1", "README.md:3"]


def test_an_unclosed_fence_is_reported_in_a_page(tmp_path: Path) -> None:
    tracked = _write_repo(tmp_path, {"docs/a.md": "text\n```sh\n{src}`nope.rs`\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "docs/a.md:2" in problems[0] and "never closed" in problems[0]


def test_an_unclosed_fence_is_reported_once_in_a_target(tmp_path: Path) -> None:
    page = "{src}`T <T.md#early>` {src}`T <T.md#late>`\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page, "T.md": "# Early\n```sh\n# Late\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 2
    assert "'late'" in problems[0]
    assert "T.md:2" in problems[1] and "never closed" in problems[1]


def test_an_unclosed_fence_is_reported_in_the_readme(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("intro\n~~~~\ncode\n~~~\n", encoding="utf-8")

    problems = readme_link_problems(tmp_path, frozenset())

    assert len(problems) == 1
    assert "README.md:2" in problems[0]


def test_fences_that_close_are_not_reported(tmp_path: Path) -> None:
    page = "```sh\nx\n```\n\n````{note}\n```sh\ny\n```\n````\n\n> ```sh\n> z\n> ```\n\n- a\n\n  ```sh\n  w\n  ```\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page})

    assert src_link_problems(tmp_path, tracked) == []


def test_an_unclosed_fence_inside_a_directive_is_reported_at_the_page_line(tmp_path: Path) -> None:
    tracked = _write_repo(tmp_path, {"docs/a.md": "intro\n\n````{note}\ntext\n```sh\ncode\n````\n"})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "docs/a.md:5" in problems[0]


def test_an_empty_unclosed_fence_at_the_end_of_a_page_is_reported(tmp_path: Path) -> None:
    tracked = _write_repo(tmp_path, {"docs/a.md": "text\n\n```"})

    assert len(src_link_problems(tmp_path, tracked)) == 1


def test_src_roles_are_not_read_in_any_literal_directive(tmp_path: Path) -> None:
    page = "".join(f"```{{{name}}}\n{{src}}`ignored.rs`\n```\n\n" for name in sorted(LITERAL_DIRECTIVES))
    tracked = _write_repo(tmp_path, {"docs/a.md": page})

    assert src_link_problems(tmp_path, tracked) == []


def test_src_roles_are_read_in_a_directive_argument(tmp_path: Path) -> None:
    """A backtick fence's info string cannot hold a backtick, so only a tilde fence can carry a role."""
    page = "~~~{admonition} See {src}`nope.rs`\nbody\n~~~\n\n~~~{code-block} {src}`ignored.rs`\ncode\n~~~\n"
    tracked = _write_repo(tmp_path, {"docs/a.md": page})

    problems = src_link_problems(tmp_path, tracked)

    assert len(problems) == 1
    assert "a.md:1" in problems[0] and "nope.rs" in problems[0]
