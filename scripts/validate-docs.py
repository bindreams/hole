#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.13"
# ///
"""Build the documentation site and check that its version substitutions rendered.

Builds `docs/` with warnings promoted to errors, then verifies the landing page's
versions line carries the real manifest versions and that no substitution was
left unrendered.

Usage:
    uv run scripts/validate-docs.py
"""
import re
import subprocess
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

SUBSTITUTIONS = ("hole_version", "galoshes_version", "garter_version", "exray_version")

# Must match the versions line in docs/index.md byte-for-byte once formatted.
VERSIONS_LINE = (
    "Component versions: hole {hole_version}, galoshes {galoshes_version}, "
    "garter {garter_version}, ex-ray {exray_version}."
)

# Only this project's own substitutions. A general `{{` match fails a correct
# build: a page documenting `${{ github.ref }}` emits it verbatim.
SUBSTITUTION_RE = re.compile(r"\{\{\s*(?:" + "|".join(SUBSTITUTIONS) + r")\s*\}\}")

# Sphinx writes these itself; their contents are not ours to check.
GENERATED_PAGES = frozenset({"search.html", "genindex.html"})


def manifest_versions(root: Path) -> dict[str, str]:
    """Substitution name -> version, read from the four release-group manifests."""
    versions = {
        f"{crate}_version": _manifest_version(root / "crates" / crate / "Cargo.toml", "package")
        for crate in ("hole", "galoshes", "garter")
    }
    # ex-ray is a Go crate with no Cargo manifest, so its version sits at the top level.
    versions["exray_version"] = _manifest_version(root / "crates" / "ex-ray" / "version.toml")
    return versions


def _manifest_version(manifest: Path, *tables: str) -> str:
    with manifest.open("rb") as f:
        data = tomllib.load(f)
    for table in tables:
        data = data[table]

    version = data["version"]
    if not isinstance(version, str):
        raise TypeError(f"{manifest}: version is {type(version).__name__}, not str -- it needs quoting")
    return version


def unrendered_substitutions(html: str) -> list[str]:
    """This project's own substitutions left literal in one page, in order."""
    return SUBSTITUTION_RE.findall(html)


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


def main() -> int:
    out_dir = REPO_ROOT / ".tmp" / "docs-build"
    # Sphinx is pinned in docs/requirements.txt alone, so it stays out of this
    # script's own dependencies. Output is inherited: capturing it would silence
    # the warnings this script exists to surface.
    build = subprocess.run(
        [
            "uv", "run", "--no-project", "--python", "3.13", "--with-requirements",
            str(REPO_ROOT / "docs" / "requirements.txt"), "--", "sphinx-build", "-W", "-b", "html",
            str(REPO_ROOT / "docs"),
            str(out_dir)
        ],
        cwd=REPO_ROOT,
    )
    if build.returncode != 0:
        return build.returncode

    problems = check_rendered(out_dir, manifest_versions(REPO_ROOT))
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
