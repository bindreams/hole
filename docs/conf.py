"""https://www.sphinx-doc.org/en/master/usage/configuration.html"""
import tomllib
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent


def manifest_version(manifest: Path, *tables: str) -> str:
    """Read a release-group version. Raises rather than rendering a blank version."""
    with manifest.open("rb") as f:
        data = tomllib.load(f)
    for table in tables:
        data = data[table]

    version = data["version"]
    if not isinstance(version, str):
        raise TypeError(f"{manifest}: version is {type(version).__name__}, not str -- it needs quoting")
    return version


def cargo_version(crate: str) -> str:
    return manifest_version(REPO_ROOT / "crates" / crate / "Cargo.toml", "package")


project = "Hole"
author = "Anna Zhukova"
release = cargo_version("hole")

year = date.today().year
copyright = f"2026, {author}" if year == 2026 else f"2026-{year}, {author}"
html_title = f"{project} {release}"

extensions = [
    "myst_parser",
    "sphinx_design",
    "sphinx_copybutton",
]
# No colon_fence: the mdformat-myst prek hook escapes colon fences, so the
# docs use backtick-fenced directives exclusively.
myst_enable_extensions = ["substitution"]
myst_heading_anchors = 3
myst_substitutions = {
    "hole_version": release,
    "galoshes_version": cargo_version("galoshes"),
    "garter_version": cargo_version("garter"),
    # ex-ray is a Go crate with no Cargo manifest; its version sits at the top level.
    "exray_version": manifest_version(REPO_ROOT / "crates" / "ex-ray" / "version.toml"),
}

exclude_patterns = ["_build"]

html_theme = "furo"
