"""https://www.sphinx-doc.org/en/master/usage/configuration.html"""
import sys
from datetime import date
from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

sys.path.insert(0, str(Path(__file__).parent))
from _versions import manifest_versions  # noqa: E402

project = "Hole"
author = "Anna Zhukova"
versions = manifest_versions(REPO_ROOT)
release = versions["hole_version"]

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
myst_substitutions = versions

exclude_patterns = ["_build"]

html_theme = "furo"
