#!/usr/bin/env python3
"""Fail when a file refers to the agent instructions file by name.

Code and docs must stand on their own: a reader of either should never be sent to
a file written for coding agents. The check reads the files prek passes it, so the
hook's own `exclude` (vendored code) applies, and prints `path:line` for each hit.

Exempt: the agent files themselves (`CLAUDE.md`, `CLAUDE.local.md`, `.claude/`), this
script, and a release config's `include_paths` entry that is exactly `- CLAUDE.md`
(it names a path whose changes belong in the release notes, not a reference to read).
"""

import fnmatch
import sys
from pathlib import Path

NEEDLE = "CLAUDE.md"
EXEMPT_FILES = frozenset({"CLAUDE.md", "CLAUDE.local.md", "scripts/check-no-claude-md-refs.py"})
RELEASE_CONFIG = ".github/release-*.yaml"
INCLUDE_PATHS_ENTRY = "- CLAUDE.md"


def posix(path: str) -> str:
    return path.replace(chr(92), "/")


def scan(path: str, text: str) -> list[int]:
    """Return the 1-based line numbers in `text` that are references, given the file's repo-relative `path`."""
    path = posix(path)
    if path in EXEMPT_FILES or path.startswith(".claude/"):
        return []
    is_release_config = fnmatch.fnmatchcase(path, RELEASE_CONFIG)
    return [
        number
        for number, line in enumerate(text.splitlines(), start=1)
        if NEEDLE in line and not (is_release_config and line.strip() == INCLUDE_PATHS_ENTRY)
    ]


def main(argv: list[str]) -> int:
    failed = False
    for name in argv:
        path = Path(name)
        if not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        for number in scan(name, text):
            print(f"{posix(name)}:{number}: refers to the agent instructions file")
            failed = True
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

# Tests (run with pytest) ==============================================================================================

import subprocess  # noqa: E402


def test_flags_a_reference_in_a_source_comment() -> None:
    assert scan("crates/bridge/src/x.rs", "fn a() {}\n// see CLAUDE.md for why\n") == [2]


def test_flags_a_reference_in_a_docs_page() -> None:
    assert scan("docs/contributing/testing.md", "Per CLAUDE.md, tests fail loudly.\n") == [1]


def test_reports_every_line() -> None:
    assert scan("a.py", "CLAUDE.md\nok\nCLAUDE.md again\n") == [1, 3]


def test_ignores_files_without_the_name() -> None:
    assert scan("a.rs", "// nothing here, CLAUDE.local is not it\n") == []


def test_exempts_the_agent_files() -> None:
    for path in ("CLAUDE.md", "CLAUDE.local.md", ".claude/settings.json", ".claude/skills/x/SKILL.md"):
        assert scan(path, "CLAUDE.md\n") == [], path


def test_exempts_the_script_itself() -> None:
    assert scan("scripts/check-no-claude-md-refs.py", 'NEEDLE = "CLAUDE.md"\n') == []


def test_does_not_exempt_a_file_that_only_looks_like_an_agent_file() -> None:
    assert scan("docs/CLAUDE.md", "x\nCLAUDE.md\n") == [2]
    assert scan("src/.claude/x.rs", "CLAUDE.md\n") == [1]


def test_exempts_a_release_config_include_paths_entry() -> None:
    text = "include_paths:\n  - docs/**\n  - CLAUDE.md\n  - README.md\n"
    assert scan(".github/release-hole.yaml", text) == []


def test_flags_other_mentions_in_a_release_config() -> None:
    text = '# see CLAUDE.md "Releases"\ninclude_paths:\n  - CLAUDE.md\n'
    assert scan(".github/release-hole.yaml", text) == [1]


def test_the_include_paths_exemption_is_only_for_release_configs() -> None:
    assert scan(".github/workflows/ci.yaml", "  - CLAUDE.md\n") == [1]
    assert scan(".github/release-hole.yaml.md", "  - CLAUDE.md\n") == [1]
    assert scan("docs/release-x.yaml", "  - CLAUDE.md\n") == [1]


def test_accepts_windows_separators() -> None:
    assert scan(r".github\release-hole.yaml", "  - CLAUDE.md\n") == []
    assert scan(r"crates\x\a.rs", "CLAUDE.md\n") == [1]


def test_main_prints_path_and_line_and_fails(tmp_path) -> None:
    bad = tmp_path / "a.rs"
    bad.write_text("ok\n// CLAUDE.md\n")
    r = subprocess.run([sys.executable, __file__, str(bad)], capture_output=True, text=True)
    assert r.returncode == 1
    assert r.stdout.strip().endswith("a.rs:2: refers to the agent instructions file")


def test_main_passes_on_clean_files_and_skips_non_files(tmp_path) -> None:
    good = tmp_path / "a.rs"
    good.write_text("// nothing\n")
    r = subprocess.run([sys.executable, __file__, str(good), str(tmp_path / "missing")], capture_output=True, text=True)
    assert r.returncode == 0
    assert r.stdout == ""
