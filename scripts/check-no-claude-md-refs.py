#!/usr/bin/env python3
"""Fail when a file refers to the agent instructions file by name.

Code and docs must stand on their own: a reader of either should never be sent to
a file written for coding agents. The check reads the files prek passes it and prints
`path:line` for each hit; vendored code is left out by prek's top-level `exclude`, not
by this script. The match ignores case, since the name resolves on case-insensitive
filesystems.

Exempt: the agent files themselves (any `CLAUDE.md` or `CLAUDE.local.md`, anything
under a `.claude` folder), this script, the docs checker that link-checks the map
(`scripts/validate-docs.py`), and an entry of a release config's
`include_paths` list that is exactly `- CLAUDE.md` (it names a path whose changes
belong in the release notes, not a reference to read).

A path that is not a regular file, or cannot be read, is named on stderr and not scanned.
"""

import fnmatch
import re
import sys
from pathlib import Path

NEEDLE = re.compile(r"claude\.md", re.IGNORECASE)
AGENT_BASENAMES = frozenset({"claude.md", "claude.local.md"})
AGENT_FOLDER = ".claude"
SELF = "scripts/check-no-claude-md-refs.py"
LINK_CHECKER = "scripts/validate-docs.py"
RELEASE_CONFIG = ".github/release-*.yaml"
INCLUDE_PATHS_KEY = "include_paths"
INCLUDE_PATHS_ENTRY = "- claude.md"


def posix(path: str) -> str:
    return path.replace(chr(92), "/")


def is_exempt_file(path: str) -> bool:
    parts = path.split("/")
    return path in (SELF, LINK_CHECKER) or parts[-1].lower() in AGENT_BASENAMES or AGENT_FOLDER in parts[:-1]


def top_level_key(line: str) -> str | None:
    if not line or line[0] in " \t#-" or ":" not in line:
        return None
    return line.split(":", 1)[0].strip()


def scan(path: str, text: str) -> list[int]:
    """Line numbers in `text` that refer to the agent file."""
    path = posix(path)
    if is_exempt_file(path):
        return []
    is_release_config = fnmatch.fnmatchcase(path, RELEASE_CONFIG)
    hits = []
    key = None
    for number, line in enumerate(text.splitlines(), start=1):
        key = top_level_key(line) or key
        if not NEEDLE.search(line):
            continue
        if is_release_config and key == INCLUDE_PATHS_KEY and line.strip().lower() == INCLUDE_PATHS_ENTRY:
            continue
        hits.append(number)
    return hits


def main(argv: list[str]) -> int:
    failed = False
    for name in argv:
        path = Path(name)
        try:
            if not path.is_file():
                print(f"{posix(name)}: not scanned (not a regular file)", file=sys.stderr)
                continue
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError as error:
            print(f"{posix(name)}: not scanned ({error})", file=sys.stderr)
            continue
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


def test_exempts_the_docs_checker_that_link_checks_the_map() -> None:
    assert scan("scripts/validate-docs.py", "CLAUDE.md\n") == []
    assert scan("scripts/other.py", "CLAUDE.md\n") == [1]


def test_exempts_agent_files_by_basename_and_folder_at_any_depth() -> None:
    for path in ("docs/CLAUDE.md", "crates/x/CLAUDE.local.md", "src/.claude/x.rs", "a/.claude/b/c.md"):
        assert scan(path, "CLAUDE.md\n") == [], path


def test_does_not_exempt_a_file_that_only_looks_like_an_agent_file() -> None:
    assert scan("docs/NOT-CLAUDE.md", "CLAUDE.md\n") == [1]
    assert scan("docs/claude.md.bak", "CLAUDE.md\n") == [1]
    assert scan("src/claude/x.rs", "CLAUDE.md\n") == [1]
    assert scan("src/x.claude", "CLAUDE.md\n") == [1]


def test_matches_any_case() -> None:
    assert scan("a.rs", "// see claude.md\n// see CLAUDE.MD\n// Claude.Md\n") == [1, 2, 3]
    assert scan("a.rs", "// claude_md and claudeXmd are not it\n") == []


def test_exempts_the_agent_files_in_any_case() -> None:
    assert scan("docs/claude.md", "CLAUDE.md\n") == []
    assert scan("CLAUDE.MD", "CLAUDE.md\n") == []


def test_exempts_a_release_config_include_paths_entry() -> None:
    text = "include_paths:\n  - docs/**\n  - CLAUDE.md\n  - README.md\n"
    assert scan(".github/release-hole.yaml", text) == []


def test_the_exemption_is_only_for_the_include_paths_list() -> None:
    cfg = ".github/release-hole.yaml"
    assert scan(cfg, "initial_release:\n  - CLAUDE.md\ninclude_paths:\n  - docs/**\n") == [2]
    assert scan(cfg, "other:\n  - CLAUDE.md\n") == [2]
    assert scan(cfg, "include_paths:\n  - docs/**\nother:\n  - CLAUDE.md\n") == [4]
    assert scan(cfg, "- CLAUDE.md\n") == [1]


def test_exempts_an_include_paths_entry_with_an_unindented_list_or_other_case() -> None:
    cfg = ".github/release-hole.yaml"
    assert scan(cfg, "include_paths:\n- CLAUDE.md\n") == []
    assert scan(cfg, "include_paths:\n  - claude.md\n") == []
    assert scan(cfg, "initial_release: |\n  - CLAUDE.md\ninclude_paths:\n  - docs/**\n") == [2]


def test_flags_other_mentions_in_a_release_config() -> None:
    text = '# see CLAUDE.md "Releases"\ninclude_paths:\n  - CLAUDE.md\n'
    assert scan(".github/release-hole.yaml", text) == [1]


def test_the_include_paths_exemption_is_only_for_release_configs() -> None:
    assert scan(".github/workflows/ci.yaml", "  - CLAUDE.md\n") == [1]
    assert scan(".github/release-hole.yaml.md", "  - CLAUDE.md\n") == [1]
    assert scan("docs/release-x.yaml", "  - CLAUDE.md\n") == [1]


def test_accepts_windows_separators() -> None:
    assert scan(r".github\release-hole.yaml", "include_paths:\n  - CLAUDE.md\n") == []
    assert scan(r"crates\x\a.rs", "CLAUDE.md\n") == [1]


def test_main_prints_path_and_line_and_fails(tmp_path) -> None:
    bad = tmp_path / "a.rs"
    bad.write_text("ok\n// CLAUDE.md\n")
    r = subprocess.run([sys.executable, __file__, str(bad)], capture_output=True, text=True)
    assert r.returncode == 1
    assert r.stdout.strip().endswith("a.rs:2: refers to the agent instructions file")


def test_main_passes_on_clean_files(tmp_path) -> None:
    good = tmp_path / "a.rs"
    good.write_text("// nothing\n")
    r = subprocess.run([sys.executable, __file__, str(good)], capture_output=True, text=True)
    assert r.returncode == 0
    assert r.stdout == "" and r.stderr == ""


def test_main_reports_a_path_it_cannot_scan_on_stderr_and_scans_the_rest(tmp_path) -> None:
    good = tmp_path / "a.rs"
    good.write_text("// CLAUDE.md\n")
    missing = tmp_path / "missing"
    args = [sys.executable, __file__, str(missing), str(tmp_path), str(good)]
    r = subprocess.run(args, capture_output=True, text=True)
    assert r.returncode == 1
    assert r.stdout.strip().endswith("a.rs:1: refers to the agent instructions file")
    assert f"{posix(str(missing))}: not scanned" in r.stderr
    assert f"{posix(str(tmp_path))}: not scanned" in r.stderr


def test_main_reports_a_path_whose_stat_fails_instead_of_crashing(monkeypatch, capsys) -> None:
    def deny(self):
        raise PermissionError(5, "Access is denied")

    monkeypatch.setattr(Path, "is_file", deny)
    assert main(["crates/hole/.cache"]) == 0
    assert "crates/hole/.cache: not scanned (" in capsys.readouterr().err
