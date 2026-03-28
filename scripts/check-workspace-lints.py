#!/usr/bin/env python3
"""Verify all workspace members inherit workspace lints.

Ensures every crate listed in the root Cargo.toml [workspace.members] has
`[lints] workspace = true`, so workspace-level clippy lint configuration
(e.g. disallowed_methods) is not silently ignored.
"""

import sys
import tomllib
from pathlib import Path


def main() -> None:
    root_toml = Path("Cargo.toml")
    with open(root_toml, "rb") as f:
        root = tomllib.load(f)

    members = root.get("workspace", {}).get("members", [])
    if not members:
        print("error: no workspace members found in Cargo.toml", file=sys.stderr)
        sys.exit(1)

    workspace_lints = root.get("workspace", {}).get("lints", {})
    if not workspace_lints:
        # No workspace lints defined — nothing to enforce.
        return

    errors = []
    for member in members:
        cargo_path = Path(member) / "Cargo.toml"
        with open(cargo_path, "rb") as f:
            data = tomllib.load(f)

        lints = data.get("lints", {})
        if not lints.get("workspace"):
            errors.append(str(cargo_path))

    if errors:
        print("error: these crates do not inherit workspace lints:", file=sys.stderr)
        for path in errors:
            print(f"  {path}", file=sys.stderr)
        print('  hint: add `[lints]\nworkspace = true` to each Cargo.toml', file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

# Tests (run with pytest) ==============================================================================================


def test_passes_when_all_members_opt_in(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["a"]\n[workspace.lints.clippy]\nfoo = "deny"\n')
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Cargo.toml").write_text('[package]\nname = "a"\nversion = "0.1.0"\n[lints]\nworkspace = true\n')

    import subprocess

    r = subprocess.run([sys.executable, __file__], cwd=tmp_path)
    assert r.returncode == 0


def test_fails_when_member_missing_lints(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["a"]\n[workspace.lints.clippy]\nfoo = "deny"\n')
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Cargo.toml").write_text('[package]\nname = "a"\nversion = "0.1.0"\n')

    import subprocess

    r = subprocess.run([sys.executable, __file__], cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode != 0
    assert "Cargo.toml" in r.stderr and "a" in r.stderr


def test_skips_when_no_workspace_lints(tmp_path):
    (tmp_path / "Cargo.toml").write_text('[workspace]\nmembers = ["a"]\n')
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "Cargo.toml").write_text('[package]\nname = "a"\nversion = "0.1.0"\n')

    import subprocess

    r = subprocess.run([sys.executable, __file__], cwd=tmp_path)
    assert r.returncode == 0
