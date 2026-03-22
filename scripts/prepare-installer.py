# /// script
# requires-python = ">=3.10"
# ///

"""Prepare installer staging directory for `cargo wix`.

Called as the `before` hook by cargo-wix. Builds all crates (triggering
build.rs which builds v2ray-plugin and downloads wintun), then stages
the built binaries into a directory for WiX.

Environment variables (set by cargo-wix):
    WIX_TARGET_DIR     — Cargo target directory
    WIX_WORKSPACE_ROOT — Workspace root
"""

import os
import shutil
import subprocess
import sys
from pathlib import Path


def main() -> None:
    target_dir = Path(os.environ["WIX_TARGET_DIR"])
    release_dir = target_dir / "release"
    stage = release_dir / "installer-stage"

    # Build =====

    print("==> Building release binaries...", file=sys.stderr)
    result = subprocess.run(["cargo", "build", "--release", "--workspace"])
    if result.returncode != 0:
        print("cargo build failed", file=sys.stderr)
        sys.exit(1)

    # Stage =====

    stage.mkdir(parents=True, exist_ok=True)
    print(f"==> Staging installer files to {stage}", file=sys.stderr)

    # hole.exe — main binary
    link_or_copy(release_dir / "hole.exe", stage / "hole.exe")

    # v2ray-plugin.exe — built by crates/gui/build.rs
    v2ray_dir = Path(".cache/gui/v2ray-plugin")
    candidates = list(v2ray_dir.glob("v2ray-plugin-*.exe"))
    if len(candidates) == 0:
        print(f"error: no v2ray-plugin binary found in {v2ray_dir}", file=sys.stderr)
        sys.exit(1)
    if len(candidates) > 1:
        print(
            f"error: multiple v2ray-plugin binaries in {v2ray_dir}: {candidates}",
            file=sys.stderr,
        )
        sys.exit(1)
    link_or_copy(candidates[0], stage / "v2ray-plugin.exe")

    # wintun.dll — downloaded by crates/gui/build.rs
    link_or_copy(Path(".cache/gui/wintun/wintun.dll"), stage / "wintun.dll")

    print("==> Staging complete", file=sys.stderr)


def link_or_copy(src: Path, dst: Path) -> None:
    dst.unlink(missing_ok=True)
    try:
        os.link(src, dst)
        print(f"  {dst.name} (hardlinked)", file=sys.stderr)
    except OSError:
        shutil.copy2(src, dst)
        print(f"  {dst.name} (copied)", file=sys.stderr)


if __name__ == "__main__":
    main()
