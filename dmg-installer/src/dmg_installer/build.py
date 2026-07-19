"""Assemble the styled Hole DMG with dmgbuild.

dmgbuild writes the `.DS_Store` (icon size/positions, window, background) directly
via the ds_store library — no Finder, no osascript — so the layout is
reproducible on any runner. Run by the `hole-dmg` build.yaml target after
`npx tauri build` (app-only) and `cargo xtask dmg-background`.

Entry point: `uv run --directory dmg-installer build`.
"""

import platform
import re
import tomllib
from pathlib import Path

import dmgbuild

import dmg_installer
from dmg_installer import layout


def get_version(root: Path) -> str:
    """Hole's release version from crates/hole/Cargo.toml (mirrors msi_installer)."""
    cargo_toml = root / "crates" / "hole" / "Cargo.toml"
    with open(cargo_toml, "rb") as f:
        version = tomllib.load(f)["package"]["version"]
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        raise dmg_installer.DmgTestError(f"version in {cargo_toml} is not valid semver: {version}")
    return version


def build_dmg_at(root: Path, app: Path, dmg_path: Path, background_dir: Path | None = None) -> None:
    """Assemble the styled DMG for `app` at `dmg_path` using the shared layout.

    `background_dir` (default `<root>/.cache/dmg`) holds background.png + @2x; tests
    pass a private dir so they never share the repo-global cache.
    """
    if not app.is_dir():
        raise dmg_installer.DmgTestError(f"{app.name} not found at {app} — build the app (npx tauri build) first")
    bg_dir = background_dir or root / ".cache" / "dmg"
    background = bg_dir / "background.png"
    background_2x = bg_dir / "background@2x.png"  # dmgbuild's lookForHiDPI pairs it
    missing = [str(p) for p in (background, background_2x) if not p.is_file()]
    if missing:
        raise dmg_installer.DmgTestError(
            f"background PNG(s) missing: {missing} — run `cargo xtask dmg-background` first"
        )
    width, height = layout.WINDOW
    dmg_path.unlink(missing_ok=True)  # keep the single-.dmg invariant find_built_dmg relies on
    dmgbuild.build_dmg(
        filename=str(dmg_path),
        volume_name=layout.VOLUME_NAME,
        settings={
            "format": "UDZO",
            "files": [str(app)],
            "symlinks": {"Applications": "/Applications"},
            "hide_extensions": [layout.APP_NAME],
            "icon_size": layout.ICON_SIZE,
            "icon_locations": {
                layout.APP_NAME: layout.APP_POS,
                "Applications": layout.APPFOLDER_POS,
                ".background.tiff": layout.TIFF_POS,
            },
            "background": str(background),
            "window_rect": ((200, 120), (width, height)),
        },
    )


def main() -> None:
    root = dmg_installer._find_repo_root()

    app = root / "target" / "release" / "bundle" / "macos" / layout.APP_NAME

    arch = "aarch64" if platform.machine() == "arm64" else "x86_64"
    out_dir = root / "target" / "release" / "bundle" / "dmg"
    out_dir.mkdir(parents=True, exist_ok=True)
    dmg_path = out_dir / f"{layout.VOLUME_NAME}_{get_version(root)}_{arch}.dmg"

    build_dmg_at(root, app, dmg_path)
    print(f"built {dmg_path}")
