"""Build a preview DMG for eyeballing the installer window.

Prefers the REAL built Hole.app (accurate custom icon) if present; otherwise a
dummy bundle, printing a caveat that the icon is not representative. Writes to
.cache/dmg-preview/ (a sibling of the background dir, NOT target/release/bundle/dmg/),
so it never collides with find_built_dmg's single-.dmg invariant.
Run: uv run --directory dmg-installer scripts/preview_dmg.py
"""

import dmg_installer
from dmg_installer import build, layout

root = dmg_installer._find_repo_root()
out_dir = root / ".cache" / "dmg-preview"
out_dir.mkdir(parents=True, exist_ok=True)

real_app = root / "target" / "release" / "bundle" / "macos" / layout.APP_NAME
if real_app.is_dir():
    app = real_app
    print(f"preview: using real {layout.APP_NAME} (accurate icon)")
else:
    app = out_dir / layout.APP_NAME
    app.mkdir(parents=True, exist_ok=True)
    (app / "placeholder").write_text("preview dummy\n")
    print(
        f"preview: CAVEAT — no built {layout.APP_NAME}; using a dummy, so the app ICON "
        "is not representative. Build the real app for final icon-alignment sign-off."
    )

out = out_dir / "Hole_preview.dmg"
build.build_dmg_at(root, app, out)  # default background dir = .cache/dmg
print(f"preview DMG: {out}")
