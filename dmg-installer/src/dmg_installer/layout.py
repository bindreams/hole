"""Single source of truth for the DMG installer window layout.

Geometry lives in crates/hole/dmg/layout.json so the Rust renderer/tests and this
Python builder read ONE source; no coordinate is restated across the boundary.
"""

import json
from pathlib import Path

_GEO = json.loads((Path(__file__).resolve().parents[3] / "crates/hole/dmg/layout.json").read_text())

APP_NAME = "Hole.app"
VOLUME_NAME = "Hole"
WINDOW = tuple(_GEO["window"])  # (width, height) in points
ICON_SIZE = _GEO["icon_size"]
APP_POS = tuple(_GEO["app_pos"])
APPFOLDER_POS = tuple(_GEO["appfolder_pos"])
# `.background.tiff` (dmgbuild's hidden HiDPI background) parked below the window,
# derived from WINDOW height so a window-size change can't strand it on-screen.
TIFF_POS = (WINDOW[0] // 2, WINDOW[1] + 640)
