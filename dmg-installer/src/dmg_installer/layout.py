"""Single source of truth for the DMG installer window layout.

Imported by the dmgbuild builder AND the layout tests so the artifact is checked
against the same numbers that produced it — never a hand-copied second guess.
"""

APP_NAME = "Hole.app"
VOLUME_NAME = "Hole"
WINDOW = (660, 560)  # (width, height) in points
ICON_SIZE = 128  # Finder icon size in points
APP_POS = (196, 160)  # Hole.app icon center
APPFOLDER_POS = (464, 160)  # Applications symlink icon center
