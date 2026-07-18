"""layout.py must parse layout.json into the expected geometry.

test_config.py never imports layout, so a broken layout.json (typo, wrong
parents[] index, list-vs-tuple) would otherwise surface only in the
DMG-dependent layout tests. This is the direct unit guard.
"""

import json
from pathlib import Path

from dmg_installer import layout


def test_layout_matches_json() -> None:
    geo = json.loads((Path(layout.__file__).resolve().parents[3] / "crates/hole/dmg/layout.json").read_text())
    assert layout.WINDOW == tuple(geo["window"])
    assert layout.ICON_SIZE == geo["icon_size"]
    assert layout.APP_POS == tuple(geo["app_pos"])
    assert layout.APPFOLDER_POS == tuple(geo["appfolder_pos"])


def test_tiff_pos_is_off_window() -> None:
    assert layout.TIFF_POS[1] > layout.WINDOW[1]
