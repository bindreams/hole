"""layout.py must parse layout.json into the expected geometry.

test_config.py never imports layout, so a broken layout.json (typo, wrong
parents[] index, list-vs-tuple) would otherwise surface only in the
DMG-dependent layout tests. This is the direct unit guard.
"""

from dmg_installer import layout


def test_layout_is_expected_geometry() -> None:
    # Hand-picked canonical geometry (a deliberate tripwire, independent of
    # layout.json's own parse): catches a wrong value in layout.json OR a mis-parse
    # in layout.py (e.g. list instead of tuple). Update deliberately if geometry changes.
    assert layout.WINDOW == (660, 560)
    assert layout.ICON_SIZE == 128
    assert layout.APP_POS == (196, 128)
    assert layout.APPFOLDER_POS == (464, 128)


def test_tiff_pos_is_off_window() -> None:
    assert layout.TIFF_POS[1] > layout.WINDOW[1]
