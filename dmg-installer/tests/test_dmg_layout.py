"""The built DMG must carry the layout dmgbuild was told to write.

Reads the mounted volume's `.DS_Store`. dmgbuild writes it directly (no Finder),
so this is deterministic: any drift means the builder or the shared `layout`
constants regressed. Expected values come from `dmg_installer.layout` — the same
module the builder used — so this proves "artifact matches config", not "matches
a number typed twice". Guards issue #609.
"""

import re
from pathlib import Path

import pytest
from ds_store import DSStore

from dmg_installer import layout

# icvp backgroundType: 2 == picture (confirmed against a real dmgbuild output).
BACKGROUND_PICTURE = 2


def _read_ds_store(mount: Path) -> tuple[dict, dict | None, dict | None]:
    ds = mount / ".DS_Store"
    if not ds.exists():
        pytest.fail("no .DS_Store on the volume — DMG layout was not written")
    positions: dict[str, tuple[int, int]] = {}
    icvp = bwsp = None
    store = DSStore.open(str(ds), "r")
    try:
        for e in store:
            if e.code == b"Iloc":
                positions[e.filename] = e.value  # (x, y)
            elif e.code == b"icvp":
                icvp = e.value  # dict
            elif e.code == b"bwsp":
                bwsp = e.value  # dict
    finally:
        store.close()
    return positions, icvp, bwsp


def test_icon_size_and_background(mounted_dmg: Path) -> None:
    _, icvp, _ = _read_ds_store(mounted_dmg)
    assert icvp is not None, "no icon-view settings (icvp) in .DS_Store"
    assert icvp["iconSize"] == layout.ICON_SIZE, f"iconSize {icvp['iconSize']} != {layout.ICON_SIZE}"
    assert icvp.get("backgroundType") == BACKGROUND_PICTURE, "no picture background set on the DMG window"
    # dmgbuild combines background.png + background@2x.png into a HiDPI .background.tiff
    assert (mounted_dmg / ".background.tiff").is_file(), "no .background.tiff on the volume"


def test_icon_positions(mounted_dmg: Path) -> None:
    positions, _, _ = _read_ds_store(mounted_dmg)
    assert positions.get(
        layout.APP_NAME
    ) == layout.APP_POS, (f"{layout.APP_NAME} at {positions.get(layout.APP_NAME)} != {layout.APP_POS}")
    assert positions.get("Applications") == layout.APPFOLDER_POS, (
        f"Applications at {positions.get('Applications')} != {layout.APPFOLDER_POS}"
    )


def test_window_size(mounted_dmg: Path) -> None:
    _, _, bwsp = _read_ds_store(mounted_dmg)
    assert bwsp is not None, "no window settings (bwsp) in .DS_Store"
    # WindowBounds is a string like "{{x, y}, {w, h}}".
    nums = [int(n) for n in re.findall(r"-?\d+", bwsp["WindowBounds"])]
    assert (nums[2], nums[3]) == layout.WINDOW, f"window {nums[2]}x{nums[3]} != {layout.WINDOW}"


def test_background_tiff_parked_offscreen(mounted_dmg: Path) -> None:
    positions, _, _ = _read_ds_store(mounted_dmg)
    assert positions.get(".background.tiff") == layout.TIFF_POS, (
        f".background.tiff at {positions.get('.background.tiff')} != {layout.TIFF_POS}"
    )
