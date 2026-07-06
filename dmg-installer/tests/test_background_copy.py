"""The DMG background art must carry the verbatim-locked instruction copy.

Parses background.svg's <text> nodes in document order and asserts the exact
locked strings (incl. terminal punctuation) appear in order. A dropped semicolon
or a later art edit that changes wording fails here — no human eyeballing the
rendered PNG required. Cheap, deterministic, no render/font.
"""

import re
from pathlib import Path
from xml.etree import ElementTree as ET

import dmg_installer

SVG = dmg_installer._find_repo_root() / "crates" / "hole" / "dmg" / "background.svg"
NS = "{http://www.w3.org/2000/svg}"

# Must appear in this order among the SVG text runs (whitespace normalized).
# Step 2 is split around the Settings/Privacy glyphs, so it is three fragments.
EXPECTED = [
    "Hey! Listen!",
    "When you first open Hole, you might get this warning:",
    "Apple could not verify ‘Hole’ is free of malware",
    "that may harm your Mac or compromise your privacy.",
    "Don’t panic!",
    "1. Click “Done”;",
    "Open",
    "Settings →",
    "Privacy & Security and scroll down;",
    "3. Click “Open Anyway” next to Hole.",
]


def _texts(svg: Path) -> list[str]:
    root = ET.fromstring(svg.read_text(encoding="utf-8"))
    return [re.sub(r"\s+", " ", "".join(t.itertext())).strip() for t in root.iter(f"{NS}text")]


def test_background_copy_is_verbatim() -> None:
    texts = _texts(SVG)
    haystack = " ␟ ".join(texts)  # unit-separator join keeps order checkable
    idx = -1
    for line in EXPECTED:
        nxt = haystack.find(line, idx + 1)
        assert nxt > idx, f"locked copy line missing or out of order: {line!r}\ngot: {texts}"
        idx = nxt
