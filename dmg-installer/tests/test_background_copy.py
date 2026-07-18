"""Change-detection tripwire for the DMG background's instruction copy.

Asserts the exact locked strings are present, in order, in background.typ's LIVE
markup (comment lines dropped). This proves the copy is still THERE — not that the
prose is "correct". EXPECTED is a deliberate independent restatement: that
duplication IS the lock, forcing every copy change to be a conscious two-file edit;
do NOT derive it from background.typ (that would make the test tautological).
"""

import dmg_installer

TYP = dmg_installer._find_repo_root() / "crates" / "hole" / "dmg" / "background.typ"

EXPECTED = [
    "Hey! Listen!",
    "When you first open Hole, you might get this warning:",
    "Apple could not verify ‘Hole’ is free of malware",
    "that may harm your Mac or compromise your privacy.",
    "Don’t panic!",
    "Click “Done”;",
    "Open",
    "Settings →",
    "Privacy & Security and scroll down;",
    "Click “Open Anyway” next to Hole.",
]


def test_background_copy_is_verbatim() -> None:
    live = "\n".join(ln for ln in TYP.read_text(encoding="utf-8").splitlines() if not ln.lstrip().startswith("//"))
    idx = -1
    for line in EXPECTED:
        nxt = live.find(line, idx + 1)
        assert nxt > idx, f"locked copy line missing or out of order: {line!r}"
        idx = nxt
