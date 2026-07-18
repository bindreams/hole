// Hole DMG installer background, rendered by `cargo xtask dmg-background`.
// Copy targets macOS 15/26 Gatekeeper wording — re-review on an OS change.
// Copy edits must be mirrored in dmg-installer/tests/test_background_copy.py (EXPECTED).
#let inp(k, d) = sys.inputs.at(k, default: d)
#let win_w = float(inp("window_w", "660")) * 1pt
#let win_h = float(inp("window_h", "560")) * 1pt
#set page(
  width: win_w, height: win_h,
  margin: (top: 232pt, x: 46pt, bottom: 34pt),
  fill: none,
  // Drag arrow (92pt × 44pt). Offset comes from layout.json's icon centers via
  // sys.inputs (default centers it in the 660-wide window), so it tracks the icons.
  foreground: place(top + left,
    dx: float(inp("arrow_dx", "284")) * 1pt, dy: float(inp("arrow_dy", "138")) * 1pt,
    polygon(fill: rgb("#86868b"),
      (0pt, 12pt), (70pt, 12pt), (70pt, 0pt), (92pt, 22pt), (70pt, 44pt), (70pt, 32pt), (0pt, 32pt))),
)
#set text(font: inp("font", "SF NS"), size: 15pt, fill: rgb("#1d1d1f"))
#set par(leading: 0.55em)

#align(center, text(size: 22pt, weight: "bold")[Hey! Listen!])
#v(10pt)
When you first open Hole, you might get this warning:
#v(4pt)
#block(inset: (left: 16pt), stroke: (left: 3pt + rgb("#0a84ff")))[
  #text(size: 14.5pt, fill: rgb("#3a3a3c"))[
    Apple could not verify ‘Hole’ is free of malware \
    that may harm your Mac or compromise your privacy.
  ]
]
#v(8pt)
#text(weight: "semibold")[Don’t panic!]
#v(4pt)
#set enum(numbering: "1.", spacing: 6pt)
#set text(size: 14.5pt)
+ Click “Done”;
+ Open #box(baseline: 20%, image("./gear.svg", height: 18pt)) Settings → #box(baseline: 20%, image("./hand.svg", height: 18pt)) Privacy & Security and scroll down;
+ Click “Open Anyway” next to Hole.
