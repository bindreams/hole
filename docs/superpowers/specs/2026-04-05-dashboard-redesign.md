# Dashboard UI Redesign

## Context

The current Hole dashboard is a plain 600x400 window with a flat HTML table of servers, a single SOCKS5 port field, and a basic Connect/Disconnect button. Users have complained that when their ISP drops, they blame the VPN — there is no diagnostic visibility. There are no connection stats, no IP display, and no traffic filtering controls. The window is too small and the design is visually dated.

This redesign replaces the dashboard with a modern, dark-themed (with light option) 800x600 window that surfaces real-time connection data, diagnostics, and traffic filtering controls.

## Window and Layout

- **Size**: 800x600 minimum, resizable vertically only (fixed width 800px)
- **Layout**: Two-panel — scrollable main area (left), fixed sidebar (right, 220px)
- **Fonts**: Inter (UI text), Fira Code (addresses, stats values, port numbers, version)
- **Theming**: CSS custom properties on `[data-theme]` with `color-scheme: light dark`. Dark by default, Light available, System option follows OS preference. No hacks — all colors via `--var` tokens

## Right Sidebar

Top to bottom:

### Status Header

- Round 40px power button: green when connected (with glow), red when disconnected
- "You are **Connected**" / "You are **Disconnected**" — only the status word is colored
- Subtitle line: country badge (`DE` text, not emoji — emoji flags don't render on Windows) + public IP address
  - When connected: VPN exit IP
  - When disconnected: ISP-provided IP (always visible, no layout shift)
- Copy-to-clipboard icon appears on hover, positioned immediately after the IP text

### Throughput Graph

- Stretches edge-to-edge within the sidebar (negative margin bleed, no frame/box)
- Two lines: download (green) and upload (amber), with filled area beneath each
- Y-axis: single label above the graph showing the current scale (e.g. "68 Mbps")
- X-axis: "1m ago" on left, "now" on right
- Horizontal midpoint gridline (dashed, very subtle)
- Rolling 60-second window, updated live

### Stats Table

- Key-value pairs, keys left-aligned (muted), values right-aligned (Fira Code):
  - Downloaded / Uploaded (cumulative, current session)
  - Download speed (green, matching graph) / Upload speed (amber, matching graph)
  - Uptime

### Diagnostics Chain (below a full-width divider)

- Label: "DIAGNOSTICS" (uppercase, small)
- 5 nodes vertically: App > Daemon > Network > VPN Server > Internet
- Each node: 14px colored circle + label to the right
- Connected by 2px vertical wires
- States: green (ok), red (error), gray (unknown/unreachable)
- Logic: if a node fails, all downstream nodes go gray
- The chain sticks to the top of its area (does not float to the bottom)

### Version Footer

- "Hole v{version}" centered, small, Fira Code, at very bottom of sidebar
- Separated by a full-width border

## Main Area (Scrollable Sections)

Three collapsible sections, each with a clickable header (uppercase label + triangle icon). Sections collapse/expand with a slide animation (content slides up behind the header divider line, not just fades). Triangle rotates between pointing-down (expanded) and pointing-right (collapsed).

### 1. Servers

List of server cards, each showing:

- Radio button (selected server highlighted with accent color border + background)
- Server name
- Address (Fira Code)
- Plugin badge if applicable (e.g. "v2ray" in a small colored badge)
- Delete cross icon (right-aligned, appears same style as filter table crosses)

Below the server list: a dashed-border "Import servers from file" zone (click to open file picker). Same visual weight as the filter table's "+ Add rule" zone.

### 2. Filters

A rules table for domain/IP traffic filtering. Rules are evaluated top-to-bottom; later rules override earlier ones (like .gitignore without calling it that).

**Table structure** (`table-layout: fixed` with `<colgroup>`):

| Column   | Width | Content                               |
| -------- | ----- | ------------------------------------- |
| Address  | ~48%  | Drag handle (⠿) + address (Fira Code) |
| Matching | ~22%  | Rule type                             |
| Action   | ~22%  | Proxy / Bypass / Block                |
| Delete   | ~8%   | Cross icon                            |

**Visual style:**

- Traditional table with vertical column border lines
- Action cell has a full-cell color wash: green tint for Proxy, amber for Bypass, red for Block, with matching colored bold text
- Compact rows (small padding)

**Default rule:** The topmost `*` wildcard → Proxy rule is not editable, not deletable, and not draggable. Other rules cannot be moved above it.

**In-place editing** (no separate edit mode or edit button):

- Click an address cell → inline text input (bottom-border only, no box, no height change)
- Click a matching/action cell → inline dropdown appears below the cell. Click again to close (toggle behavior). Chevron icon visible on hover to hint at interactivity
- Escape cancels address edit, Enter/blur commits

**Drag reorder:**

- Grab the ⠿ handle to drag
- The dragged row lifts out with a solid background + shadow (no browser ghost image — use pointer events, not HTML drag API)
- Other rows animate smoothly to make space (FLIP animation: snapshot positions, calculate delta, animate translateY over ~250ms)
- Placeholder shows an accent-colored border where the row will land

**Matching types:**

- `exactly` — exact string match
- `with subdomains` — matches domain and all subdomains
- `wildcard` — glob pattern (`*` matches any)
- `subnet` — CIDR notation for IP ranges (e.g. `192.168.0.0/16`)

**Actions:**

- `Proxy` — route through VPN
- `Bypass` — direct connection, skip VPN
- `Block` — drop the connection

Below the table:

- "+ Add rule" dashed zone
- **Test filtering** subsection: text input where the user types a domain or IP, and the UI instantly shows which action would apply and which rule matched it. Hint text: "Rules are evaluated top-to-bottom. Later rules override earlier ones."

### 3. Settings

Settings displayed as label + control rows (label left, control right via `margin-left: auto`). Compact vertical gaps.

**General settings:**

- **Start Hole on login** — toggle switch
- **On startup** — custom dropdown: "Do not connect" / "Restore last state" / "Always connect"
- **Theme** — custom dropdown: "Light" / "Dark" / "System" (functional — switches theme live)

**Divider line**

**Proxy server settings:**

- **Local proxy server** — toggle switch (master enable)
- Nested (indented ~1.5rem), muted at 40% opacity when master toggle is off (but still interactive):
  - **SOCKS5** — toggle switch
  - **HTTP** — toggle switch
  - **Serving port** — numeric input (Fira Code), 70px width

**Custom dropdowns** (not native `<select>`):

- Styled button with rounded corners and chevron
- Dropdown menu appears below with matching border-radius, subtle shadow
- Options highlight on hover with theme-appropriate color
- Selected option shown in accent color
- Click outside or click the button again to dismiss

**Toggle switches:**

- 36x20px, rounded pill shape
- Off: gray track, white knob left
- On: green track, white knob right
- Knob centered vertically with `transform: translateY(-50%)`
- Smooth 200ms transition

## New Backend Requirements

The current daemon API provides only `running`, `uptime_secs`, and `error`. The redesign requires new data:

### New API Endpoints (daemon)

**`GET /v1/metrics`** — Connection statistics

```json
{
  "bytes_in": 1331234816,
  "bytes_out": 356515840,
  "speed_in_bps": 44040192,
  "speed_out_bps": 8699084,
  "uptime_secs": 8040
}
```

**`GET /v1/diagnostics`** — Health check chain

```json
{
  "app": "ok",
  "daemon": "ok",
  "network": "ok",
  "vpn_server": "ok",
  "internet": "ok"
}
```

Each field is `"ok"`, `"error"`, or `"unknown"`. If a node is in error, all downstream nodes should report `"unknown"`.

**`GET /v1/public-ip`** — Current public IP

```json
{
  "ip": "185.x.x.42",
  "country_code": "DE"
}
```

Called on connect/disconnect, cached with periodic refresh (~60s). Use an external service (e.g. ip-api.com, ipify.org).

### New Tauri Commands

- `get_metrics()` → wraps `/v1/metrics`
- `get_diagnostics()` → wraps `/v1/diagnostics`
- `get_public_ip()` → when connected, wraps `/v1/public-ip` (daemon fetches through VPN). When disconnected, the GUI fetches directly from an external IP service (daemon is not running)

### New Config Fields

The filter rules and new settings need to be persisted in `AppConfig`:

```rust
pub struct FilterRule {
    pub address: String,
    pub matching: MatchType,  // Exactly, WithSubdomains, Wildcard, Subnet
    pub action: FilterAction, // Proxy, Bypass, Block
}

// New fields on AppConfig:
pub filters: Vec<FilterRule>,
pub start_on_login: bool,
pub on_startup: StartupBehavior,  // DoNotConnect, RestoreLastState, AlwaysConnect
pub theme: Theme,                 // Light, Dark, System
pub proxy_server_enabled: bool,
pub proxy_socks5: bool,
pub proxy_http: bool,
// proxy_port: reuses existing `local_port` field
```

## Verification

1. **Visual**: Open the dashboard — dark theme by default, all sections visible, sidebar shows connection state
1. **Theme switching**: Change theme in Settings → UI updates live, persists across restarts
1. **Server management**: Select servers, delete, import from file — all work
1. **Filter rules**: Add, edit in-place, reorder by drag, delete, test filtering — all work
1. **Diagnostics**: Disconnect network → Network node goes red, VPN Server and Internet go gray
1. **Stats**: Connect to a server → graph animates, stats update live
1. **IP display**: Shows VPN IP when connected, ISP IP when disconnected, country badge correct
1. **Settings**: All toggles and dropdowns persist, proxy nesting mutes correctly
1. **Resize**: Window resizes gracefully, main area scrolls, sidebar stays fixed width

## Reference

- **Reference implementation**: `docs/superpowers/specs/2026-04-05-dashboard-mockup.html` — the final prototype (v11) with CSS theme tokens, layout, and interaction JS. Open directly in a browser. Some interactions have prototype bugs (dropdown toggle, drag after collapse) — treat as visual/structural reference, not production code.
- Prototype iteration history: `.superpowers/brainstorm/` (v7-v11 are most current)
- Current UI files: `ui/index.html`, `ui/style.css`, `ui/main.js`
- Tauri config: `crates/gui/tauri.conf.json`
- Tray/window code: `crates/gui/src/tray.rs`
- Tauri commands: `crates/gui/src/commands.rs`
- Daemon API spec: `crates/common/api/openapi.yaml`
- Daemon proxy manager: `crates/daemon/src/proxy_manager.rs`
- Daemon IPC handlers: `crates/daemon/src/ipc.rs`
- Config types: `crates/common/src/config.rs`
- Protocol types: `crates/common/src/protocol.rs`
