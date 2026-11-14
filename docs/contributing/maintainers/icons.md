# Icons

The app and tray icons are drawn as SVG, one per platform and role, and turned into raster images at build time. You edit
the SVG and never the raster.

## The sources

The SVGs are in {src}`crates/hole/icons/`: `icon-windows.svg` and `icon-macos.svg` for the app, `tray-windows-light.svg`
and `tray-windows-dark.svg` for the Windows tray (one per taskbar theme), and `tray-macos.svg`. {src}`crates/hole/build.rs`
renders them and caches the app icons in `.cache/icons/`. **Do not commit generated raster icons**: that folder is not
tracked.

`.cache/icons/icon.ico` is also what the MSI binds as `ARPPRODUCTICON`, so the entry in Add/Remove Programs shows the same
icon as the app ({src}`msi-installer/src/msi_installer/hole.wxs`).

## The tray icon

{src}`crates/hole/src/tray_icons.rs` picks the image. `TrayState::Disabled` currently gives the same image as `Enabled`:
the enum stays so a second design can be added in one place.

On macOS the tray icon is a [template image](https://developer.apple.com/documentation/appkit/nsimage/1520017-template):
only its alpha channel carries the shape (RGB is 0), and the system inverts it to match the menu bar. Two rules follow.

- **Update the icon with `set_icon_with_as_template(icon, true)`.** `TrayIcon::set_icon` passes `icon_is_template=false`
  to the system, so the first state change turns the icon solid black.
- **Do not call `set_icon` or `set_icon_as_template`**, at the tauri or the inner `tray_icon` level. Clippy bans them
  ({src}`clippy.toml`), because `set_icon_as_template` is a second, non-atomic call that can flicker or clear the flag.
