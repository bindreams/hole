//! Startup banner + per-platform webview-debugging hints (dev.py parity).

use std::path::Path;

use crate::ansi::{BOLD, CYAN, MAGENTA, RESET, YELLOW};

/// Chrome DevTools Protocol port for WebView2 remote debugging (dev.py §5.16).
pub const CDP_PORT: u16 = 9222;
pub const VITE_PORT: u16 = 1420;

pub fn startup_banner(socket: &Path, state_dir: &Path, bridge_bin: &Path, gui_bin: &Path, sudo_note: &str) -> String {
    format!(
        "\n{BOLD}Starting dev environment...{RESET}\n\
         \x20 Socket:    {}\n\
         \x20 State dir: {}\n\
         \x20 {CYAN}[bridge]{RESET} {sudo_note}{} → real TUN + routing (elevated)\n\
         \x20 {MAGENTA}[client]{RESET} {} (GUI, as you)\n\
         \x20 {YELLOW}[  vite]{RESET} npm run dev → port {VITE_PORT} (as you)\n\
         \x20 Frontend changes hot-reload. Rust changes need Ctrl+C and re-run.\n",
        socket.display(),
        state_dir.display(),
        bridge_bin.display(),
        gui_bin.display(),
    )
}

pub fn webview_debug_hint() -> &'static str {
    #[cfg(windows)]
    return "\x1b[1mWebView2 remote debugging:\x1b[0m http://127.0.0.1:9222";
    #[cfg(target_os = "macos")]
    return "\x1b[1mWKWebView remote debugging:\x1b[0m Safari → Develop → Hole → Hole Dashboard";
    #[cfg(not(any(windows, target_os = "macos")))]
    return "";
}
