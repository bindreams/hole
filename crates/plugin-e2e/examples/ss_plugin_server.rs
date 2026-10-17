//! Standalone shadowsocks server fronted by a server-mode plugin, for the macOS
//! install-and-connect e2e (`dmg-installer/tests/test_install_connect.py`).
//!
//! Wraps the same `ssserver` fixture the nextest suites use. Prints one JSON line
//! describing the server (the fields a `ServerEntry` needs) and then serves until
//! stdin reaches EOF, so the parent's exit ends the server.
//!
//! Usage: `ss_plugin_server <ex-ray|galoshes>`

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::io::{Read, Write};

use plugin_e2e::locators::{locate_built_galoshes, locate_ex_ray};
use plugin_e2e::ssserver::{start_real_ss_server_with_plugin_ws, TEST_METHOD, TEST_METHOD_STR, TEST_PASSWORD};
use plugin_e2e::util::{require_binary, rt};

/// Client-side options matching `WS_SERVER_OPTS` minus the `server` flag.
const WS_CLIENT_OPTS: &str = "host=cloudfront.com;path=/";

fn main() {
    let kind = std::env::args().nth(1).unwrap_or_default();
    let (plugin, remedy) = match kind.as_str() {
        "ex-ray" => (locate_ex_ray(), "run `cargo xtask ex-ray`"),
        "galoshes" => (locate_built_galoshes(), "run `cargo xtask galoshes`"),
        other => panic!("usage: ss_plugin_server <ex-ray|galoshes>, got {other:?}"),
    };
    require_binary(&plugin, remedy);
    let plugin = plugin.to_str().expect("plugin path is valid utf-8");

    // The runtime stays alive across the blocking stdin read below: its workers
    // keep driving the server and the plugin chain.
    let rt = rt();
    let (addr, _server) = rt.block_on(start_real_ss_server_with_plugin_ws(TEST_METHOD, TEST_PASSWORD, plugin));

    let line = serde_json::json!({
        "server": addr.ip().to_string(),
        "server_port": addr.port(),
        "method": TEST_METHOD_STR,
        "password": TEST_PASSWORD,
        "plugin_opts": WS_CLIENT_OPTS,
    });
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{line}").expect("write the server description");
    stdout.flush().expect("flush the server description");
    drop(stdout);

    std::io::stdin()
        .lock()
        .read_to_end(&mut Vec::new())
        .expect("read stdin");
}
