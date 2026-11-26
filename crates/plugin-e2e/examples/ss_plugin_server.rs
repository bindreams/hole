//! Standalone shadowsocks server, plain or fronted by a server-mode plugin, for the
//! install-and-connect tests of the installed product (`tests/installed/connect_journey.py`).
//!
//! Wraps the same `ssserver` fixtures the nextest suites use. Prints one JSON line
//! describing the server (the fields a `ServerEntry` needs; `plugin_opts` only for a
//! plugin) and then serves until stdin reaches EOF, so the parent's exit ends the server.
//!
//! Usage: `ss_plugin_server <ex-ray|galoshes|none> [outbound-interface]`. With an interface, the server's own dials to
//! its targets leave through it, not through the routing table: a server on the machine of a full tunnel needs that,
//! or its dials loop back into the tunnel.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::io::{Read, Write};

use plugin_e2e::locators::{locate_built_galoshes, locate_ex_ray};
use plugin_e2e::ssserver::{
    route_logs, start_real_ss_server_via, start_real_ss_server_with_plugin_ws_via, LevelFilter, TEST_METHOD,
    TEST_METHOD_STR, TEST_PASSWORD,
};
use plugin_e2e::util::{require_binary, rt};

/// Client-side options matching `WS_SERVER_OPTS` minus the `server` flag.
const WS_CLIENT_OPTS: &str = "host=cloudfront.com;path=/";

fn main() {
    // Relays the plugin chain's output to stderr, which the pytest fixture prints on failure.
    hole_test_observability::install();
    // The ss server's records too, down to `debug`: its line for each relay it opens is what the full-tunnel journey
    // counts. The fixture turns that target on (`HOLE_TEST_LOG`); the default filter writes `info` and above.
    route_logs(LevelFilter::Debug);

    let kind = std::env::args().nth(1).unwrap_or_default();
    let outbound_interface = std::env::args().nth(2);
    let outbound_interface = outbound_interface.as_deref();
    let plugin = match kind.as_str() {
        "ex-ray" => Some((locate_ex_ray(), "run `cargo xtask ex-ray`")),
        "galoshes" => Some((locate_built_galoshes(), "run `cargo xtask galoshes`")),
        "none" => None,
        other => panic!("usage: ss_plugin_server <ex-ray|galoshes|none> [outbound-interface], got {other:?}"),
    };

    // Keep `rt` and `_server` alive: the runtime's workers drive the server during the blocking stdin read.
    let rt = rt();
    let mut line = serde_json::json!({ "method": TEST_METHOD_STR, "password": TEST_PASSWORD });
    let (addr, _server): (_, Box<dyn std::any::Any>) = match plugin {
        Some((plugin, remedy)) => {
            require_binary(&plugin, remedy);
            let plugin = plugin.to_str().expect("plugin path is valid utf-8");
            let (addr, server) = rt.block_on(start_real_ss_server_with_plugin_ws_via(
                TEST_METHOD,
                TEST_PASSWORD,
                plugin,
                outbound_interface,
            ));
            line["plugin_opts"] = WS_CLIENT_OPTS.into();
            (addr, Box::new(server))
        }
        None => {
            let (addr, server) = rt.block_on(start_real_ss_server_via(TEST_METHOD, TEST_PASSWORD, outbound_interface));
            (addr, Box::new(server))
        }
    };
    line["server"] = addr.ip().to_string().into();
    line["server_port"] = addr.port().into();

    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "{line}").expect("write the server description");
    stdout.flush().expect("flush the server description");
    drop(stdout);

    std::io::stdin()
        .lock()
        .read_to_end(&mut Vec::new())
        .expect("read stdin");
}
