//! Standalone shadowsocks server, plain or fronted by a server-mode plugin, for the
//! install-and-connect tests of the installed product (`tests/installed/connect_journey.py`).
//!
//! Wraps the same `ssserver` fixtures the nextest suites use. Prints one JSON line
//! describing the server (the fields a `ServerEntry` needs; `plugin_opts` only for a
//! plugin) and then serves until stdin reaches EOF, so the parent's exit ends the server.
//!
//! Usage: `ss_plugin_server <ex-ray|galoshes|none> [<outbound-interface> <its-ipv4-address> [<listen-address>]]`.
//! With an interface, the server's own dials to its targets leave through it, not through the routing table, or they
//! loop back into the tunnel of the machine it runs on. On Windows its sockets are also bound to the address, which
//! holds an IPv4 UDP relay there (`ssserver::start_real_ss_server_via`). The server, or the plugin in front of it, listens on the listen address
//! (loopback when none is given) and the description names it.

#![allow(clippy::disallowed_methods)] // dev tooling, never privileged

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr};

use plugin_e2e::locators::{locate_built_galoshes, locate_ex_ray};
use plugin_e2e::ssserver::{
    route_logs, start_real_ss_server_via, start_real_ss_server_with_plugin_ws_via, LevelFilter, OutboundInterface,
    TEST_METHOD, TEST_METHOD_STR, TEST_PASSWORD,
};
use plugin_e2e::util::{require_binary, rt};

/// Client-side options matching `WS_SERVER_OPTS` minus the `server` flag.
const WS_CLIENT_OPTS: &str = "host=cloudfront.com;path=/";

fn main() {
    // Relays the plugin chain's output to stderr, which the pytest fixture prints on failure.
    hole_test_observability::install();
    // The ss server's records too, down to `trace`: its line for each TCP relay it opens (`debug`) and for each UDP
    // datagram it relays (`trace`) is what the full-tunnel journey counts. The journey turns those targets on
    // (`HOLE_TEST_LOG`); the default filter writes `info` and above.
    route_logs(LevelFilter::Trace);

    let kind = std::env::args().nth(1).unwrap_or_default();
    let listen = match std::env::args().nth(4) {
        None => IpAddr::V4(Ipv4Addr::LOCALHOST),
        Some(listen) => listen
            .parse()
            .unwrap_or_else(|e| panic!("the listen address {listen:?} is not an IP address: {e}")),
    };
    let outbound = match (std::env::args().nth(2), std::env::args().nth(3)) {
        (None, None) => None,
        (Some(name), Some(ipv4)) => Some(OutboundInterface {
            name,
            ipv4: ipv4
                .parse()
                .unwrap_or_else(|e| panic!("the interface's address {ipv4:?} is not IPv4: {e}")),
        }),
        (name, ipv4) => panic!("the outbound interface and its address go together, got {name:?} and {ipv4:?}"),
    };
    let outbound = outbound.as_ref();
    let plugin = match kind.as_str() {
        "ex-ray" => Some((locate_ex_ray(), "run `cargo xtask ex-ray`")),
        "galoshes" => Some((locate_built_galoshes(), "run `cargo xtask galoshes`")),
        "none" => None,
        other => panic!(
            "usage: ss_plugin_server <ex-ray|galoshes|none> [<outbound-interface> <its-ipv4-address> [<listen-address>]], got {other:?}"
        ),
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
                listen,
                outbound,
            ));
            line["plugin_opts"] = WS_CLIENT_OPTS.into();
            (addr, Box::new(server))
        }
        None => {
            let (addr, server) = rt.block_on(start_real_ss_server_via(TEST_METHOD, TEST_PASSWORD, listen, outbound));
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
