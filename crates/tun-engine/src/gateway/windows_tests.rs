use super::*;
use crate::GLOBAL_NET_STATE;
use std::net::{IpAddr, Ipv4Addr};
use windows::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_HOST_UNREACHABLE, ERROR_INVALID_NETNAME, ERROR_INVALID_PARAMETER,
    ERROR_NETWORK_UNREACHABLE, ERROR_NOT_FOUND,
};

// Oracle ==============================================================================================================

/// The route object `Find-NetRoute` reports for a destination.
struct OracleRoute {
    if_index: u32,
    next_hop: String,
}

/// Ask Windows itself where a destination routes.
///
/// `Find-NetRoute` is the cmdlet wrapper over the OS's own best-route lookup, so
/// it is an independent *implementation* of the selection rather than a
/// reimplementation of the *policy* — sorting `Get-NetRoute` by metric in
/// PowerShell would be the latter, and reimplementing route selection outside
/// the OS is the mistake bindreams/hole#798 is made of. It proves we read the
/// right fields off the right row; it cannot prove the selection itself.
///
/// It emits TWO objects: the source `NetIPAddress` (no `DestinationPrefix`) and
/// the `NetRoute`. Taking `[0]` would silently take the wrong one, so the route
/// is identified by having a `DestinationPrefix`.
fn find_net_route(dest: &str) -> Option<OracleRoute> {
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         try {{ Find-NetRoute -RemoteIPAddress {dest} | \
         Select-Object ifIndex,NextHop,DestinationPrefix | ConvertTo-Json -Depth 4 }} \
         catch {{ '[]' }}"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .expect("powershell must be runnable");
    let stdout = String::from_utf8_lossy(&out.stdout);
    let parsed: serde_json::Value = serde_json::from_str(stdout.trim()).unwrap_or(serde_json::Value::Null);

    // A single result comes back as an object, several as an array.
    let rows: Vec<&serde_json::Value> = match &parsed {
        serde_json::Value::Array(a) => a.iter().collect(),
        serde_json::Value::Object(_) => vec![&parsed],
        _ => vec![],
    };
    rows.into_iter()
        .find(|r| !r["DestinationPrefix"].is_null())
        .map(|r| OracleRoute {
            if_index: r["ifIndex"].as_u64().expect("ifIndex is a number") as u32,
            next_hop: r["NextHop"].as_str().unwrap_or("0.0.0.0").to_string(),
        })
}

fn get_netadapter_name(if_index: u32) -> Option<String> {
    let script = format!(
        "$ErrorActionPreference='Stop'; \
         try {{ (Get-NetAdapter -IncludeHidden -InterfaceIndex {if_index}).Name }} catch {{ '' }}"
    );
    let out = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &script])
        .output()
        .expect("powershell must be runnable");
    let name = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!name.is_empty()).then_some(name)
}

// Error mapping =======================================================================================================

/// The three-way split is the whole point: a reachability answer must not
/// render as "Could not read the system routing table". `GetBestRoute2` really
/// does return all of these — `ERROR_HOST_UNREACHABLE` for a destination with no
/// path, `ERROR_NOT_FOUND` for a family with no routes at all.
#[skuld::test]
fn map_query_error_separates_reachability_from_query_failure() {
    for code in [ERROR_NETWORK_UNREACHABLE, ERROR_HOST_UNREACHABLE, ERROR_NOT_FOUND] {
        assert!(
            map_query_error(code.0).is_none(),
            "{code:?} is a reachability answer, not a query failure"
        );
    }

    for code in [ERROR_INVALID_PARAMETER, ERROR_INVALID_NETNAME, ERROR_ACCESS_DENIED] {
        let mapped = map_query_error(code.0).unwrap_or_else(|| panic!("{code:?} must map to an error"));
        assert!(
            matches!(mapped, GatewayError::RouteQueryFailed { code: c, .. } if c == code.0),
            "{code:?} must carry its raw code for bridge.log, got {mapped:?}"
        );
    }

    // An unlisted code falls through to the query-failure bucket: a real
    // diagnostic beats a wrong reassurance, and `code` keeps it identifiable.
    let mapped = map_query_error(0xDEAD).expect("an unanticipated code is a query failure");
    assert!(matches!(mapped, GatewayError::RouteQueryFailed { code: 0xDEAD, .. }));
}

// Real-OS agreement ===================================================================================================

/// Asserted for BOTH a routable address and `0.0.0.0` — the latter is the value
/// production actually queries (`get_default_gateway_info`), so the load-bearing
/// assumption is exercised rather than assumed.
///
/// `gateway_global_net_state_` prefix + `GLOBAL_NET_STATE`: reads the REAL
/// host routing table twice (once through `best_route`, once — after a
/// `powershell` cold start — through `Find-NetRoute`), with nothing holding
/// it still in between. Unserialized, a concurrent elevated-lane test in
/// another binary that installs/removes `hole-tun`'s split routes could
/// change the answer between the two reads and fail this test for a reason
/// that has nothing to do with `best_route` itself.
#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn gateway_global_net_state_best_route_agrees_with_find_netroute() {
    // `find_net_route`'s script catches every PowerShell terminating error —
    // "no route" (a real answer) alike with "Find-NetRoute unavailable" or
    // any other cmdlet fault (not a real answer) — as the same `[]`. Both
    // `1.1.1.1` and `0.0.0.0` resolve to a route on any healthy host, so if
    // the oracle never once returns `Some` across both, that is the oracle
    // failing to answer, not two hosts genuinely lacking any route.
    let mut oracle_answered = 0usize;
    for dest_str in ["1.1.1.1", "0.0.0.0"] {
        let dest: IpAddr = dest_str.parse().unwrap();
        let ours = best_route(dest).expect("route lookup must not fail on a healthy host");

        match find_net_route(dest_str) {
            None => assert!(
                ours.is_none(),
                "oracle found no route to {dest_str} but best_route returned {ours:?}"
            ),
            Some(oracle) => {
                oracle_answered += 1;
                let hop = ours.unwrap_or_else(|| panic!("oracle found a route to {dest_str}, best_route did not"));
                assert_eq!(
                    hop.interface_index, oracle.if_index,
                    "interface index disagrees for {dest_str}"
                );
                assert_eq!(
                    hop.next_hop.to_string(),
                    oracle.next_hop,
                    "next hop disagrees for {dest_str}"
                );
            }
        }
    }
    assert!(
        oracle_answered > 0,
        "Find-NetRoute never returned a real route for either destination — the oracle is broken, not this host"
    );
}

/// The alias is not cosmetic: it is the adapter token in `netsh interface ip
/// add route`, the alias the system-DNS capture keys on, and the value crash
/// recovery replays out of `bridge-routes.json`. A silent change there breaks
/// three subsystems at once.
///
/// `gateway_global_net_state_` prefix + `GLOBAL_NET_STATE`: reads the REAL
/// host routing table, same race as
/// `gateway_global_net_state_best_route_agrees_with_find_netroute` above —
/// see that test's doc.
#[skuld::test(labels = [GLOBAL_NET_STATE])]
fn gateway_global_net_state_interface_alias_matches_get_netadapter_name() {
    let mut checked = 0usize;
    if let Some(hop) = best_route(IpAddr::V4(Ipv4Addr::UNSPECIFIED)).expect("lookup must not fail") {
        // Skipped when the upstream is not a Get-NetAdapter object (e.g. a
        // loopback/tunnel pseudo-interface) — nothing independent to compare
        // against.
        if let Some(expected) = get_netadapter_name(hop.interface_index) {
            assert_eq!(hop.interface_alias, expected);
            checked += 1;
        }
    }
    // Both `if let`s above are real skip conditions on SOME hosts, but this
    // box (and every unprivileged CI runner) always has a default route
    // through a real NIC — if neither ever ran, the oracle query broke, not
    // the environment.
    assert!(
        checked > 0,
        "no default route through a real NIC was found to compare against — the oracle is broken, not this host"
    );
}
