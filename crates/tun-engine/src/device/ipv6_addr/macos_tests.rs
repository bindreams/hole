//! Unprivileged unit tests for the macOS path's pure logic — the argv shape,
//! and the network-address arithmetic behind [`prefix_route_interface`]'s
//! probe-address choice. See the module doc for why the rest (the actual
//! `ifconfig`/`route` shell-outs) is unreachable without root and why the
//! path is warn-only because of it.

use std::net::Ipv6Addr;

use super::*;

#[skuld::test]
fn ifconfig_alias_argv_names_the_interface_address_and_prefix() {
    let cidr: Ipv6Cidr = "fdf8:f6d5:536e::1/64".parse().unwrap();
    let argv = ifconfig_alias_argv("utun7", cidr);

    assert_eq!(
        argv.iter().map(String::as_str).collect::<Vec<_>>(),
        [
            "ifconfig",
            "utun7",
            "inet6",
            "fdf8:f6d5:536e::1",
            "prefixlen",
            "64",
            "alias"
        ],
        "the address carries no prefix suffix and the prefix length is its own argument"
    );
}

#[skuld::test]
fn network_address_clears_only_the_host_bits() {
    assert_eq!(
        network_address("fdf8:f6d5:536e::1".parse().unwrap(), 64),
        "fdf8:f6d5:536e::".parse::<Ipv6Addr>().unwrap(),
        "TUN_SUBNET6's own shape: a /64 clears everything past the third hextet"
    );
    assert_eq!(
        network_address("fdf8:f6d5:536e::1".parse().unwrap(), 0),
        "::".parse::<Ipv6Addr>().unwrap(),
        "prefix_len 0 clears every bit, matching Cidr::contains_addr's own shortcut for it"
    );
    assert_eq!(
        network_address("fdf8:f6d5:536e::1".parse().unwrap(), 128),
        "fdf8:f6d5:536e::1".parse::<Ipv6Addr>().unwrap(),
        "prefix_len 128 clears no bits — the network address is the address"
    );
}

#[skuld::test]
fn probe_address_for_is_never_the_configured_address() {
    let cidr: Ipv6Cidr = "fdf8:f6d5:536e::1/64".parse().unwrap();
    assert_eq!(
        probe_address_for(cidr),
        "fdf8:f6d5:536e::".parse::<Ipv6Addr>().unwrap(),
        "the ordinary case: the network address already differs from the configured one"
    );
}

#[skuld::test]
fn probe_address_for_falls_back_when_the_configured_address_has_no_host_part() {
    // A configured address whose host part is already all-zero — the one
    // case `network_address` alone would return the SAME address `assign`
    // just aliased, which `prefix_route_interface`'s doc explains is
    // useless to probe (it would always resolve via the host-scope local
    // route, present or not the wider prefix route is).
    let cidr: Ipv6Cidr = "fdf8:f6d5:536e::/64".parse().unwrap();
    let probe = probe_address_for(cidr);

    assert_ne!(
        probe,
        cidr.address(),
        "must never probe the address assign() just configured"
    );
    assert!(
        cidr.contains_addr(&probe),
        "the fallback must still land inside the prefix it's meant to probe, got {probe}"
    );
}
