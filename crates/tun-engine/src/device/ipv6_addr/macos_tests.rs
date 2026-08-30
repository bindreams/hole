//! Unprivileged unit test for the macOS argv shape. It is the only piece of
//! the macOS path a test can reach today — see the module doc for why the rest
//! is unreachable and why the path is warn-only because of it.

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
