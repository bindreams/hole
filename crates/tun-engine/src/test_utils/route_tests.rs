use super::netstat_dest;

/// `netstat -rn` drops trailing zero octets, so the guard that searches its
/// output must derive its needle from the prefix the test installs — a
/// hardcoded literal goes stale the moment the prefix changes, and the
/// pre-existence guard then silently matches nothing.
#[skuld::test]
fn netstat_dest_drops_trailing_zero_octets() {
    assert_eq!(netstat_dest("198.51.100.0/24"), "198.51.100");
    assert_eq!(netstat_dest("203.0.113.0/24"), "203.0.113");
    assert_eq!(netstat_dest("10.0.0.0/8"), "10");
}

#[skuld::test]
fn netstat_dest_keeps_significant_octets() {
    assert_eq!(netstat_dest("198.51.100.7/32"), "198.51.100.7");
    assert_eq!(netstat_dest("192.168.10.0/23"), "192.168.10");
    assert_eq!(netstat_dest("8.8.8.8"), "8.8.8.8");
}

/// A destination that is all zeros keeps one octet rather than emptying out —
/// an empty needle would match every line of the routing table.
#[skuld::test]
fn netstat_dest_never_empties() {
    assert_eq!(netstat_dest("0.0.0.0/0"), "0");
}
