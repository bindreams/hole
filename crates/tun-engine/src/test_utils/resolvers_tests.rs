use super::nameservers;

#[skuld::test]
fn only_the_nameserver_lines_are_kept_sorted_and_deduplicated() {
    let dns = "DNS configuration\n\
               \n\
               resolver #1\n\
               \x20 search domain[0] : lan\n\
               \x20 domain : nameserver.example\n\
               \x20 nameserver[1] : 9.9.9.9\n\
               \x20 nameserver[0] : 1.1.1.1\n\
               \x20 if_index : 15 (en0)\n\
               resolver #2\n\
               \x20 nameserver[0] : 1.1.1.1\n";
    assert_eq!(
        nameservers(dns),
        ["nameserver[0] : 1.1.1.1", "nameserver[1] : 9.9.9.9"],
        "the set is the distinct nameserver lines, ordered"
    );
}

#[skuld::test]
fn output_with_no_resolver_has_an_empty_set() {
    assert!(nameservers("DNS configuration (for scoped queries)\n").is_empty());
}
