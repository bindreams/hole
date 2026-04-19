#[cfg(any(target_os = "windows", target_os = "macos"))]
use crate::dns_state::DnsPrior;
#[cfg(any(target_os = "windows", target_os = "macos"))]
use std::net::{IpAddr, Ipv4Addr};

#[cfg(target_os = "windows")]
use std::net::Ipv6Addr;

// Windows parser tests ================================================================================================

#[cfg(target_os = "windows")]
mod windows_parsers {
    use super::{DnsPrior, IpAddr, Ipv4Addr, Ipv6Addr};
    use crate::dns::system::windows::parse_netsh_dnsservers;

    #[skuld::test]
    fn parse_static_single() {
        let out = "
Configuration for interface \"Ethernet\"
    Statically Configured DNS Servers:  1.1.1.1
    Register with which suffix:         Primary only
";
        let p = parse_netsh_dnsservers(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(servers, vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))]);
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[skuld::test]
    fn parse_static_multiple() {
        let out = "
Configuration for interface \"Ethernet\"
    Statically Configured DNS Servers:  1.1.1.1
                                        8.8.8.8
                                        9.9.9.9
    Register with which suffix:         Primary only
";
        let p = parse_netsh_dnsservers(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(
                    servers,
                    vec![
                        IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                        IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)),
                    ]
                );
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }

    #[skuld::test]
    fn parse_dhcp_with_ip() {
        let out = "
Configuration for interface \"Ethernet\"
    DNS servers configured through DHCP:  192.168.1.1
    Register with which suffix:           Primary only
";
        let p = parse_netsh_dnsservers(out);
        assert!(matches!(p, DnsPrior::Dhcp));
    }

    #[skuld::test]
    fn parse_dhcp_none() {
        let out = "
Configuration for interface \"Wi-Fi\"
    DNS servers configured through DHCP:  None
    Register with which suffix:           Primary only
";
        let p = parse_netsh_dnsservers(out);
        assert!(matches!(p, DnsPrior::None));
    }

    #[skuld::test]
    fn parse_empty_output_returns_none() {
        let p = parse_netsh_dnsservers("");
        assert!(matches!(p, DnsPrior::None));
    }

    #[skuld::test]
    fn parse_ipv6_static() {
        let out = "
    Statically Configured DNS Servers:  2606:4700:4700::1111
";
        let p = parse_netsh_dnsservers(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(
                    servers,
                    vec![IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111))]
                );
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }
}

// macOS parser tests ==================================================================================================

#[cfg(target_os = "macos")]
mod macos_parsers {
    use super::{DnsPrior, IpAddr, Ipv4Addr};
    use crate::dns::system::macos::parse_networksetup_output;

    #[skuld::test]
    fn parse_empty_reports_dhcp() {
        let out = "There aren't any DNS Servers set on Wi-Fi.\n";
        let p = parse_networksetup_output(out);
        assert!(matches!(p, DnsPrior::Dhcp));
    }

    #[skuld::test]
    fn parse_multiple_ips() {
        let out = "1.1.1.1\n2606:4700:4700::1111\n";
        let p = parse_networksetup_output(out);
        match p {
            DnsPrior::Static { servers } => {
                assert_eq!(servers.len(), 2);
                assert!(servers.contains(&IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
            }
            other => panic!("expected Static, got {other:?}"),
        }
    }
}
