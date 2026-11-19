//! SSRF address classification (C2-U2 design §4; FR-N5.2; Q7).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// What an address is, for egress decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpClass {
    /// Routable on the public internet.
    Public,
    /// Internal / special-purpose (the `&str` names the range for audit messages).
    Private(&'static str),
    /// A cloud instance-metadata endpoint: blocked even with `allow_private_ips`
    /// unless an IP rule names it explicitly (FR-N5.4).
    Metadata,
}

const METADATA_V4: [Ipv4Addr; 3] = [
    Ipv4Addr::new(169, 254, 169, 254), // AWS, GCP, Azure IMDS, OpenStack
    Ipv4Addr::new(100, 100, 100, 200), // Alibaba Cloud
    Ipv4Addr::new(168, 63, 129, 16),   // Azure wireserver
];
const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254); // AWS IMDS v6

/// Classify an address, looking through IPv6 forms that embed an IPv4 address.
pub fn classify(ip: IpAddr) -> IpClass {
    match ip {
        IpAddr::V4(v4) => classify_v4(v4),
        IpAddr::V6(v6) => classify_v6(v6),
    }
}

fn classify_v4(ip: Ipv4Addr) -> IpClass {
    if METADATA_V4.contains(&ip) {
        return IpClass::Metadata;
    }
    let [a, b, c, _] = ip.octets();
    let class = match (a, b, c) {
        (0, _, _) => "this-network 0.0.0.0/8",
        (10, _, _) => "private 10.0.0.0/8",
        (100, 64..=127, _) => "carrier-grade NAT 100.64.0.0/10",
        (127, _, _) => "loopback 127.0.0.0/8",
        (169, 254, _) => "link-local 169.254.0.0/16",
        (172, 16..=31, _) => "private 172.16.0.0/12",
        (192, 0, 0) => "IETF protocol assignments 192.0.0.0/24",
        (192, 0, 2) | (198, 51, 100) | (203, 0, 113) => "documentation range",
        (192, 88, 99) => "6to4 relay anycast 192.88.99.0/24",
        (192, 168, _) => "private 192.168.0.0/16",
        (198, 18..=19, _) => "benchmarking 198.18.0.0/15",
        (224..=239, _, _) => "multicast 224.0.0.0/4",
        (240..=255, _, _) => "reserved 240.0.0.0/4",
        _ => return IpClass::Public,
    };
    IpClass::Private(class)
}

fn classify_v6(ip: Ipv6Addr) -> IpClass {
    if ip == METADATA_V6 {
        return IpClass::Metadata;
    }
    let s = ip.segments();
    // Forms that carry an IPv4 address: classify by the inner address.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return classify_v4(v4); // ::ffff:a.b.c.d
    }
    if s[..6] == [0; 6] && !(s[6] == 0 && s[7] <= 1) {
        return classify_v4(embedded(s[6], s[7])); // deprecated IPv4-compatible ::a.b.c.d
    }
    if s[0] == 0x2002 {
        return classify_v4(embedded(s[1], s[2])); // 6to4 2002:AABB:CCDD::/48
    }
    if s[..6] == [0x64, 0xff9b, 0, 0, 0, 0] {
        return classify_v4(embedded(s[6], s[7])); // NAT64 well-known prefix 64:ff9b::/96
    }
    let class = if ip.is_unspecified() {
        "unspecified ::"
    } else if ip.is_loopback() {
        "loopback ::1"
    } else if s[0] == 0x2001 && s[1] == 0 {
        "Teredo 2001::/32" // tunnels to arbitrary IPv4; blocked entirely (Q7)
    } else if s[0] == 0x64 && s[1] == 0xff9b && s[2] == 1 {
        "local-use NAT64 64:ff9b:1::/48"
    } else if (s[0] & 0xfe00) == 0xfc00 {
        "unique local fc00::/7"
    } else if (s[0] & 0xffc0) == 0xfe80 {
        "link-local fe80::/10"
    } else if (s[0] & 0xff00) == 0xff00 {
        "multicast ff00::/8"
    } else if s[0] == 0x0100 && s[1..4] == [0, 0, 0] {
        "discard-only 100::/64"
    } else if s[0] == 0x2001 && s[1] == 0x0db8 {
        "documentation 2001:db8::/32"
    } else {
        return IpClass::Public;
    };
    IpClass::Private(class)
}

fn embedded(hi: u16, lo: u16) -> Ipv4Addr {
    let [a, b] = hi.to_be_bytes();
    let [c, d] = lo.to_be_bytes();
    Ipv4Addr::new(a, b, c, d)
}

/// Decide whether `ip` may be contacted. `explicit_ip_rule` is true when an allowlist rule names
/// this exact IP literal (the only way to reach a metadata endpoint, FR-N5.4).
pub fn permitted(ip: IpAddr, allow_private: bool, explicit_ip_rule: bool) -> Result<(), String> {
    match classify(ip) {
        IpClass::Public => Ok(()),
        IpClass::Private(_) if allow_private => Ok(()),
        IpClass::Private(range) => Err(format!(
            "{ip} is in {range} (private addresses are blocked by policy)"
        )),
        IpClass::Metadata if allow_private && explicit_ip_rule => Ok(()),
        IpClass::Metadata => Err(format!("{ip} is a cloud metadata endpoint")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn c(s: &str) -> IpClass {
        classify(s.parse().expect("ip"))
    }
    fn private(s: &str) -> bool {
        matches!(c(s), IpClass::Private(_))
    }

    #[test]
    fn v4_ranges() {
        for p in [
            "8.8.8.8",
            "1.1.1.1",
            "93.184.216.34",
            "100.63.255.255",
            "100.128.0.0",
            "172.15.0.1",
            "172.32.0.1",
            "192.169.0.1",
            "223.255.255.255",
        ] {
            assert_eq!(c(p), IpClass::Public, "{p}");
        }
        for p in [
            "0.0.0.0",
            "10.1.2.3",
            "100.64.0.1",
            "127.0.0.1",
            "127.255.255.254",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "198.18.0.1",
            "224.0.0.1",
            "239.255.255.250",
            "240.0.0.1",
            "255.255.255.255",
            "192.0.0.8",
            "192.0.2.1",
        ] {
            assert!(private(p), "{p}");
        }
        for p in ["169.254.169.254", "100.100.100.200", "168.63.129.16"] {
            assert_eq!(c(p), IpClass::Metadata, "{p}");
        }
    }

    #[test]
    fn v6_ranges_and_embedded_v4() {
        assert_eq!(c("2606:4700:4700::1111"), IpClass::Public);
        for p in [
            "::",
            "::1",
            "fc00::1",
            "fd12:3456::1",
            "fe80::1",
            "ff02::1",
            "2001::1",
            "2001:0:abcd::1",
            "2001:db8::1",
            "64:ff9b:1::1",
            "100::1",
        ] {
            assert!(private(p), "{p}");
        }
        // Embedded IPv4 is classified by the inner address.
        assert!(private("::ffff:127.0.0.1"));
        assert!(private("::ffff:10.0.0.1"));
        assert_eq!(c("::ffff:8.8.8.8"), IpClass::Public);
        assert!(private("::127.0.0.1"));
        assert!(private("2002:7f00:1::1")); // 6to4 of 127.0.0.1
        assert!(private("2002:c0a8:101::")); // 6to4 of 192.168.1.1
        assert_eq!(c("2002:0808:0808::1"), IpClass::Public);
        assert!(private("64:ff9b::7f00:1")); // NAT64 of 127.0.0.1
        assert_eq!(c("64:ff9b::808:808"), IpClass::Public);
        assert_eq!(c("::ffff:169.254.169.254"), IpClass::Metadata);
        assert_eq!(c("fd00:ec2::254"), IpClass::Metadata);
    }

    #[test]
    fn permission_matrix() {
        let lo: IpAddr = "127.0.0.1".parse().expect("ip");
        let md: IpAddr = "169.254.169.254".parse().expect("ip");
        let pub_: IpAddr = "8.8.8.8".parse().expect("ip");
        assert!(permitted(pub_, false, false).is_ok());
        assert!(permitted(lo, false, false).is_err());
        assert!(permitted(lo, true, false).is_ok());
        assert!(
            permitted(md, true, false).is_err(),
            "metadata stays blocked with allow_private"
        );
        assert!(
            permitted(md, false, true).is_err(),
            "explicit rule alone is not enough"
        );
        assert!(permitted(md, true, true).is_ok());
    }
}
