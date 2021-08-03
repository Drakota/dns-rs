use parser::resources::{name::DnsName, record::DnsRecord, DnsClass};
use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

pub fn get_root_servers() -> [DnsRecord; 26] {
    [
        DnsRecord::A {
            name: DnsName::from("a.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("198.41.0.4").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("a.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:503:ba3e::2:30").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("b.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("199.9.14.201").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("b.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:200::b").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("c.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("192.33.4.12").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("c.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:2::c").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("d.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("199.7.91.13").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("d.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:2d::d").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("e.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("192.203.230.10").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("e.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:a8::e").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("f.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("192.5.5.241").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("f.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:2f::f").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("g.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("192.112.36.4").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("g.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:12::d0d").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("h.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("198.97.190.53").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("h.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:1::53").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("i.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("192.36.148.17").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("i.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:7fe::53").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("j.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("192.58.128.30").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("j.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:503:c27::2:30").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("k.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("193.0.14.129").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("k.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:7fd::1").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("l.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("199.7.83.42").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("l.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:500:9f::42").unwrap(),
        },
        DnsRecord::A {
            name: DnsName::from("m.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv4Addr::from_str("202.12.27.33").unwrap(),
        },
        DnsRecord::AAAA {
            name: DnsName::from("m.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x162E,
            address: Ipv6Addr::from_str("2001:dc3::35").unwrap(),
        },
    ]
}
