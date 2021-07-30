use parser::{
    header::flags::*,
    header::*,
    packet::*,
    resources::{name::*, query::*, record::*, DnsClass},
};

use std::{
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

#[test]
fn test_parse_ipv4_dns_query() {
    #[rustfmt::skip]
        let bytes: Vec<u8> = vec![
            0xD0, 0xAE, // Transaction ID: 0xD0AE
            0x01, 0x00, // Flags
                        // 0... .... .... .... = Response: Message is a query
                        // .000 0... .... .... = Opcode: Standard query (0)
                        // .... ..0. .... .... = Truncated: Message is not truncated
                        // .... ...1 .... .... = Recursion desired: Do query recursively
                        // .... .... .0.. .... = Z: reserved (0)
                        // .... .... ...0 .... = Non-authenticated data: Unacceptable
            0x00, 0x01, // Queries count: 1
            0x00, 0x00, // Responses count: 0
            0x00, 0x00, // Authority RRs: 0 
            0x00, 0x00, // Additional RRs: 0
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
            0x03, 0x63, 0x6F, 0x6D, // com 
            0x00,       // Null terminated
            0x00, 0x01, // Record Type: A 
            0x00, 0x01, // Class: IN
        ];

    let expect = DnsPacket {
        header: DnsHeader {
            transaction_id: 0xD0AE,
            flags: DnsHeaderFlags {
                response: false,
                opcode: Opcode::Query,
                truncated: false,
                recdesired: true,
                z: false,
                authenticated: false,
                ..Default::default()
            },
            queries: 0x01,
            responses: 0x00,
            add_rr: 0x00,
            auth_rr: 0x00,
        },
        queries: vec![DnsQuery::A {
            name: DnsName::from("google.com"),
            class: DnsClass::IN,
        }],
        responses: vec![],
        authorities: vec![],
        additional_records: vec![],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]).unwrap())
}

#[test]
pub fn test_parse_ipv6_dns_query() {
    #[rustfmt::skip]
        let bytes: Vec<u8> = vec![
            0x62, 0x09, // Transaction ID: 0x6209 
            0x01, 0x00, // Flags
                        // 0... .... .... .... = Response: Message is a query
                        // .000 0... .... .... = Opcode: Standard query (0)
                        // .... ..0. .... .... = Truncated: Message is not truncated
                        // .... ...1 .... .... = Recursion desired: Do query recursively
                        // .... .... .0.. .... = Z: reserved (0)
                        // .... .... ...0 .... = Non-authenticated data: Unacceptable
            0x00, 0x01, // Queries count: 1
            0x00, 0x00, // Responses count: 0
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
            0x03, 0x63, 0x6F, 0x6D, // com
            0x00,       // Null terminated
            0x00, 0x1C, // Record Type: AAAA
            0x00, 0x01, // Class: IN
        ];

    let expect = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x6209,
            flags: DnsHeaderFlags {
                response: false,
                opcode: Opcode::Query,
                truncated: false,
                recdesired: true,
                z: false,
                authenticated: false,
                ..Default::default()
            },
            queries: 0x01,
            responses: 0x00,
            add_rr: 0x00,
            auth_rr: 0x00,
        },
        queries: vec![DnsQuery::AAAA {
            name: DnsName::from("google.com"),
            class: DnsClass::IN,
        }],
        responses: vec![],
        authorities: vec![],
        additional_records: vec![],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]).unwrap());
}

#[test]
pub fn test_parse_ipv4_dns_response() {
    #[rustfmt::skip]
        let bytes: Vec<u8> = vec![
            0xD0, 0xAE, // Transaction ID: 0xD0AE
            0x81, 0x80, // Flags
                        // 1... .... .... .... = Response: Message is a response
                        // .000 0... .... .... = Opcode: Standard query (0)
                        // .... .0.. .... .... = Authoritative: Server is not an authority for domain
                        // .... ..0. .... .... = Truncated: Message is not truncated
                        // .... ...1 .... .... = Recursion desired: Do query recursively
                        // .... .... 1... .... = Recursion available: Server can do recursive queries
                        // .... .... .0.. .... = Z: reserved (0)
                        // .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
                        // .... .... ...0 .... = Non-authenticated data: Unacceptable
                        // .... .... .... 0000 = Reply code: No error (0)
            0x00, 0x01, // Queries count: 1
            0x00, 0x01, // Responses count: 1
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
            0x03, 0x63, 0x6F, 0x6D, // com
            0x00,       // Null terminated
            0x00, 0x01, // Record Type: A
            0x00, 0x01, // Class: IN
            0xC0, 0x0C, // Compressed offset: 12
            0x00, 0x01, // Record Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x80, // TTL: 128 seconds
            0x00, 0x04, // Data length: 4
            0xAC, 0xD9, 0x0D, 0xAE, // Address: 172.217.13.174
        ];

    let expect = DnsPacket {
        header: DnsHeader {
            transaction_id: 0xD0AE,
            flags: DnsHeaderFlags {
                response: true,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recdesired: true,
                recavail: true,
                z: false,
                authenticated: false,
                checkdisable: false,
                rcode: ReplyCode::NoError,
            },
            queries: 0x01,
            responses: 0x01,
            add_rr: 0x00,
            auth_rr: 0x00,
        },
        queries: vec![DnsQuery::A {
            name: DnsName::from("google.com"),
            class: DnsClass::IN,
        }],
        responses: vec![DnsRecord::A {
            name: DnsName::from("google.com"),
            class: DnsClass::IN,
            ttl: 128,
            address: Ipv4Addr::from_str("172.217.13.174").unwrap(),
        }],
        authorities: vec![],
        additional_records: vec![],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]).unwrap());
}

#[test]
pub fn test_parse_ipv6_dns_response() {
    #[rustfmt::skip]
        let bytes: Vec<u8> = vec![
            0x62, 0x09, // Transaction ID: 0x6209
            0x81, 0x80, // Flags
                        // 1... .... .... .... = Response: Message is a response
                        // .000 0... .... .... = Opcode: Standard query (0)
                        // .... .0.. .... .... = Authoritative: Server is not an authority for domain
                        // .... ..0. .... .... = Truncated: Message is not truncated
                        // .... ...1 .... .... = Recursion desired: Do query recursively
                        // .... .... 1... .... = Recursion available: Server can do recursive queries
                        // .... .... .0.. .... = Z: reserved (0)
                        // .... .... ..0. .... = Answer authenticated: Answer/authority portion was not authenticated by the server
                        // .... .... ...0 .... = Non-authenticated data: Unacceptable
                        // .... .... .... 0000 = Reply code: No error (0)
            0x00, 0x01, // Queries count: 1
            0x00, 0x01, // Responses count: 1
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x06, 0x67, 0x6F, 0x6F, 0x67, 0x6C, 0x65, // google
            0x03, 0x63, 0x6F, 0x6D, // com
            0x00,       // Null terminated
            0x00, 0x1C, // Record Type: AAAA
            0x00, 0x01, // Class: IN
            0xC0, 0x0C, // Compressed offset: 12
            0x00, 0x1C, // Record Type: AAAA
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x00, 0x1E, // TTL: 30 seconds 
            0x00, 0x10, // Data length: 16
            0x26, 0x07, 0xF8, 0xB0, 0x40, 0x20, 0x08, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x0E, // Address: 2607:F8B0:4020:805::200E
        ];

    let expect = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x6209,
            flags: DnsHeaderFlags {
                response: true,
                opcode: Opcode::Query,
                authoritative: false,
                truncated: false,
                recdesired: true,
                recavail: true,
                z: false,
                authenticated: false,
                checkdisable: false,
                rcode: ReplyCode::NoError,
            },
            queries: 0x01,
            responses: 0x01,
            add_rr: 0x00,
            auth_rr: 0x00,
        },
        queries: vec![DnsQuery::AAAA {
            name: DnsName::from("google.com"),
            class: DnsClass::IN,
        }],
        responses: vec![DnsRecord::AAAA {
            name: DnsName::from("google.com"),
            class: DnsClass::IN,
            ttl: 30,
            address: Ipv6Addr::from_str("2607:F8B0:4020:805::200E").unwrap(),
        }],
        authorities: vec![],
        additional_records: vec![],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]).unwrap());
}

#[test]
pub fn test_parse_dns_response_with_cname() {
    let bytes: Vec<u8> = vec![
        0x82, 0x23, // Transaction ID: 0x8223
        0x81, 0x80, // Flags
        0x00, 0x01, // Queries count: 1
        0x00, 0x02, // Responses count: 2
        0x00, 0x00, // Authority RRs: 0
        0x00, 0x00, // Additional RRs: 0
        0x04, 0x64, 0x6f, 0x63, 0x73, // docs
        0x06, 0x73, 0x62, 0x6f, 0x6e, 0x64, 0x73, // sbonds
        0x03, 0x6f, 0x72, 0x67, // org
        0x00, // Null terminated
        0x00, 0x01, // Record Type: A
        0x00, 0x01, // Class: IN
        0xc0, 0x0c, // Compressed offset: 12
        0x00, 0x05, // Record Type: CNAME
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x1c, 0x0f, // TTL: 1 hour, 59 minutes, and 43 seconds
        0x00, 0x10, // Data length: 16
        0x03, 0x67, 0x68, 0x73, // ghs
        0x06, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, // google
        0x03, 0x63, 0x6f, 0x6d, // com
        0x00, // Null terminated
        0xc0, 0x2d, // Compressed offset: 45
        0x00, 0x01, // Record Type: A
        0x00, 0x01, // Class: IN
        0x00, 0x00, 0x00, 0x79, // TTL: 2 minutes, 1 second
        0x00, 0x04, // Data length: 4
        0xac, 0xd9, 0x0d, 0x73, // Address: 172.217.13.115
    ];

    let expect = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x8223,
            flags: DnsHeaderFlags {
                response: true,
                recdesired: true,
                recavail: true,
                ..Default::default()
            },
            queries: 0x01,
            responses: 0x02,
            add_rr: 0x00,
            auth_rr: 0x00,
        },
        queries: vec![DnsQuery::A {
            name: DnsName::from("docs.sbonds.org"),
            class: DnsClass::IN,
        }],
        responses: vec![
            DnsRecord::CNAME {
                name: DnsName::from("docs.sbonds.org"),
                class: DnsClass::IN,
                ttl: 0x1C0F,
                canonical_name: DnsName::from("ghs.google.com"),
            },
            DnsRecord::A {
                name: DnsName::from("ghs.google.com"),
                class: DnsClass::IN,
                ttl: 0x79,
                address: Ipv4Addr::from_str("172.217.13.115").unwrap(),
            },
        ],
        additional_records: vec![],
        authorities: vec![],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]).unwrap());
}

#[test]
pub fn test_parse_dns_response_with_name_servers_and_additional_records() {
    let bytes: Vec<u8> = vec![
        0x24, 0x4b, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x0d, 0x00, 0x0e, 0x01, 0x61, 0x0c,
        0x72, 0x6f, 0x6f, 0x74, 0x2d, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x03, 0x6e, 0x65,
        0x74, 0x00, 0x00, 0x01, 0x00, 0x01, 0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x30, 0x6d,
        0x2f, 0x00, 0x04, 0xc6, 0x29, 0x00, 0x04, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
        0x16, 0x2e, 0x00, 0x02, 0xc0, 0x0c, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x16,
        0x2e, 0x00, 0x04, 0x01, 0x62, 0xc0, 0x0e, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00,
        0x16, 0x2e, 0x00, 0x04, 0x01, 0x63, 0xc0, 0x0e, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00,
        0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x64, 0xc0, 0x0e, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01,
        0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x65, 0xc0, 0x0e, 0xc0, 0x0e, 0x00, 0x02, 0x00,
        0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x66, 0xc0, 0x0e, 0xc0, 0x0e, 0x00, 0x02,
        0x00, 0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x67, 0xc0, 0x0e, 0xc0, 0x0e, 0x00,
        0x02, 0x00, 0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x68, 0xc0, 0x0e, 0xc0, 0x0e,
        0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x69, 0xc0, 0x0e, 0xc0,
        0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x6a, 0xc0, 0x0e,
        0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x6b, 0xc0,
        0x0e, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01, 0x6c,
        0xc0, 0x0e, 0xc0, 0x0e, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x16, 0x2e, 0x00, 0x04, 0x01,
        0x6d, 0xc0, 0x0e, 0xc0, 0x4e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x30, 0x6d, 0x2e, 0x00, 0x04,
        0xc7, 0x09, 0x0e, 0xc9, 0xc0, 0x5e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x33, 0x18, 0x36, 0x00,
        0x04, 0xc0, 0x21, 0x04, 0x0c, 0xc0, 0x6e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x35, 0x99, 0x34,
        0x00, 0x04, 0xc7, 0x07, 0x5b, 0x0d, 0xc0, 0x7e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x35, 0x99,
        0xa3, 0x00, 0x04, 0xc0, 0xcb, 0xe6, 0x0a, 0xc0, 0x8e, 0x00, 0x01, 0x00, 0x01, 0x00, 0x35,
        0xa4, 0xdd, 0x00, 0x04, 0xc0, 0x05, 0x05, 0xf1, 0xc0, 0x9e, 0x00, 0x01, 0x00, 0x01, 0x00,
        0x35, 0xd1, 0x15, 0x00, 0x04, 0xc0, 0x70, 0x24, 0x04, 0xc0, 0xae, 0x00, 0x01, 0x00, 0x01,
        0x00, 0x35, 0x9b, 0x1f, 0x00, 0x04, 0xc6, 0x61, 0xbe, 0x35, 0xc0, 0xbe, 0x00, 0x01, 0x00,
        0x01, 0x00, 0x35, 0x97, 0xb8, 0x00, 0x04, 0xc0, 0x24, 0x94, 0x11, 0xc0, 0xce, 0x00, 0x01,
        0x00, 0x01, 0x00, 0x36, 0x8a, 0x51, 0x00, 0x04, 0xc0, 0x3a, 0x80, 0x1e, 0xc0, 0xde, 0x00,
        0x01, 0x00, 0x01, 0x00, 0x36, 0x8a, 0x51, 0x00, 0x04, 0xc1, 0x00, 0x0e, 0x81, 0xc0, 0xee,
        0x00, 0x01, 0x00, 0x01, 0x00, 0x36, 0xce, 0xfd, 0x00, 0x04, 0xc7, 0x07, 0x53, 0x2a, 0xc0,
        0xfe, 0x00, 0x01, 0x00, 0x01, 0x00, 0x35, 0x92, 0x76, 0x00, 0x04, 0xca, 0x0c, 0x1b, 0x21,
        0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x35, 0x9d, 0xda, 0x00, 0x10, 0x20, 0x01, 0x05,
        0x03, 0xba, 0x3e, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x30, 0xc0, 0x4e,
        0x00, 0x1c, 0x00, 0x01, 0x00, 0x36, 0x44, 0xe7, 0x00, 0x10, 0x20, 0x01, 0x05, 0x00, 0x02,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b,
    ];

    let expect = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x244B,
            flags: DnsHeaderFlags {
                response: true,
                recdesired: true,
                recavail: true,
                ..Default::default()
            },
            queries: 0x01,
            responses: 0x01,
            auth_rr: 0x0D,
            add_rr: 0x0E,
        },
        queries: vec![DnsQuery::A {
            name: DnsName::from("a.root-servers.net"),
            class: DnsClass::IN,
        }],
        responses: vec![DnsRecord::A {
            name: DnsName::from("a.root-servers.net"),
            class: DnsClass::IN,
            ttl: 0x306D2F,
            address: Ipv4Addr::from_str("198.41.0.4").unwrap(),
        }],
        authorities: (b'a'..=b'm')
            .map(|c| DnsRecord::NS {
                name: DnsName::from("root-servers.net"),
                class: DnsClass::IN,
                ttl: 0x162E,
                name_server: DnsName::from(
                    format!("{}.root-servers.net", char::from(c).to_string()).as_ref(),
                ),
            })
            .collect(),
        additional_records: vec![
            DnsRecord::A {
                name: DnsName::from("b.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3173678,
                address: Ipv4Addr::from_str("199.9.14.201").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("c.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3348534,
                address: Ipv4Addr::from_str("192.33.4.12").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("d.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3512628,
                address: Ipv4Addr::from_str("199.7.91.13").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("e.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3512739,
                address: Ipv4Addr::from_str("192.203.230.10").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("f.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3515613,
                address: Ipv4Addr::from_str("192.5.5.241").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("g.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3526933,
                address: Ipv4Addr::from_str("192.112.36.4").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("h.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3513119,
                address: Ipv4Addr::from_str("198.97.190.53").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("i.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3512248,
                address: Ipv4Addr::from_str("192.36.148.17").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("j.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3574353,
                address: Ipv4Addr::from_str("192.58.128.30").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("k.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3574353,
                address: Ipv4Addr::from_str("193.0.14.129").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("l.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3591933,
                address: Ipv4Addr::from_str("199.7.83.42").unwrap(),
            },
            DnsRecord::A {
                name: DnsName::from("m.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3510902,
                address: Ipv4Addr::from_str("202.12.27.33").unwrap(),
            },
            DnsRecord::AAAA {
                name: DnsName::from("a.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3513818,
                address: Ipv6Addr::from_str("2001:503:ba3e::2:30").unwrap(),
            },
            DnsRecord::AAAA {
                name: DnsName::from("b.root-servers.net"),
                class: DnsClass::IN,
                ttl: 3556583,
                address: Ipv6Addr::from_str("2001:500:200::b").unwrap(),
            },
        ],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]).unwrap());
}

#[test]
fn test_serialize() {
    let packet = DnsPacket {
        header: DnsHeader {
            transaction_id: 0x244B,
            flags: DnsHeaderFlags {
                response: true,
                recdesired: true,
                recavail: true,
                ..Default::default()
            },
            queries: 0x02,
            responses: 0x02,
            auth_rr: 0x00,
            add_rr: 0x00,
        },
        queries: vec![
            DnsQuery::A {
                name: DnsName::from("a.root-servers.net"),
                class: DnsClass::IN,
            },
            DnsQuery::AAAA {
                name: DnsName::from("a.root-servers.net"),
                class: DnsClass::IN,
            },
        ],
        responses: vec![
            DnsRecord::A {
                name: DnsName::from("a.root-servers.net"),
                class: DnsClass::IN,
                ttl: 0x162E,
                address: Ipv4Addr::from_str("199.9.14.201").unwrap(),
            },
            DnsRecord::AAAA {
                name: DnsName::from("a.root-servers.net"),
                class: DnsClass::IN,
                ttl: 0x1234,
                address: Ipv6Addr::from_str("2001:503:ba3e::2:30").unwrap(),
            },
        ],
        authorities: vec![],
        additional_records: vec![],
    };

    #[rustfmt::skip]
        let expect: Vec<u8> = vec![
            0x24, 0x4B, // Transaction ID
            0x81, 0x80, // Flags
            0x00, 0x02, // Queries count: 2
            0x00, 0x02, // Responses count: 2
            0x00, 0x00, // Authority RRs: 0
            0x00, 0x00, // Additional RRs: 0
            0x01, 0x61, // a
            0x0C, 0x72, 0x6F, 0x6F, 0x74, 0x2D, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, // root-servers
            0x03, 0x6e, 0x65, 0x74, // net
            0x00,       // Null terminated
            0x00, 0x01, // Record Type: A
            0x00, 0x01, // Class: IN
            0x01, 0x61, // a
            0x0c, 0x72, 0x6F, 0x6F, 0x74, 0x2D, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, // root-servers
            0x03, 0x6E, 0x65, 0x74, // net
            0x00,       // Null terminated
            0x00, 0x1C, // Record Type: AAAA
            0x00, 0x01, // Class: IN
            0x01, 0x61, // a
            0x0C, 0x72, 0x6F, 0x6F, 0x74, 0x2D, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, // root-servers
            0x03, 0x6e, 0x65, 0x74, // net
            0x00,       // Null terminated
            0x00, 0x01, // Record Type: A
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x16, 0x2E, // TTL: 0x162E
            0xC7, 0x09, 0x0E, 0xC9, // Address: 199.9.14.201
            0x01, 0x61, // a
            0x0c, 0x72, 0x6F, 0x6F, 0x74, 0x2D, 0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, // root-servers
            0x03, 0x6E, 0x65, 0x74, // net
            0x00,       // Null terminated
            0x00, 0x1C, // Record Type: AAAA
            0x00, 0x01, // Class: IN
            0x00, 0x00, 0x12, 0x34, // TTL: 0x1234
            0x20, 0x01, 0x05, 0x03, 0xBA, 0x3E, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x30 // Address: 2001:503:ba3e::2:30
        ];

    assert_eq!(expect, packet.serialize().unwrap());
}
