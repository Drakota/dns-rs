use dns_rs::{
    header::{
        flags::{DnsHeaderFlags, Opcode, ReplyCode},
        DnsHeader,
    },
    packet::DnsPacket,
    resources::query::DnsQuery,
    resources::DnsRecordType,
    resources::{response::DnsResponse, DnsClass},
};

use std::{net::IpAddr, str::FromStr};

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
        queries: vec![DnsQuery {
            name: String::from("google.com"),
            r#type: DnsRecordType::A,
            class: DnsClass::IN,
        }],
        responses: vec![],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]))
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
        queries: vec![DnsQuery {
            name: String::from("google.com"),
            r#type: DnsRecordType::AAAA,
            class: DnsClass::IN,
        }],
        responses: vec![],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]));
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
        queries: vec![DnsQuery {
            name: String::from("google.com"),
            r#type: DnsRecordType::A,
            class: DnsClass::IN,
        }],
        responses: vec![DnsResponse {
            name: String::from("google.com"),
            r#type: DnsRecordType::A,
            class: DnsClass::IN,
            ttl: 128,
            address: IpAddr::from_str("172.217.13.174").unwrap(),
        }],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]));
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
        queries: vec![DnsQuery {
            name: String::from("google.com"),
            r#type: DnsRecordType::AAAA,
            class: DnsClass::IN,
        }],
        responses: vec![DnsResponse {
            name: String::from("google.com"),
            r#type: DnsRecordType::AAAA,
            class: DnsClass::IN,
            ttl: 30,
            address: IpAddr::from_str("2607:F8B0:4020:805::200E").unwrap(),
        }],
    };

    assert_eq!(expect, DnsPacket::parse(&bytes[..]));
}
