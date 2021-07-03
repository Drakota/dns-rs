use dns_rs::{
    header::{
        flags::{DnsHeaderFlags, Opcode},
        DnsHeader,
    },
    packet::DnsPacket,
    resources::query::DnsQuery,
    resources::DnsClass,
    resources::DnsRecordType,
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
        0x00, // Null terminated
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
