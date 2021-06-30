use super::header::DnsHeader;

use nom::error::context;

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
}

impl DnsPacket {
    pub fn parse(i: &[u8]) -> Self {
        let (i, header) =
            context("Header", DnsHeader::parse)(i).expect("Error while parsing header");

        Self { header }
    }
}
