use super::header::DnsHeader;

use nom::{combinator::map, sequence::tuple, IResult};

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
}

impl DnsPacket {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        map(tuple((DnsHeader::parse,)), |(header,)| Self { header })(i)
    }
}
