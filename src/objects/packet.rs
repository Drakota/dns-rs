use super::header::DnsHeader;
use super::query::DnsQuery;

use nom::error::context;

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQuery>,
}

impl DnsPacket {
    pub fn parse(i: &[u8]) -> Self {
        let (i, header) =
            context("Header", DnsHeader::parse)(i).expect("Error while parsing header");

        let mut queries: Vec<DnsQuery> = Vec::with_capacity(header.queries as usize);
        for _ in 0..header.queries {
            let (_, query) =
                context("Query", DnsQuery::parse)(i).expect("Error while parsing query");
            queries.push(query);
        }

        Self { header, queries }
    }
}
