use super::header::DnsHeader;
use super::query::DnsQuery;

use nom::error::context;
use nom::multi::fold_many_m_n;

#[derive(Debug)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQuery>,
}

impl DnsPacket {
    pub fn parse(i: &[u8]) -> Self {
        let (i, header) =
            context("Header", DnsHeader::parse)(i).expect("Error while parsing header");

        let lookup_bytes: Vec<u8> = i.iter().copied().collect();

        let (i, queries) = fold_many_m_n(
            0,
            header.queries as usize,
            DnsQuery::parse(&lookup_bytes),
            Vec::with_capacity(header.queries as usize),
            |mut queries, query| {
                queries.push(query);
                queries
            },
        )(i)
        .expect("Error while parsing queries");

        Self { header, queries }
    }
}
