use super::header::DnsHeader;
use super::resources::query::DnsQuery;
use super::resources::response::DnsResponse;

use nom::error::context;
use nom::multi::fold_many_m_n;

#[derive(Debug, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQuery>,
    pub responses: Vec<DnsResponse>,
}

impl DnsPacket {
    pub fn parse(i: &[u8]) -> Self {
        let lookup_bytes: Vec<u8> = i.iter().copied().collect();

        let (i, header) =
            context("Header", DnsHeader::parse)(i).expect("Error while parsing header");

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

        let (_, responses) = fold_many_m_n(
            0,
            header.responses as usize,
            DnsResponse::parse(&lookup_bytes),
            Vec::with_capacity(header.responses as usize),
            |mut responses, response| {
                responses.push(response);
                responses
            },
        )(i)
        .expect("Error while parsing responses");

        Self {
            header,
            queries,
            responses,
        }
    }
}
