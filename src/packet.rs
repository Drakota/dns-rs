use super::header::DnsHeader;
use super::resources::name_server::DnsNameServer;
use super::resources::query::DnsQuery;
use super::resources::response::DnsResponse;

use nom::error::context;
use nom::multi::fold_many_m_n;

#[derive(Debug, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQuery>,
    pub responses: Vec<DnsResponse>,
    pub name_servers: Vec<DnsNameServer>,
    pub additional_records: Vec<DnsResponse>,
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

        let (i, responses) = fold_many_m_n(
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

        let (i, name_servers) = fold_many_m_n(
            0,
            header.auth_rr as usize,
            DnsNameServer::parse(&lookup_bytes),
            Vec::with_capacity(header.auth_rr as usize),
            |mut name_servers, name_server| {
                name_servers.push(name_server);
                name_servers
            },
        )(i)
        .expect("Error while parsing name servers");

        let (_, additional_records) = fold_many_m_n(
            0,
            header.add_rr as usize,
            DnsResponse::parse(&lookup_bytes),
            Vec::with_capacity(header.add_rr as usize),
            |mut additional_records, additional_record| {
                additional_records.push(additional_record);
                additional_records
            },
        )(i)
        .expect("Error while parsing additional records");

        Self {
            header,
            queries,
            responses,
            name_servers,
            additional_records,
        }
    }
}
