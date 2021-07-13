use super::header::DnsHeader;
use super::resources::query::DnsQuery;
use super::resources::record::DnsRecord;
use crate::types::{Error as ParseError, ParseInput};

use nom::multi::fold_many_m_n;
use nom::{error::context, Err as NomErr};

#[derive(Debug, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQuery>,
    pub responses: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additional_records: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn parse(i: ParseInput) -> Result<Self, NomErr<ParseError<ParseInput>>> {
        let (b, header) = context("Header", DnsHeader::parse)(i)?;

        let (b, queries) = fold_many_m_n(
            0,
            header.queries as usize,
            DnsQuery::parse(i),
            Vec::with_capacity(header.queries as usize),
            |mut queries, query| {
                queries.push(query);
                queries
            },
        )(b)?;

        let (b, responses) = fold_many_m_n(
            0,
            header.responses as usize,
            DnsRecord::parse(i),
            Vec::with_capacity(header.responses as usize),
            |mut responses, response| {
                responses.push(response);
                responses
            },
        )(b)?;

        let (b, authorities) = fold_many_m_n(
            0,
            header.auth_rr as usize,
            DnsRecord::parse(i),
            Vec::with_capacity(header.auth_rr as usize),
            |mut authorities, authority| {
                authorities.push(authority);
                authorities
            },
        )(b)?;

        let (_, additional_records) = fold_many_m_n(
            0,
            header.add_rr as usize,
            DnsRecord::parse(i),
            Vec::with_capacity(header.add_rr as usize),
            |mut additional_records, additional_record| {
                additional_records.push(additional_record);
                additional_records
            },
        )(b)?;

        Ok(Self {
            header,
            queries,
            responses,
            authorities,
            additional_records,
        })
    }
}
