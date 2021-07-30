use super::header::DnsHeader;
use super::resources::query::DnsQuery;
use super::resources::record::DnsRecord;
use crate::types::{ParseError, ParseInput};

use cookie_factory::{self as cf, gen_simple, GenError};
use nom::error::context;
use nom::multi::fold_many_m_n;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsPacket {
    pub header: DnsHeader,
    pub queries: Vec<DnsQuery>,
    pub responses: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additional_records: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn parse(i: ParseInput) -> Result<Self, ParseError<Vec<u8>>> {
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

    pub fn serialize(&self) -> Result<Vec<u8>, GenError> {
        use cf::{combinator::slice, sequence::tuple};

        let bytes = tuple((
            self.header.serialize(),
            slice(
                self.queries
                    .iter()
                    // TODO: Don't use unwrap here and handle the error.
                    .map(|q| q.to_bytes().unwrap())
                    .flatten()
                    .collect::<Vec<u8>>(),
            ),
            slice(
                self.responses
                    .iter()
                    // TODO: Don't use unwrap here and handle the error.
                    .map(|r| r.to_bytes().unwrap())
                    .flatten()
                    .collect::<Vec<u8>>(),
            ),
            slice(
                self.authorities
                    .iter()
                    // TODO: Don't use unwrap here and handle the error.
                    .map(|a| a.to_bytes().unwrap())
                    .flatten()
                    .collect::<Vec<u8>>(),
            ),
            slice(
                self.additional_records
                    .iter()
                    // TODO: Don't use unwrap here and handle the error.
                    .map(|ar| ar.to_bytes().unwrap())
                    .flatten()
                    .collect::<Vec<u8>>(),
            ),
        ));

        gen_simple(bytes, Vec::new())
    }
}
