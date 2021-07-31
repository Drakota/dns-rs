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
    queries: Vec<DnsQuery>,
    responses: Vec<DnsRecord>,
    authorities: Vec<DnsRecord>,
    additional_records: Vec<DnsRecord>,
}

impl DnsPacket {
    pub fn new() -> Self {
        Self {
            header: DnsHeader::new(),
            queries: Vec::new(),
            responses: Vec::new(),
            authorities: Vec::new(),
            additional_records: Vec::new(),
        }
    }

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

    pub fn header(&self) -> &DnsHeader {
        &self.header
    }

    // IMPROVEMENT: Could make a macro for this.
    pub fn queries(&self) -> &Vec<DnsQuery> {
        &self.queries
    }

    pub fn add_query(&mut self, query: DnsQuery) {
        self.header.queries += 1;
        self.queries.push(query);
    }

    pub fn add_queries(&mut self, queries: Vec<DnsQuery>) {
        self.header.queries += queries.len() as u16;
        self.queries.extend(queries.iter().cloned());
    }

    pub fn responses(&self) -> &Vec<DnsRecord> {
        &self.responses
    }

    pub fn add_response(&mut self, response: DnsRecord) {
        self.header.responses += 1;
        self.responses.push(response);
    }

    pub fn add_responses(&mut self, responses: Vec<DnsRecord>) {
        self.header.responses += responses.len() as u16;
        self.responses.extend(responses.iter().cloned());
    }

    pub fn authorities(&self) -> &Vec<DnsRecord> {
        &self.authorities
    }

    pub fn add_authority(&mut self, authority: DnsRecord) {
        self.header.auth_rr += 1;
        self.authorities.push(authority);
    }

    pub fn add_authorities(&mut self, authorities: Vec<DnsRecord>) {
        self.header.auth_rr += authorities.len() as u16;
        self.authorities.extend(authorities.iter().cloned());
    }

    pub fn additional_records(&self) -> &Vec<DnsRecord> {
        &self.additional_records
    }

    pub fn add_record(&mut self, record: DnsRecord) {
        self.header.add_rr += 1;
        self.additional_records.push(record);
    }

    pub fn add_records(&mut self, records: Vec<DnsRecord>) {
        self.header.add_rr += records.len() as u16;
        self.additional_records.extend(records.iter().cloned());
    }
}

impl Default for DnsPacket {
    fn default() -> Self {
        Self::new()
    }
}
