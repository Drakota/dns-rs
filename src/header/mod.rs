pub mod flags;
mod utils;

use self::flags::DnsHeaderFlags;
use crate::types::{ParseInput, ParseResult};

use nom::{bits::bits, combinator::map, error::context, number::complete::be_u16, sequence::tuple};

#[derive(Debug, PartialEq, Eq)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: DnsHeaderFlags,
    pub queries: u16,
    pub responses: u16,
    pub auth_rr: u16,
    pub add_rr: u16,
}

impl DnsHeader {
    pub fn parse(i: ParseInput) -> ParseResult<Self> {
        map(
            tuple((
                context("Transaction ID", be_u16),
                context("Flags", bits(DnsHeaderFlags::parse)),
                context("Responses", be_u16),
                context("Answers", be_u16),
                context("Authority RRs", be_u16),
                context("Additional RRs", be_u16),
            )),
            |(transaction_id, flags, queries, responses, auth_rr, add_rr)| Self {
                transaction_id,
                flags,
                queries,
                responses,
                auth_rr,
                add_rr,
            },
        )(i)
    }
}
