pub mod flags;
mod utils;

use self::flags::DnsHeaderFlags;
use crate::types::{ParseInput, ParseResult};
use cookie_factory::{self as cf, gen_simple, GenError, SerializeFn};
use std::io::Write;

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
        use nom::{
            bits::bits, combinator::map, error::context, number::complete::be_u16, sequence::tuple,
        };

        map(
            tuple((
                context("Transaction ID", be_u16),
                context("Flags", bits(DnsHeaderFlags::parse)),
                context("Queries", be_u16),
                context("Responses", be_u16),
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

    pub fn serialize<W: Write>(&self) -> impl SerializeFn<W> {
        use cf::{bytes::be_u16, sequence::tuple};

        tuple((
            be_u16(self.transaction_id),
            be_u16(self.queries),
            be_u16(self.responses),
            be_u16(self.auth_rr),
            be_u16(self.add_rr),
        ))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GenError> {
        gen_simple(self.serialize(), Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        let header = DnsHeader {
            transaction_id: 0x1234,
            flags: DnsHeaderFlags::default(),
            queries: 0x5678,
            responses: 0x9abc,
            auth_rr: 0xdef0,
            add_rr: 0xabcd,
        };

        #[rustfmt::skip]
        assert_eq!(header.to_bytes().unwrap(), vec![
            0x12, 0x34, // Transaction ID
            0x56, 0x78, // Queries
            0x9A, 0xBC, // Responses
            0xDE, 0xF0, // Auth RRs
            0xAB, 0xCD, // Additional RRs
        ]);
    }
}
