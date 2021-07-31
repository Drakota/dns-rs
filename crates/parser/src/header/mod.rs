pub mod flags;
mod utils;

use self::flags::DnsHeaderFlags;
use crate::types::{ParseInput, ParseResult};
use cookie_factory::{self as cf, gen_simple, GenError, SerializeFn};
use std::io::Write;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsHeader {
    pub transaction_id: u16,
    flags: DnsHeaderFlags,
    pub queries: u16,
    pub responses: u16,
    pub auth_rr: u16,
    pub add_rr: u16,
}

impl DnsHeader {
    pub fn new() -> Self {
        Self {
            transaction_id: 1337,
            flags: DnsHeaderFlags::default(),
            queries: 0,
            responses: 0,
            auth_rr: 0,
            add_rr: 0,
        }
    }

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

    pub fn serialize<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, sequence::tuple};

        tuple((
            be_u16(self.transaction_id),
            self.flags.serialize(),
            be_u16(self.queries),
            be_u16(self.responses),
            be_u16(self.auth_rr),
            be_u16(self.add_rr),
        ))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GenError> {
        gen_simple(self.serialize(), Vec::new())
    }

    pub fn set_flags(&mut self, flags: DnsHeaderFlags) {
        self.flags = flags;
    }
}

impl Default for DnsHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        let header = DnsHeader {
            transaction_id: 0x1234,
            flags: DnsHeaderFlags {
                recdesired: true,
                ..Default::default()
            },
            queries: 0x5678,
            responses: 0x9abc,
            auth_rr: 0xdef0,
            add_rr: 0xabcd,
        };

        #[rustfmt::skip]
        assert_eq!(header.to_bytes().unwrap(), vec![
            0x12, 0x34, // Transaction ID
            0x01, 0x00, // Flags
            0x56, 0x78, // Queries
            0x9A, 0xBC, // Responses
            0xDE, 0xF0, // Auth RRs
            0xAB, 0xCD, // Additional RRs
        ]);
    }
}
