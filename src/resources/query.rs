use super::name::*;
use super::*;
use crate::types::{ParseInput, ParseResult};
use cookie_factory::{self as cf, gen_simple, GenError, SerializeFn};
use std::io::Write;

use nom::{
    combinator::{map, map_res},
    error::context,
    number::complete::be_u16,
    sequence::tuple,
};
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsQuery {
    A { name: DnsName, class: DnsClass },
    AAAA { name: DnsName, class: DnsClass },
}

impl DnsQuery {
    pub fn parse<'a>(
        reference_bytes: ParseInput<'a>,
    ) -> impl FnMut(ParseInput<'a>) -> ParseResult<Self> {
        move |i: ParseInput| {
            map(
                tuple((
                    context("Name", DnsName::parse(reference_bytes)),
                    context("Type", map_res(be_u16, DnsRecordType::try_from)),
                    context("Class", map_res(be_u16, DnsClass::try_from)),
                )),
                |(name, record_type, class)| match record_type {
                    DnsRecordType::A => DnsQuery::A { name, class },
                    DnsRecordType::AAAA => DnsQuery::AAAA { name, class },
                    _ => unreachable!(),
                },
            )(i)
        }
    }

    pub fn serialize<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, sequence::tuple};
        let (name, r#type, class) = match self {
            DnsQuery::A { name, class } => (name, DnsRecordType::A, class),
            DnsQuery::AAAA { name, class } => (name, DnsRecordType::AAAA, class),
        };

        tuple((
            name.serialize(),
            be_u16(r#type as u16),
            be_u16(*class as u16),
        ))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GenError> {
        gen_simple(self.serialize(), Vec::new())
    }
}
