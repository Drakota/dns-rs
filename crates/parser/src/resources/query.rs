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
pub struct DnsQuery {
    pub name: DnsName,
    pub record_type: DnsRecordType,
    pub class: DnsClass,
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
                |(name, record_type, class)| DnsQuery {
                    name,
                    record_type,
                    class,
                },
            )(i)
        }
    }

    pub fn serialize<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        use cf::{bytes::be_u16, combinator::slice, sequence::tuple};

        tuple((
            slice(self.name.to_bytes().unwrap()),
            be_u16(self.record_type as u16),
            be_u16(self.class as u16),
        ))
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GenError> {
        gen_simple(self.serialize(), Vec::new())
    }
}
