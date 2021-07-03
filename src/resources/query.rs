use super::name::*;
use super::*;

use nom::{
    combinator::{map, map_res},
    error::context,
    number::complete::be_u16,
    sequence::tuple,
    IResult,
};
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub name: String,
    pub r#type: DnsRecordType,
    pub class: DnsClass,
}

impl DnsQuery {
    pub fn parse<'a>(lookup_bytes: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&[u8], Self> {
        move |i: &[u8]| {
            map(
                tuple((
                    context("Name", DnsName::parse(lookup_bytes)),
                    context("Type", map_res(be_u16, DnsRecordType::try_from)),
                    context("Class", map_res(be_u16, DnsClass::try_from)),
                )),
                |(name, r#type, class)| Self {
                    name,
                    r#type,
                    class,
                },
            )(i)
        }
    }
}
