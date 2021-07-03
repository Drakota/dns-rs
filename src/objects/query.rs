use super::name::*;

use derive_try_from_primitive::*;
use nom::{
    combinator::{map, map_res},
    error::context,
    number::complete::be_u16,
    sequence::tuple,
    IResult,
};
use std::convert::TryFrom;

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, TryFromPrimitive, Clone)]
#[repr(u16)]
enum DnsQueryType {
    A = 0x1,
    NS = 0x2,
    MD = 0x3,
    MF = 0x4,
    CNAME = 0x5,
    SOA = 0x6,
    MB = 0x7,
    MG = 0x8,
    MR = 0x9,
    NULL = 0xA,
    WKS = 0xB,
    PTR = 0xC,
    HINFO = 0xD,
    MINFO = 0xE,
    MX = 0xF,
    TXT = 0x10,
}

#[derive(Debug, TryFromPrimitive, Clone)]
#[repr(u16)]
enum DnsQueryClass {
    IN = 0x1,
    CS = 0x2,
    CH = 0x3,
    HS = 0x4,
}

#[derive(Debug, Clone)]
pub struct DnsQuery {
    name: String,
    r#type: DnsQueryType,
    class: DnsQueryClass,
}

impl DnsQuery {
    pub fn parse<'a>(lookup_bytes: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&[u8], Self> {
        move |i: &[u8]| {
            map(
                tuple((
                    context("Name", Name::parse(lookup_bytes)),
                    context("Type", map_res(be_u16, DnsQueryType::try_from)),
                    context("Class", map_res(be_u16, DnsQueryClass::try_from)),
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
