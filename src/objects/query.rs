use std::convert::TryFrom;

use derive_try_from_primitive::*;
use nom::{
    bytes::complete::{tag, take},
    combinator::{map, map_res},
    error::context,
    multi::many_till,
    number::complete::{be_u16, be_u8},
    sequence::tuple,
    IResult,
};

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug, TryFromPrimitive)]
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

#[derive(Debug, TryFromPrimitive)]
#[repr(u16)]
enum DnsQueryClass {
    IN = 0x1,
    CS = 0x2,
    CH = 0x3,
    HS = 0x4,
}

#[derive(Debug)]
pub struct DnsQuery {
    name: String,
    r#type: DnsQueryType,
    class: DnsQueryClass,
}

impl DnsQuery {
    fn parse_name(i: &'_ [u8]) -> IResult<&'_ [u8], String> {
        let (i, size) = be_u8(i)?;
        let (i, bytes) = take(size)(i)?;
        Ok((i, String::from_utf8_lossy(bytes).into_owned()))
    }

    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        map(
            tuple((
                context("Name", many_till(Self::parse_name, tag([0x0]))),
                context("Type", map_res(be_u16, DnsQueryType::try_from)),
                context("Class", map_res(be_u16, DnsQueryClass::try_from)),
            )),
            |((name, _), r#type, class)| Self {
                name: name.join("."),
                r#type,
                class,
            },
        )(i)
    }
}
