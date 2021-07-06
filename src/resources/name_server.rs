use super::name::*;
use super::*;

use nom::bytes::complete::take;
use nom::combinator::map_res;
use nom::error::context;
use nom::number::complete::{be_u16, be_u32};
use nom::IResult;
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsNameServer {
    pub name: DnsName,
    pub r#type: DnsRecordType,
    pub class: DnsClass,
    pub ttl: u32,
    pub name_server: DnsName,
}

impl DnsNameServer {
    pub fn parse<'a>(lookup_bytes: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&[u8], Self> {
        move |i: &[u8]| {
            let (i, name) = context("Name", DnsName::parse(lookup_bytes))(i)?;
            let (i, r#type) = context("Type", map_res(be_u16, DnsRecordType::try_from))(i)?;
            let (i, class) = context("Class", map_res(be_u16, DnsClass::try_from))(i)?;
            let (i, ttl) = context("Time to live", be_u32)(i)?;
            let (i, len) = context("Data length", be_u16)(i)?;
            let (i, (_, name_server)) = context(
                "Name server",
                map_res(take(len), DnsName::parse(lookup_bytes)),
            )(i)?;

            Ok((
                i,
                Self {
                    name,
                    r#type,
                    class,
                    ttl,
                    name_server,
                },
            ))
        }
    }
}
