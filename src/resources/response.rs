use super::address::*;
use super::name::*;
use super::*;

use nom::number::complete::be_u32;
use nom::{combinator::map_res, error::context, number::complete::be_u16, IResult};
use std::convert::TryFrom;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    name: String,
    r#type: DnsRecordType,
    class: DnsClass,
    ttl: u32,
    address: DnsAddress,
}

impl DnsResponse {
    pub fn parse<'a>(lookup_bytes: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&[u8], Self> {
        move |i: &[u8]| {
            let (i, name) = context("Name", DnsName::parse(lookup_bytes))(i)?;
            let (i, r#type) = context("Type", map_res(be_u16, DnsRecordType::try_from))(i)?;
            let (i, class) = context("Class", map_res(be_u16, DnsClass::try_from))(i)?;
            let (i, ttl) = context("Time to live", be_u32)(i)?;
            let (i, len) = context("Data length", be_u16)(i)?;
            let (i, address) = context("Address", DnsAddress::parse(len))(i)?;

            Ok((
                i,
                Self {
                    name,
                    r#type,
                    class,
                    ttl,
                    address,
                },
            ))
        }
    }
}
