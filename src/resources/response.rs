use super::name::*;
use super::*;
use crate::traits::Parsable;

use nom::bytes::complete::take;
use nom::number::complete::be_u32;
use nom::{combinator::map_res, error::context, number::complete::be_u16, IResult};
use std::convert::TryFrom;
use std::convert::TryInto;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsResponse {
    pub name: String,
    pub r#type: DnsRecordType,
    pub class: DnsClass,
    pub ttl: u32,
    pub address: IpAddr,
}

impl Parsable for IpAddr {
    fn parse<'a>(i: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized,
    {
        match i.len() {
            4 => {
                let bytes: [u8; 4] = i.try_into().unwrap();
                Ok((i, IpAddr::V4(Ipv4Addr::from(bytes))))
            }
            16 => {
                let bytes: [u8; 16] = i.try_into().unwrap();
                Ok((i, IpAddr::V6(Ipv6Addr::from(bytes))))
            }
            _ => todo!(),
        }
    }
}

impl DnsResponse {
    pub fn parse<'a>(lookup_bytes: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&[u8], Self> {
        move |i: &[u8]| {
            let (i, name) = context("Name", DnsName::parse(lookup_bytes))(i)?;
            let (i, r#type) = context("Type", map_res(be_u16, DnsRecordType::try_from))(i)?;
            let (i, class) = context("Class", map_res(be_u16, DnsClass::try_from))(i)?;
            let (i, ttl) = context("Time to live", be_u32)(i)?;
            let (i, len) = context("Data length", be_u16)(i)?;
            let (_, (i, address)) = context("Address", map_res(take(len), IpAddr::parse))(i)?;

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
