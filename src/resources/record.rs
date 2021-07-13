use super::{name::DnsName, DnsClass, DnsRecordType};
use crate::types::{ParseInput, ParseResult};

use nom::{
    bytes::complete::take,
    combinator::map_res,
    error::context,
    number::complete::{be_u16, be_u32},
};
use std::{
    convert::{TryFrom, TryInto},
    net::{Ipv4Addr, Ipv6Addr},
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum DnsRecord {
    A {
        name: DnsName,
        class: DnsClass,
        ttl: u32,
        address: Ipv4Addr,
    },
    NS {
        name: DnsName,
        class: DnsClass,
        ttl: u32,
        name_server: DnsName,
    },
    // RFC 3596
    AAAA {
        name: DnsName,
        class: DnsClass,
        ttl: u32,
        address: Ipv6Addr,
    },
    // To implement
    // MD = 0x03,
    // MF = 0x04,
    // CNAME = 0x05,
    // SOA = 0x06,
    // MB = 0x07,
    // MG = 0x08,
    // MR = 0x09,
    // NULL = 0x0A,
    // WKS = 0x0B,
    // PTR = 0x0C,
    // HINFO = 0x0D,
    // MINFO = 0x0E,
    // MX = 0x0F,
    // TXT = 0x10,
}

impl DnsRecord {
    pub fn parse<'a>(
        reference_bytes: ParseInput<'a>,
    ) -> impl FnMut(ParseInput<'a>) -> ParseResult<'a, Self> {
        move |i: ParseInput<'a>| {
            let (i, name) = context("Name", DnsName::parse(reference_bytes))(i)?;
            let (i, record_type) = context("Type", map_res(be_u16, DnsRecordType::try_from))(i)?;
            let (i, class) = context("Class", map_res(be_u16, DnsClass::try_from))(i)?;
            let (i, ttl) = context("Time to live", be_u32)(i)?;
            let (i, len) = context("Data length", be_u16)(i)?;

            match record_type {
                DnsRecordType::A => {
                    let (i, bytes) = context("Address", take(len))(i)?;
                    let bytes: [u8; 4] = bytes.try_into().unwrap();
                    let address = Ipv4Addr::from(bytes);

                    Ok((
                        i,
                        Self::A {
                            name,
                            class,
                            ttl,
                            address,
                        },
                    ))
                }
                DnsRecordType::NS => {
                    let (i, bytes) = context("Name server", take(len))(i)?;
                    let (_, name_server) = DnsName::parse(reference_bytes)(bytes)?;

                    Ok((
                        i,
                        Self::NS {
                            name,
                            class,
                            ttl,
                            name_server,
                        },
                    ))
                }
                DnsRecordType::AAAA => {
                    let (i, bytes) = context("Address", take(len))(i)?;
                    let bytes: [u8; 16] = bytes.try_into().unwrap();
                    let address = Ipv6Addr::from(bytes);

                    Ok((
                        i,
                        Self::AAAA {
                            name,
                            class,
                            ttl,
                            address,
                        },
                    ))
                }
                _ => unreachable!(),
            }
        }
    }
}
