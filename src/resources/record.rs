use super::{name::DnsName, DnsClass, DnsRecordType};
use crate::types::{ParseInput, ParseResult};

use cookie_factory::{self as cf, gen_simple, GenError, SerializeFn};
use std::io::Write;

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
                DnsRecordType::NS => {
                    let (i, name_server) =
                        context("Name Server", DnsName::parse(reference_bytes))(i)?;

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
                _ => unimplemented!(),
            }
        }
    }

    pub fn serialize<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        use cf::{
            bytes::{be_u16, be_u32},
            combinator::slice,
            sequence::tuple,
        };

        match self {
            DnsRecord::A {
                ref name,
                ref class,
                ref ttl,
                ref address,
            } => tuple((
                name.serialize(),
                be_u16(DnsRecordType::A as u16),
                be_u16(*class as u16),
                be_u32(*ttl),
                slice(address.octets().to_vec()),
            )),
            DnsRecord::AAAA {
                ref name,
                ref class,
                ref ttl,
                ref address,
            } => tuple((
                name.serialize(),
                be_u16(DnsRecordType::AAAA as u16),
                be_u16(*class as u16),
                be_u32(*ttl),
                slice(address.octets().to_vec()),
            )),
            _ => unimplemented!(),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GenError> {
        gen_simple(self.serialize(), Vec::new())
    }
}
