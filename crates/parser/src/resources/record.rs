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
    CNAME {
        name: DnsName,
        class: DnsClass,
        ttl: u32,
        canonical_name: DnsName,
    },
    // RFC 3596
    AAAA {
        name: DnsName,
        class: DnsClass,
        ttl: u32,
        address: Ipv6Addr,
    },
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
                DnsRecordType::CNAME => {
                    let (i, canonical_name) =
                        context("Canonical Name", DnsName::parse(reference_bytes))(i)?;

                    Ok((
                        i,
                        Self::CNAME {
                            name,
                            class,
                            ttl,
                            canonical_name,
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
                slice(name.to_bytes().unwrap()),
                be_u16(DnsRecordType::A as u16),
                be_u16(*class as u16),
                be_u32(*ttl),
                be_u16(address.octets().len() as u16),
                slice(address.octets().to_vec()),
            )),
            DnsRecord::NS {
                ref name,
                ref class,
                ref ttl,
                ref name_server,
            } => {
                let name_bytes = name.to_bytes().unwrap();

                tuple((
                    slice(name.to_bytes().unwrap()),
                    be_u16(DnsRecordType::NS as u16),
                    be_u16(*class as u16),
                    be_u32(*ttl),
                    be_u16(name_bytes.len() as u16),
                    slice(name_server.to_bytes().unwrap()),
                ))
            }
            DnsRecord::CNAME {
                ref name,
                ref class,
                ref ttl,
                ref canonical_name,
            } => {
                let name_bytes = name.to_bytes().unwrap();

                tuple((
                    slice(name.to_bytes().unwrap()),
                    be_u16(DnsRecordType::NS as u16),
                    be_u16(*class as u16),
                    be_u32(*ttl),
                    be_u16(name_bytes.len() as u16),
                    slice(canonical_name.to_bytes().unwrap()),
                ))
            }
            DnsRecord::AAAA {
                ref name,
                ref class,
                ref ttl,
                ref address,
            } => tuple((
                slice(name.to_bytes().unwrap()),
                be_u16(DnsRecordType::AAAA as u16),
                be_u16(*class as u16),
                be_u32(*ttl),
                be_u16(address.octets().len() as u16),
                slice(address.octets().to_vec()),
            )),
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GenError> {
        gen_simple(self.serialize(), Vec::new())
    }
}
