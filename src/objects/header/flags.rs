use super::utils::*;

use derive_try_from_primitive::*;
use nom::{combinator::map, error::context, sequence::tuple};
use std::convert::TryFrom;

#[derive(Debug, TryFromPrimitive)]
#[repr(usize)]
pub enum Message {
    Query = 0x0,
    Response = 0x1,
}

#[derive(Debug, TryFromPrimitive)]
#[repr(usize)]
pub enum Opcode {
    Query = 0x0,
    IQuery = 0x1,
    Status = 0x2,
    // 3 - 15 reserved for future use
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
}

#[derive(Debug, TryFromPrimitive)]
#[repr(usize)]
pub enum ReplyCode {
    NoError = 0x0,
    FormatError = 0x1,
    ServerFailure = 0x2,
    NameError = 0x3,
    NotImplemented = 0x4,
    Refused = 0x5,
}

#[derive(Debug)]
pub struct DnsHeaderFlags {
    pub response: Message,
    pub opcode: Opcode,
    pub authoritative: Bool,
    pub truncated: Bool,
    pub recdesired: Bool,
    pub recavail: Bool,
    pub z: Bool,
    pub authenticated: Bool,
    pub checkdisable: Bool,
    pub rcode: ReplyCode,
}

impl DnsHeaderFlags {
    pub fn parse(i: BitInput) -> BitResult<Self> {
        map(
            tuple((
                context("Response", map_bits(1_usize, Message::try_from)),
                context("Opcode", map_bits(4_usize, Opcode::try_from)),
                context("Authoritative", map_bits(1_usize, Bool::try_from)),
                context("Truncated", map_bits(1_usize, Bool::try_from)),
                context("Recursion desired", map_bits(1_usize, Bool::try_from)),
                context("Recursion available", map_bits(1_usize, Bool::try_from)),
                context("Z", map_bits(1_usize, Bool::try_from)),
                context("Authenticated", map_bits(1_usize, Bool::try_from)),
                context("Check disable", map_bits(1_usize, Bool::try_from)),
                context("Reply code", map_bits(4_usize, ReplyCode::try_from)),
            )),
            |(
                response,
                opcode,
                authoritative,
                truncated,
                recdesired,
                recavail,
                z,
                authenticated,
                checkdisable,
                rcode,
            )| Self {
                response,
                opcode,
                authoritative,
                truncated,
                recdesired,
                recavail,
                z,
                authenticated,
                checkdisable,
                rcode,
            },
        )(i)
    }
}
