use super::utils::*;

use derive_try_from_primitive::*;
use nom::{combinator::map, error::context, sequence::tuple};
use std::convert::TryFrom;

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
    pub response: bool,
    pub opcode: Opcode,
    pub authoritative: bool,
    pub truncated: bool,
    pub recdesired: bool,
    pub recavail: bool,
    pub z: bool,
    pub authenticated: bool,
    pub checkdisable: bool,
    pub rcode: ReplyCode,
}

impl DnsHeaderFlags {
    pub fn parse(i: BitInput) -> BitResult<Self> {
        map(
            tuple((
                context("Response", map_bits(1_usize, convert_bit_to_bool)),
                context("Opcode", map_bits(4_usize, Opcode::try_from)),
                context("Authoritative", map_bits(1_usize, convert_bit_to_bool)),
                context("Truncated", map_bits(1_usize, convert_bit_to_bool)),
                context("Recursion desired", map_bits(1_usize, convert_bit_to_bool)),
                context(
                    "Recursion available",
                    map_bits(1_usize, convert_bit_to_bool),
                ),
                context("Z", map_bits(1_usize, convert_bit_to_bool)),
                context("Authenticated", map_bits(1_usize, convert_bit_to_bool)),
                context("Check disable", map_bits(1_usize, convert_bit_to_bool)),
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
