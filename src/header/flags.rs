use super::utils::*;

use derive_try_from_primitive::*;
use nom::{combinator::map, error::context, sequence::tuple};
use std::convert::TryFrom;

#[derive(Debug, TryFromPrimitive, PartialEq, Eq)]
#[repr(usize)]
pub enum Opcode {
    // https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.1
    Query = 0x00,
    // Inverse Query Obsolete [RFC3425]
    IQuery = 0x01,
    Status = 0x02,
    // 3 Unassigned
    Notify = 0x04,
    Update = 0x05,
    // 6 - 15 reserved for future use
}

#[derive(Debug, TryFromPrimitive, PartialEq, Eq)]
#[repr(usize)]
pub enum ReplyCode {
    NoError = 0x00,
    FormatError = 0x01,
    ServerFailure = 0x02,
    NameError = 0x03,
    NotImplemented = 0x04,
    Refused = 0x05,
}

#[derive(Debug, PartialEq, Eq)]
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

impl Default for DnsHeaderFlags {
    fn default() -> Self {
        Self {
            response: false,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recdesired: false,
            recavail: false,
            z: false,
            authenticated: false,
            checkdisable: false,
            rcode: ReplyCode::NoError,
        }
    }
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
