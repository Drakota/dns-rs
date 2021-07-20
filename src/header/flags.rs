use super::utils::*;
use crate::types::{BitInput, BitResult};

use cookie_factory::{self as cf, gen_simple, GenError, SerializeFn};
use derive_try_from_primitive::*;
use nom::{combinator::map, error::context, sequence::tuple};
use std::{convert::TryFrom, io::Write};

#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Clone, Copy)]
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

#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Clone, Copy)]
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

    pub fn serialize<'a, W: Write + 'a>(&'a self) -> impl SerializeFn<W> + 'a {
        use cf::combinator::slice;

        move |out| {
            slice(vec![
                (self.recdesired as u8)
                    | ((self.truncated as u8) << 1)
                    | ((self.authoritative as u8) << 2)
                    | ((self.opcode as u8) << 3)
                    | ((self.response as u8) << 7) as u8,
                (self.rcode as u8)
                    | ((self.checkdisable as u8) << 4)
                    | ((self.authenticated as u8) << 5)
                    | ((self.z as u8) << 6)
                    | ((self.recavail as u8) << 7),
            ])(out)
        }
    }

    pub fn to_bytes(&self) -> Result<Vec<u8>, GenError> {
        gen_simple(self.serialize(), Vec::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serialize() {
        let flags = DnsHeaderFlags {
            response: true,
            opcode: Opcode::Query,
            authoritative: false,
            truncated: false,
            recdesired: true,
            recavail: true,
            z: false,
            authenticated: false,
            checkdisable: false,
            rcode: ReplyCode::NoError,
        };

        assert_eq!(flags.to_bytes().unwrap(), vec![0x81, 0x80]);

        // 0010 1101 1001 0010
        let flags = DnsHeaderFlags {
            response: false,
            opcode: Opcode::Update,
            authoritative: true,
            truncated: false,
            recdesired: true,
            recavail: true,
            z: false,
            authenticated: false,
            checkdisable: true,
            rcode: ReplyCode::ServerFailure,
        };

        assert_eq!(flags.to_bytes().unwrap(), vec![0x2D, 0x92]);
    }
}
