mod flags;
mod utils;

use self::flags::DnsHeaderFlags;

use nom::{bits::bits, error::context, number::complete::le_u16, IResult};

#[derive(Debug)]
pub struct DnsHeader {
    pub transaction_id: u16,
    pub flags: DnsHeaderFlags,
    // pub questions: u16,
    // pub answers: u16,
    // pub auth_rr: u16,
    // pub add_rr: u16,
}

impl DnsHeader {
    pub fn parse(i: &[u8]) -> IResult<&[u8], Self> {
        let (i, transaction_id) = context("Transaction ID", le_u16)(i)?;
        let (i, flags) = bits(DnsHeaderFlags::parse)(i)?;

        Ok((
            i,
            Self {
                transaction_id,
                flags,
            },
        ))
    }
}
