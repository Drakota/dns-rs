use nom::{bytes::complete::take, IResult};

use std::fmt::Debug;

#[derive(Clone, PartialEq, Eq)]
pub struct DnsAddress {
    address: Vec<u8>,
}

impl Debug for DnsAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.address.len() {
            // IPv4
            4 => write!(
                f,
                "{}.{}.{}.{}",
                self.address[0], self.address[1], self.address[2], self.address[3]
            ),

            _ => panic!("Unable to serialize address..."),
        }
    }
}

impl DnsAddress {
    pub fn parse(len: u16) -> impl FnMut(&[u8]) -> IResult<&[u8], Self> {
        move |i: &[u8]| {
            let (i, address) = take(len)(i)?;
            Ok((
                i,
                Self {
                    address: address.into(),
                },
            ))
        }
    }
}
