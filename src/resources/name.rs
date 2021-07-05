use std::{fmt::Debug, str::from_utf8};

use nom::{bytes::complete::take, combinator::map, number::complete::be_u8, IResult};

const COMPRESSION_MASK: u8 = 0xC0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLabel {
    pub length: u8,
    pub data: Vec<u8>,
}

impl DnsLabel {
    pub fn new(data: &[u8]) -> Self {
        Self {
            length: data.len() as u8,
            data: data.into(),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub struct DnsName {
    labels: Vec<DnsLabel>,
}

impl Debug for DnsName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let name: Vec<&str> = self
            .labels
            .iter()
            .map(|label| from_utf8(&label.data[..]).unwrap())
            .collect();
        write!(f, "{}", name.join("."))
    }
}

impl From<&str> for DnsName {
    fn from(s: &str) -> Self {
        Self {
            labels: s.split('.').map(|s| DnsLabel::new(s.as_bytes())).collect(),
        }
    }
}

impl DnsName {
    pub fn process_name<'a>(
        i: &'a [u8],
        mut parts: Vec<DnsLabel>,
        lookup_bytes: &'a [u8],
    ) -> IResult<&'a [u8], Vec<DnsLabel>> {
        let (i, size) = be_u8(i)?;
        if size == 0x00 {
            return Ok((i, parts));
        }

        // If the size has the two most significant bits set, it
        // means that we need to jump to an offset in our lookup_bytes
        // because of compression
        if (size & COMPRESSION_MASK) == COMPRESSION_MASK {
            let (i, offset) = be_u8(i)?;
            let (_, parts) =
                Self::process_name(&lookup_bytes[(offset as usize)..], parts, lookup_bytes)?;
            return Ok((i, parts));
        }

        let (i, part) = take(size)(i)?;
        parts.push(DnsLabel::new(part));
        Self::process_name(i, parts, lookup_bytes)
    }

    pub fn parse<'a>(lookup_bytes: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&[u8], Self> {
        move |i: &[u8]| {
            map(
                |i| Self::process_name(i, Vec::new(), lookup_bytes),
                |labels| Self { labels },
            )(i)
        }
    }
}
