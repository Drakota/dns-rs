use crate::types::{ParseInput, ParseResult};

use nom::{bytes::complete::take, combinator::map, number::complete::be_u8};
use std::{fmt::Debug, str::from_utf8};

const COMPRESSION_MASK: u8 = 0xC0;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsLabel {
    pub data: Vec<u8>,
}

impl DnsLabel {
    pub fn new(data: ParseInput) -> Self {
        Self { data: data.into() }
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
        i: ParseInput<'a>,
        reference_bytes: ParseInput<'a>,
        mut labels: Vec<DnsLabel>,
    ) -> ParseResult<'a, Vec<DnsLabel>> {
        let (i, size) = be_u8(i)?;
        if size == 0x00 {
            return Ok((i, labels));
        }

        // If the size has the two most significant bits set, it
        // means that we need to jump to an offset in our reference_bytes
        // because of compression
        if (size & COMPRESSION_MASK) == COMPRESSION_MASK {
            let (i, offset) = be_u8(i)?;
            let (_, parts) = Self::process_name(
                &reference_bytes[(offset as usize)..],
                reference_bytes,
                labels,
            )?;
            return Ok((i, parts));
        }

        let (i, part) = take(size)(i)?;
        labels.push(DnsLabel::new(part));
        Self::process_name(i, reference_bytes, labels)
    }

    pub fn parse<'a>(
        reference_bytes: ParseInput<'a>,
    ) -> impl FnMut(ParseInput<'a>) -> ParseResult<'a, Self> {
        move |i: ParseInput<'a>| {
            map(
                |i| Self::process_name(i, reference_bytes, Vec::new()),
                |labels| Self { labels },
            )(i)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_name() {
        let bytes = [
            0x03, 0x77, 0x77, 0x77, // "www"
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, // "local"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // Null terminated
        ];

        let (_, name) = DnsName::parse(&[])(&bytes).unwrap();

        assert_eq!(name.labels.len(), 3);
        assert_eq!(name.labels[0].data, vec![0x77, 0x77, 0x77]);
        assert_eq!(name.labels[1].data, vec![0x6c, 0x6f, 0x63, 0x61, 0x6c]);
        assert_eq!(name.labels[2].data, vec![0x63, 0x6f, 0x6d]);
        assert_eq!(name, DnsName::from("www.local.com"));
    }

    #[test]
    fn test_parse_compressed_name() {
        let bytes = [
            0x03, 0x77, 0x77, 0x77, // "www"
            0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, // "local"
            0x03, 0x63, 0x6f, 0x6d, // "com"
            0x00, // Null terminated
            0x09, 0x73, 0x75, 0x62, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e, // "subdomain"
            0xC0, 0x04, // Compression jump to the fourth byte
        ];

        let (_, name) = DnsName::parse(&bytes)(&bytes[15..]).unwrap();

        assert_eq!(name.labels.len(), 3);
        assert_eq!(
            name.labels[0].data,
            vec![0x73, 0x75, 0x62, 0x64, 0x6f, 0x6d, 0x61, 0x69, 0x6e]
        );
        assert_eq!(name.labels[1].data, vec![0x6c, 0x6f, 0x63, 0x61, 0x6c]);
        assert_eq!(name.labels[2].data, vec![0x63, 0x6f, 0x6d]);
        assert_eq!(name, DnsName::from("subdomain.local.com"));
    }
}
