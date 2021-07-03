use nom::{bytes::complete::take, combinator::map, number::complete::be_u8, IResult};

const COMPRESSION_MASK: u8 = 0xC0;

#[derive(Debug)]
pub struct DnsName {}

impl DnsName {
    pub fn process_name<'a>(
        i: &'a [u8],
        mut parts: Vec<String>,
        lookup_bytes: &'a [u8],
    ) -> IResult<&'a [u8], Vec<String>> {
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
        parts.push(String::from_utf8_lossy(part).into_owned());
        Self::process_name(i, parts, lookup_bytes)
    }

    pub fn parse<'a>(lookup_bytes: &'a [u8]) -> impl FnMut(&'a [u8]) -> IResult<&[u8], String> {
        move |i: &[u8]| {
            map(
                |i| Self::process_name(i, Vec::new(), lookup_bytes),
                |parts| parts.join("."),
            )(i)
        }
    }
}
