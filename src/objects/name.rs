use nom::{bytes::complete::take, combinator::map, number::complete::be_u8, IResult};

#[derive(Debug)]
pub struct Name {}

impl Name {
    pub fn process_name<'a>(
        i: &'a [u8],
        mut parts: Vec<String>,
        lookup_bytes: &[u8],
    ) -> IResult<&'a [u8], Vec<String>> {
        let (i, size) = be_u8(i)?;
        if size == 0x0 {
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
