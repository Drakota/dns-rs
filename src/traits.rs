use nom::IResult;

pub trait Parsable {
    fn parse(i: &[u8]) -> IResult<&[u8], Self>
    where
        Self: Sized;
}
