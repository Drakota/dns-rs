use std::{convert::TryFrom, fmt::Debug, num::TryFromIntError};

use nom::{bits::complete::take, combinator::map_res, error::Error, IResult};

pub type BitInput<'a> = (&'a [u8], usize);
pub type BitResult<'a, T, E = Error<BitInput<'a>>> = IResult<BitInput<'a>, T, E>;

pub fn take_bits(count: usize) -> impl Fn(BitInput) -> BitResult<usize> {
    move |input: BitInput| take(count)(input)
}

pub fn map_bits<'a, F, O, E>(count: usize, f: F) -> impl FnMut(BitInput<'a>) -> BitResult<'a, O>
where
    F: FnMut(usize) -> Result<O, E> + Copy,
{
    move |input: BitInput| map_res(take_bits(count), f)(input)
}

pub struct Bool {
    value: bool,
}

impl Debug for Bool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.value)
    }
}

impl TryFrom<usize> for Bool {
    type Error = TryFromIntError;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        assert!(value <= 1, "Should be 0 or 1");
        Ok(Self { value: value == 1 })
    }
}
