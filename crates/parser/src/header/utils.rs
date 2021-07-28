use crate::types::{BitInput, BitResult};

use nom::{bits::complete::take, combinator::map_res};

pub fn take_bits(count: usize) -> impl Fn(BitInput) -> BitResult<usize> {
    move |input: BitInput| take(count)(input)
}

pub fn map_bits<'a, F, O, E>(count: usize, f: F) -> impl FnMut(BitInput<'a>) -> BitResult<'a, O>
where
    F: FnMut(usize) -> Result<O, E> + Copy,
{
    move |input: BitInput| map_res(take_bits(count), f)(input)
}

pub fn convert_bit_to_bool(value: usize) -> Result<bool, ()> {
    assert!(value <= 1, "Should be 0 or 1");
    Ok(value == 1)
}
