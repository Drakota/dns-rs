use std::{fmt::Debug, ops::RangeFrom};

use nom::{
    error::{ContextError, ErrorKind as NomErrorKind, FromExternalError, ParseError},
    ErrorConvert, IResult, Slice,
};

pub type BitInput<'a> = (&'a [u8], usize);
pub type BitResult<'a, T> = IResult<BitInput<'a>, T, Error<BitInput<'a>>>;

pub type ParseInput<'a> = &'a [u8];
pub type ParseResult<'a, T> = IResult<ParseInput<'a>, T, Error<ParseInput<'a>>>;

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(&'static str),
}

pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<'a> Debug for Error<ParseInput<'a>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "dns-rs parsing error\n[Stacktrace]:")?;
        for (input, kind) in self.errors.iter().rev() {
            let prefix = match kind {
                ErrorKind::Context(ctx) => format!("> in {}", ctx),
                ErrorKind::Nom(err) => format!("* nom error: {:?}", err),
            };

            let maxlen = 40;
            let input = if input.len() > maxlen {
                &input[input.len() - maxlen..]
            } else {
                input
            };

            writeln!(f, "{:<30} {:02X?}", prefix, input)?;
        }
        Ok(())
    }
}

impl<I> ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        Self {
            errors: vec![(input, ErrorKind::Nom(kind))],
        }
    }

    fn append(input: I, kind: NomErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }
}

impl<I> ContextError<I> for Error<I> {
    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

impl<I, E> FromExternalError<I, E> for Error<I> {
    fn from_external_error(input: I, kind: NomErrorKind, _e: E) -> Self {
        Self {
            errors: vec![(input, ErrorKind::Nom(kind))],
        }
    }
}

impl<I> ErrorConvert<Error<I>> for Error<(I, usize)>
where
    I: Slice<RangeFrom<usize>>,
{
    fn convert(self) -> Error<I> {
        let errors = self
            .errors
            .into_iter()
            .map(|((rest, offset), err)| (rest.slice(offset / 8..), err))
            .collect();
        Error { errors }
    }
}
