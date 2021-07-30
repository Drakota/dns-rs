use std::{
    fmt::{Debug, Display},
    ops::RangeFrom,
};

use nom::{
    error::{
        ContextError, ErrorKind as NomErrorKind, FromExternalError, ParseError as NomParseError,
    },
    Err as NomErr, ErrorConvert, IResult, Slice,
};
use std::error::Error;

pub type BitInput<'a> = (&'a [u8], usize);
pub type BitResult<'a, T> = IResult<BitInput<'a>, T, ParseError<BitInput<'a>>>;

pub type ParseInput<'a> = &'a [u8];
pub type ParseResult<'a, T> = IResult<ParseInput<'a>, T, ParseError<ParseInput<'a>>>;

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(&'static str),
}

pub struct ParseError<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl Error for ParseError<Vec<u8>> {}

impl<'a> Debug for ParseError<ParseInput<'a>> {
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

impl Debug for ParseError<Vec<u8>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl Display for ParseError<Vec<u8>> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", &self)
    }
}

impl<I> NomParseError<I> for ParseError<I> {
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

impl<I> ContextError<I> for ParseError<I> {
    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

impl<I, E> FromExternalError<I, E> for ParseError<I> {
    fn from_external_error(input: I, kind: NomErrorKind, _e: E) -> Self {
        Self {
            errors: vec![(input, ErrorKind::Nom(kind))],
        }
    }
}

impl<I> ErrorConvert<ParseError<I>> for ParseError<(I, usize)>
where
    I: Slice<RangeFrom<usize>>,
{
    fn convert(self) -> ParseError<I> {
        let errors = self
            .errors
            .into_iter()
            .map(|((rest, offset), err)| (rest.slice(offset / 8..), err))
            .collect();
        ParseError { errors }
    }
}

impl From<NomErr<ParseError<&[u8]>>> for ParseError<Vec<u8>> {
    fn from(err: NomErr<ParseError<&[u8]>>) -> Self {
        match err {
            NomErr::Error(e) => Self {
                errors: e
                    .errors
                    .into_iter()
                    .map(|(input, error_kind)| (input.to_vec(), error_kind))
                    .collect(),
            },
            NomErr::Failure(e) => Self {
                errors: e
                    .errors
                    .into_iter()
                    .map(|(input, error_kind)| (input.to_vec(), error_kind))
                    .collect(),
            },
            _ => unimplemented!(),
        }
    }
}
