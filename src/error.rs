use nom::error::{ErrorKind, ParseError};

#[derive(Debug)]
pub enum IPsecError {
    PayloadTooSmall,
    ExtraBytesInPayload,
    PayloadParseError,

    NomError(ErrorKind),
}

impl<I> ParseError<I> for IPsecError {
    fn from_error_kind(_input: I, kind: ErrorKind) -> Self {
        IPsecError::NomError(kind)
    }
    fn append(_input: I, _kind: ErrorKind, other: Self) -> Self {
        other
    }
}
