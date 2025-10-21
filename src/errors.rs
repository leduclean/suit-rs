use core::{fmt::Debug, str::Utf8Error};
use thiserror::Error;

#[derive(Error, Debug, Default)]
#[error("{ctx}: {source}")]
pub struct SuitError {
    ctx: &'static str,
    #[source]
    source: ErrorImpl,
}

#[derive(Error, Debug, Default)]
enum ErrorImpl {
    #[error(transparent)]
    DecodeError(#[from] minicbor::decode::Error),
    #[error(transparent)]
    Utf8(#[from] Utf8Error),
    #[error("Vec overflow, capacity was {0}")]
    OutOfSpace(usize),
    #[error("Unknow op: {0}")]
    UnknowOp(i64),
    #[error("Indefinite length collection in entry")]
    IndefiniteLength,
    #[error("Default Error")]
    #[default]
    Default,
}

impl SuitError {
    pub fn with_ctx(mut self, ctx: &'static str) -> Self {
        self.ctx = ctx;
        self
    }

    pub fn out_of_space(capacity: usize) -> Self {
        ErrorImpl::OutOfSpace(capacity).into()
    }

    pub fn unknown_op(op: i64) -> Self {
        ErrorImpl::UnknowOp(op).into()
    }

    pub fn indefinite_length() -> Self {
        ErrorImpl::IndefiniteLength.into()
    }

    pub fn is_decode_error(&self) -> bool {
        matches!(self.source, ErrorImpl::DecodeError(_))
    }

    pub fn is_unknown_op(&self) -> bool {
        matches!(self.source, ErrorImpl::UnknowOp(_))
    }

    pub fn is_out_of_space(&self) -> bool {
        matches!(self.source, ErrorImpl::OutOfSpace(_))
    }

    pub fn is_indefinite_length(&self) -> bool {
        matches!(self.source, ErrorImpl::IndefiniteLength)
    }
}

impl<E> From<E> for SuitError
where
    ErrorImpl: From<E>,
{
    fn from(e: E) -> Self {
        SuitError {
            source: ErrorImpl::from(e),
            ..Default::default()
        }
    }
}
