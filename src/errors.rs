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
    #[error("Default Error")]
    #[default]
    Default,
}

impl SuitError {
    pub fn with_ctx(mut self, ctx: &'static str) -> Self {
        self.ctx = ctx;
        self
    }

    pub fn vec_overflow(capacity: usize) -> Self {
        ErrorImpl::OutOfSpace(capacity).into()
    }

    pub fn unknown_op(op: i64) -> Self {
        ErrorImpl::UnknowOp(op).into()
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
