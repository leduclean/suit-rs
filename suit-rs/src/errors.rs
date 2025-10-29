use core::{fmt::Debug, str::Utf8Error};
use thiserror::Error;

#[derive(Error, Debug, Default)]
#[error("{ctx}: {source}")]
pub struct SuitError {
    ctx: &'static str,
    #[source]
    pub(crate) source: ErrorImpl,
}

#[derive(Error, Debug, Default)]
pub(crate) enum ErrorImpl {
    #[error(transparent)]
    DecodeError(#[from] minicbor::decode::Error),

    #[error(transparent)]
    EncodeError(#[from] minicbor::encode::Error<heapless::CapacityError>),

    #[error(transparent)]
    CborError(#[from] suit_cbor::errors::CborError),

    #[error(transparent)]
    CoseError(#[from] cose_minicbor::errors::CoseError),

    #[error(transparent)]
    Utf8(#[from] Utf8Error),

    #[error("Invalid Digest")]
    InvalidDigest,

    #[error(
        "Unexpected alg for digest verifying, found alg id {0}, (only SHA256, SHA384 and SHA521 are supported)"
    )]
    UnexpectedHashAlg(i32),

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

    pub fn out_of_space(capacity: usize) -> Self {
        ErrorImpl::OutOfSpace(capacity).into()
    }

    pub fn unknown_op(op: i64) -> Self {
        ErrorImpl::UnknowOp(op).into()
    }

    pub fn unexpected_hash_alg(id: i32) -> Self {
        ErrorImpl::UnexpectedHashAlg(id).into()
    }

    pub fn invalid_digest() -> Self {
        ErrorImpl::InvalidDigest.into()
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
