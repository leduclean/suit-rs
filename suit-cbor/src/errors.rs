use core::{fmt::Debug, str::Utf8Error};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CborError {
    #[error(transparent)]
    DecodeError(#[from] minicbor::decode::Error),

    #[error(transparent)]
    Utf8(#[from] Utf8Error),

    #[error("Invalid Digest")]
    InvalidDigest,
}
