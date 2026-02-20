use core::fmt::Debug;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CborError {
    #[error(transparent)]
    DecodeError(#[from] minicbor::decode::Error),
}
