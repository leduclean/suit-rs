use core::{fmt::Debug, str::Utf8Error};
use thiserror::Error;

#[derive(Error, Debug, Default)]
#[error("{ctx}: {source}")]
pub struct CoseError {
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
    Utf8(#[from] Utf8Error),

    #[error("Missing detached payload")]
    MissingPayload,

    #[error("Input data is understood, but self-contradictory.")]
    InconsistentDetails,

    #[error(
        "Data could be processed and keys were found, but cryptographic verification was unsuccessful."
    )]
    VerifyFailed,

    #[error("Unexpected alg for signature verifying (only ES256 supported)")]
    UnexpectedSignAlg,

    #[error(
        "Unexpected alg for MAC authentification, (only HMAC 256/256 and  HMAC 256/64 supported)"
    )]
    UnexpectedMacAlg,

    #[error(
        "Unexpected Curve founded during ECDH key exchange, (only supports P256, P512, X25519)"
    )]
    UnexpectedCurve,

    #[error("UnexpectedAgl associated with the key type")]
    UnexpectedAlg,

    #[error("Missing key for authentification")]
    UnvalidKeySet,

    #[error("Missing Key in SuitKey")]
    MissingKeyValue,

    #[error("Missing Curve in SuitKey EC2 or OKP")]
    MissingCurve,

    #[error("Key value not compatible")]
    UncompatibleKeyField,

    #[error("Invalid key length")]
    InvalidKeyLength,

    #[error("Invalid Mac ")]
    MacInvalid,

    #[error(transparent)]
    CapacityError(#[from] heapless::CapacityError),

    #[error("Vec overflow, capacity was {0}")]
    OutOfSpace(usize),

    #[error("Default Error")]
    #[default]
    Default,
}

impl<E> From<E> for CoseError
where
    ErrorImpl: From<E>,
{
    fn from(e: E) -> Self {
        CoseError {
            source: ErrorImpl::from(e),
            ..Default::default()
        }
    }
}
