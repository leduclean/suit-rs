use crate::errors::CoseError;

/// Trait for the common verification procedure for each  
/// cryptographic algorithm implementened.
pub(crate) trait VerifySignature {
    fn cose_verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), CoseError>;
}

#[cfg(feature = "es256")]
pub mod p256;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[cfg(feature = "hss_lms")]
pub mod hss_lms;
