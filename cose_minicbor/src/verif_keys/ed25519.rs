use crate::cose_keys::{Curve, KeyMaterial};
use crate::errors::{CoseError, ErrorImpl};
use crate::verif_keys::VerifySignature;
use ed25519_dalek::Verifier;

pub(crate) struct Ed25519VerifyingKey(ed25519_dalek::VerifyingKey);

impl Ed25519VerifyingKey {
    /// Build the signature verification key from the ed25519 coordinate point.
    ///
    /// * `x`: x coordinate
    fn from_coordinate(x: &[u8]) -> Result<Self, CoseError> {
        Ok(Ed25519VerifyingKey(
            ed25519_dalek::VerifyingKey::try_from(x).map_err(|_| ErrorImpl::InconsistentDetails)?,
        ))
    }
}

impl<'a> TryFrom<KeyMaterial<'a>> for Ed25519VerifyingKey {
    type Error = CoseError;

    fn try_from(km: KeyMaterial<'a>) -> Result<Self, Self::Error> {
        if let KeyMaterial::Okp { x, crv } = km {
            crv.check_curve(Curve::Ed25519)?;
            Ed25519VerifyingKey::from_coordinate(x)
        } else {
            Err(ErrorImpl::UnvalidKeySet)?
        }
    }
}

// Ed25519/Okp
impl VerifySignature for Ed25519VerifyingKey {
    fn cose_verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), CoseError> {
        let signature = ed25519_dalek::Signature::from_slice(sig)
            .map_err(|_| ErrorImpl::InconsistentDetails)?;
        self.0
            .verify(msg, &signature)
            .map_err(|_| ErrorImpl::VerifyFailed.into())
    }
}
