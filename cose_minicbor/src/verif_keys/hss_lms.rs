use crate::cose_keys::KeyMaterial;
use crate::errors::{CoseError, ErrorImpl};
use crate::verif_keys::VerifySignature;
use hbs_lms::{
    Sha256_256,
    signature::{Signature, Verifier},
};

pub(crate) struct HssLmsVerifyingKey(hbs_lms::VerifyingKey<hbs_lms::Sha256_256>);

impl HssLmsVerifyingKey {
    fn from_bytes(k: &[u8]) -> Result<Self, CoseError> {
        let vk = hbs_lms::VerifyingKey::<Sha256_256>::from_bytes(k)
            .map_err(|_| ErrorImpl::InconsistentDetails)?;
        Ok(HssLmsVerifyingKey(vk))
    }
}

impl<'a> TryFrom<KeyMaterial<'a>> for HssLmsVerifyingKey {
    type Error = CoseError;

    fn try_from(km: KeyMaterial<'a>) -> Result<Self, Self::Error> {
        if let KeyMaterial::HssLms(k) = km {
            HssLmsVerifyingKey::from_bytes(k)
        } else {
            Err(ErrorImpl::UnvalidKeySet)?
        }
    }
}

// HSSLMS
impl VerifySignature for HssLmsVerifyingKey {
    fn cose_verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), CoseError> {
        let signature =
            hbs_lms::Signature::from_bytes(sig).map_err(|_| ErrorImpl::InconsistentDetails)?;
        self.0
            .verify(msg, &signature)
            .map_err(|_| ErrorImpl::VerifyFailed.into())
    }
}
