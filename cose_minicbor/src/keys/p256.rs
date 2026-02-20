use crate::cose_keys::{Curve, KeyMaterial};
use crate::errors::{CoseError, ErrorImpl};
use crate::keys::VerifySignature;
use crate::multitype::BytesBool;
use p256::ecdsa::signature::Verifier;
use p256::elliptic_curve::point::DecompressPoint;

pub struct P256VerifyingKey(pub p256::ecdsa::VerifyingKey);

impl P256VerifyingKey {
    /// Build the signature verification key from the two elliptic_curve points
    /// It supports both single point and affine coordinates.
    ///
    /// * `x`: x coordinate
    /// * `y`: y coordinate
    fn from_coordinates(x: &[u8], y: BytesBool) -> Result<Self, CoseError> {
        let vk = match y {
            BytesBool::Bool(y_is_odd) => p256::ecdsa::VerifyingKey::from_affine(
                p256::AffinePoint::decompress(x.into(), (y_is_odd as u8).into())
                    .into_option()
                    .ok_or(ErrorImpl::InconsistentDetails)?,
            )
            .map_err(|_| ErrorImpl::InconsistentDetails)?,
            BytesBool::Bytes(y_bytes) => p256::ecdsa::VerifyingKey::from_encoded_point(
                &p256::EncodedPoint::from_affine_coordinates(x.into(), y_bytes.into(), false),
            )
            .map_err(|_| ErrorImpl::InconsistentDetails)?,
        };

        Ok(P256VerifyingKey(vk))
    }
}

impl<'a> TryFrom<KeyMaterial<'a>> for P256VerifyingKey {
    type Error = CoseError;

    fn try_from(km: KeyMaterial<'a>) -> Result<Self, Self::Error> {
        if let KeyMaterial::Ec2 { x, y, crv } = km {
            crv.check_curve(Curve::P256)?;
            P256VerifyingKey::from_coordinates(x, y)
        } else {
            Err(ErrorImpl::UnvalidKeySet)?
        }
    }
}

impl VerifySignature for P256VerifyingKey {
    fn cose_verify(&self, msg: &[u8], sig: &[u8]) -> Result<(), CoseError> {
        let signature =
            p256::ecdsa::Signature::from_slice(sig).map_err(|_| ErrorImpl::InconsistentDetails)?;
        self.0
            .verify(msg, &signature)
            .map_err(|_| ErrorImpl::VerifyFailed.into())
    }
}
