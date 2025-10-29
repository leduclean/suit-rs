use crate::cose::HeaderMap;
use crate::errors::{CoseError, ErrorImpl};
use crate::keys::{CoseAlg, CoseKeySet, Curve, KeyMaterial, KeyOp, KeyType};
use crate::multitype::BytesBool;

/// Decodes a [`CoseKeySet`] from `keys`, selects the matching public key, adapts it to the underlying crypto library,
/// and calls the signature verification algorithm, passing in the key, bstr encoded ToBeSigned and the signature
/// as described in [RFC9052 section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4).
pub(crate) fn verify_cose_sign(
    keys: &[u8],
    to_be_signed: &[u8],
    headers: HeaderMap,
    signature: &[u8],
) -> Result<(), CoseError> {
    use hbs_lms::{
        Sha256_256, VerifyingKey as HbsVerifyingKey, signature::Signature,
        signature::Verifier as HbsVerifier,
    };
    use p256::ecdsa::{VerifyingKey, signature::Verifier};
    use p256::elliptic_curve::point::DecompressPoint;

    let key_set: CoseKeySet = minicbor::decode(keys)?;

    match headers.alg {
        Some(CoseAlg::ES256 | CoseAlg::ES256P256) => {
            if let KeyMaterial::Ec2 { x, y, crv } =
                key_set.match_and_get_key(KeyType::Ec2, headers.alg, KeyOp::Verify, headers.kid)?
            {
                if crv != Curve::P256 {
                    return Err(ErrorImpl::UnexpectedCurve.into());
                };
                let as_key = match y {
                    BytesBool::Bool(y_is_odd) => VerifyingKey::from_affine(
                        p256::AffinePoint::decompress(x.into(), (y_is_odd as u8).into())
                            .into_option()
                            .ok_or(ErrorImpl::InconsistentDetails)?,
                    )
                    .map_err(|_| ErrorImpl::InconsistentDetails)?,
                    BytesBool::Bytes(y) => VerifyingKey::from_encoded_point(
                        &p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false),
                    )
                    .map_err(|_| ErrorImpl::InconsistentDetails)?,
                };
                let signature = p256::ecdsa::Signature::from_slice(signature)
                    .map_err(|_| ErrorImpl::InconsistentDetails)?;
                as_key
                    .verify(to_be_signed, &signature)
                    .map_err(|_| ErrorImpl::VerifyFailed)?;
            } else {
                return Err(ErrorImpl::UnvalidKeySet.into());
            }
        }
        Some(CoseAlg::ED25519) => {
            if let KeyMaterial::Okp { x, crv } =
                key_set.match_and_get_key(KeyType::Okp, headers.alg, KeyOp::Verify, headers.kid)?
            {
                if crv != Curve::Ed25519 {
                    return Err(ErrorImpl::UnexpectedCurve.into());
                };
                let as_key = ed25519_dalek::VerifyingKey::try_from(x)
                    .map_err(|_| ErrorImpl::InconsistentDetails)?;
                let signature = ed25519_dalek::Signature::from_slice(signature)
                    .map_err(|_| ErrorImpl::InconsistentDetails)?;
                as_key
                    .verify(to_be_signed, &signature)
                    .map_err(|_| ErrorImpl::VerifyFailed)?;
            } else {
                return Err(ErrorImpl::UnvalidKeySet.into());
            }
        }
        Some(CoseAlg::HSSLMS) => {
            if let KeyMaterial::HssLms(k) = key_set.match_and_get_key(
                KeyType::HssLms,
                headers.alg,
                KeyOp::Verify,
                headers.kid,
            )? {
                let as_key: HbsVerifyingKey<Sha256_256> = hbs_lms::VerifyingKey::from_bytes(k)
                    .map_err(|_| ErrorImpl::InconsistentDetails)?;
                let signature = hbs_lms::Signature::from_bytes(signature)
                    .map_err(|_| ErrorImpl::InconsistentDetails)?;
                as_key
                    .verify(to_be_signed, &signature)
                    .map_err(|_| ErrorImpl::VerifyFailed)?;
            } else {
                return Err(ErrorImpl::UnvalidKeySet.into());
            }
        }
        _ => return Err(ErrorImpl::UnexpectedSignAlg.into()),
    }

    Ok(())
}
