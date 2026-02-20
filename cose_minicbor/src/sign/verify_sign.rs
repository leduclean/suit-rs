use crate::common::HeaderMap;
use crate::cose_keys::{CoseAlg, CoseKeySet, KeyMaterial, KeyOp, KeyType};
use crate::errors::{CoseError, ErrorImpl};

#[cfg(feature = "es256")]
use crate::verif_keys::p256::P256VerifyingKey;

#[cfg(feature = "ed25519")]
use crate::verif_keys::ed25519::Ed25519VerifyingKey;

#[cfg(feature = "hss_lms")]
use crate::verif_keys::hss_lms::HssLmsVerifyingKey;

#[cfg(any(feature = "es256", feature = "ed25519", feature = "hss_lms"))]
use crate::verif_keys::VerifySignature;

#[inline]
#[allow(dead_code)]
pub fn get_verified_key<'a, K>(
    key_set: &'a CoseKeySet,
    kty: KeyType,
    alg: CoseAlg,
    kid: Option<&[u8]>,
) -> Result<K, CoseError>
where
    K: TryFrom<KeyMaterial<'a>, Error = CoseError>,
{
    let key_material = key_set.match_and_get_key(kty, Some(alg), KeyOp::Verify, kid)?;
    K::try_from(key_material)
}

/// Decodes a [`CoseKeySet`] from `keys`, selects the matching public key, adapts it to the underlying crypto library,
/// and calls the signature verification algorithm, passing in the key, bstr encoded ToBeSigned and the signature
/// as described in [RFC9052 section 4.4](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.4).
#[allow(unused_variables)]
pub(crate) fn verify_cose_sign(
    keys: &[u8],
    to_be_signed: &[u8],
    headers: HeaderMap,
    signature: &[u8],
) -> Result<(), CoseError> {
    let key_set: CoseKeySet = minicbor::decode(keys)?;

    match headers.alg {
        #[cfg(feature = "es256")]
        Some(CoseAlg::ES256 | CoseAlg::ES256P256) => {
            let vk: P256VerifyingKey =
                get_verified_key(&key_set, KeyType::Ec2, CoseAlg::ES256, headers.kid)?;
            vk.cose_verify(to_be_signed, signature)?;
            Ok(())
        }
        #[cfg(feature = "ed25519")]
        Some(CoseAlg::ED25519) => {
            let vk: Ed25519VerifyingKey =
                get_verified_key(&key_set, KeyType::Okp, CoseAlg::ED25519, headers.kid)?;
            vk.cose_verify(to_be_signed, signature)?;
            Ok(())
        }
        #[cfg(feature = "hss_lms")]
        Some(CoseAlg::HSSLMS) => {
            let vk: HssLmsVerifyingKey =
                get_verified_key(&key_set, KeyType::HssLms, CoseAlg::HSSLMS, headers.kid)?;
            vk.cose_verify(to_be_signed, signature)?;
            Ok(())
        }
        _ => Err(ErrorImpl::UnexpectedSignAlg.into()),
    }
}
