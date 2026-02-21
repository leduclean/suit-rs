#![cfg(feature = "hmac")]
use crate::common::HeaderMap;
use crate::cose_keys::{CoseAlg, CoseKeySet, KeyMaterial, KeyOp, KeyType};
use crate::errors::{CoseError, ErrorImpl};

pub(crate) fn verify_cose_mac(
    key_bytes: &[u8],
    headers: HeaderMap,
    to_be_maced: &[u8],
    tag: &[u8],
) -> Result<(), CoseError> {
    let key_set: CoseKeySet = minicbor::decode(key_bytes)?;
    if !matches!(
        headers.alg,
        Some(CoseAlg::HMAC256256) | Some(CoseAlg::HMAC25664)
    ) {
        Err(ErrorImpl::UnexpectedMacAlg.into())
    } else {
        let key = match key_set.match_and_get_key(
            KeyType::Symmetric,
            headers.alg,
            KeyOp::MACVerify,
            headers.kid,
        )? {
            KeyMaterial::Symmetric(k) => k,
            _ => return Err(ErrorImpl::UnvalidKeySet.into()),
        };

        verify_mac(key, to_be_maced, tag)
    }
}

/// Calls the MAC creation algorithm, passing in the key, and the bstr encoded ToBeMaced.
/// Then compares the MAC value to the tag provided as described in [RFC9052 section 6.3](https://www.rfc-editor.org/rfc/rfc9052.html#section-6.3).
pub(crate) fn verify_mac(
    key_bytes: &[u8],
    to_be_maced: &[u8],
    tag: &[u8],
) -> Result<(), CoseError> {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    if key_bytes.len() < 16 {
        return Err(ErrorImpl::InvalidKeyLength.into());
    }

    let mut mac =
        Hmac::<Sha256>::new_from_slice(key_bytes).map_err(|_| ErrorImpl::InvalidKeyLength)?;
    mac.update(to_be_maced);

    mac.verify_truncated_left(tag)
        .map_err(|_| ErrorImpl::MacInvalid)?;
    Ok(())
}
