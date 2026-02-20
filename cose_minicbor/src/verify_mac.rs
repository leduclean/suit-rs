use crate::errors::{CoseError, ErrorImpl};

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
