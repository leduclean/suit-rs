//! This module defines the crypto trait handler for the suit manifest processing.
//! You can either use your own crypto backend supplying the two
use crate::SuitError;

/// Trait to handle the cryptographic backend for SUIT manifest verification.
///
/// # Example using the default backend
///
/// ```ignore
/// use suit_validator::crypto::{CoseCrypto, SuitCrypto};
/// use suit_validator::suit_decode;
///
/// // Example keys: 32 bytes of zeros (for testing only)
/// let keys = vec![0u8; 32];
/// let crypto = CoseCrypto::new(&keys);
///
/// let data = vec![/* CBOR manifest */];
/// let mut handler = /* your handler */;
/// suit_decode(&data, &mut handler, &mut crypto)?;
/// ```
///
/// In production, `keys` should be a valid CBOR-encoded COSE KeySet.
pub trait SuitCrypto {
    fn verify_cose(&self, auth_bytes: &[u8], digest_bytes: &[u8]) -> Result<(), SuitError>;
}

#[cfg(feature = "default_crypto")]
use cose_minicbor::cose::{CoseMac, CoseMac0, CoseSign, CoseSign1};

#[cfg(feature = "default_crypto")]
/// Default crypto backend using cose_minicbor basic
/// backend.
///
/// * `keys`: CoseKey set bytes.
pub struct CoseCrypto<'a> {
    // Cose Key set bytes
    keys: &'a [u8],
}

#[cfg(feature = "default_crypto")]
impl<'a> CoseCrypto<'a> {
    pub fn new(keys_bytes: &'a [u8]) -> Self {
        CoseCrypto { keys: keys_bytes }
    }
}

#[cfg(feature = "default_crypto")]
impl<'a> SuitCrypto for CoseCrypto<'a> {
    fn verify_cose(&self, auth_bytes: &[u8], digest_bytes: &[u8]) -> Result<(), SuitError> {
        let mut d = minicbor::Decoder::new(auth_bytes);
        let tag = d.tag()?;
        match tag.as_u64() {
            17 => {
                let mac0: CoseMac0 = d.decode()?;
                mac0.suit_verify_mac0(Some(digest_bytes), self.keys)?;
                Ok(())
            }
            18 => {
                let sign1: CoseSign1 = d.decode()?;
                sign1.suit_verify_cose_sign1(Some(digest_bytes), self.keys)?;
                Ok(())
            }
            97 => {
                let mac: CoseMac = d.decode()?;
                mac.suit_verify_mac(Some(digest_bytes), self.keys)?;
                Ok(())
            }
            98 => {
                let sign: CoseSign = d.decode()?;
                sign.suit_verify_cose_sign(Some(digest_bytes), self.keys)?;
                Ok(())
            }
            _ => Err(minicbor::decode::Error::tag_mismatch(tag)
                .with_message("SuitAuthenticationBlock: unexpected tag value")
                .into()),
        }
    }
}
