use crate::common::{BstrHeaderMap, HeaderMap, MAX_SUPPORTED_ACCESSTOKEN_LEN};
use crate::cose_recipient::IterCoseRecipient;
use crate::errors::{CoseError, ErrorImpl};
use crate::hmac::verify_mac;
use minicbor::{Decode, Encode};

#[allow(dead_code)]
const MAX_CEK_KEY_LEN: usize = 64;

/// `Cose_MAC0` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with implicit key.
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseMac0<'a> {
    #[b(0)]
    protected: BstrHeaderMap<'a>,

    #[b(1)]
    unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    payload: Option<&'a [u8]>,

    #[cbor(b(3), with = "minicbor::bytes")]
    tag: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseMac`] and [`CoseMac0`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(minicbor::Encode)]
pub(crate) struct MacStructure<'a> {
    #[n(0)]
    context: &'static str, // "MAC" / "MAC0"
    #[cbor(b(1), with = "minicbor::bytes")]
    body_protected: &'a [u8],
    #[cbor(b(2), with = "minicbor::bytes")]
    external_aad: &'a [u8],
    // The full payload is used here
    #[cbor(b(3), with = "minicbor::bytes")]
    payload: &'a [u8],
}

impl CoseMac0<'_> {
    #[cfg(feature = "hmac")]
    /// Verification process for a [`CoseMac0`] (ie: a MAC with implicit Key) as detailled in 6.3 of RFC 9052.
    pub fn suit_verify_mac0(
        &self,
        payload_buf: Option<&[u8]>,
        keys: &[u8],
    ) -> Result<(), CoseError> {
        let headers = self.unprotected.updated_with(&self.protected.get()?);

        let payload = match self.payload {
            Some(p) => p,
            None => payload_buf.ok_or(ErrorImpl::MissingPayload)?,
        };

        let aad = MacStructure {
            context: "MAC0",
            body_protected: self.protected.inner_bytes()?,
            external_aad: &[],
            payload,
        };
        let mut to_be_maced = heapless::Vec::<u8, MAX_SUPPORTED_ACCESSTOKEN_LEN>::new();
        minicbor::encode(aad, minicbor_adapters::WriteToHeapless(&mut to_be_maced))?;
        verify_mac::verify_cose_mac(keys, headers, &to_be_maced, self.tag)
    }
}

/// `Cose_MAC` as described in RCF 9052 6.2.
///
/// This Structure is for MACed Messages with recipients.
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
#[allow(dead_code)]
pub struct CoseMac<'a> {
    #[b(0)]
    protected: BstrHeaderMap<'a>,

    #[b(1)]
    unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    payload: Option<&'a [u8]>,

    #[cbor(b(3), with = "minicbor::bytes")]
    tag: &'a [u8],

    #[n(4)]
    pub recipients: IterCoseRecipient<'a>, // at least 1
}

#[cfg(feature = "hmac")]
impl CoseMac<'_> {
    /// Verification process for a MAC with multiple recipients as detailled in 5.4 of RFC 9052.
    ///
    /// Only supports A128kw, A255k and ECDH + A128k kw.
    pub fn suit_verify_mac(
        &self,
        payload_buf: Option<&[u8]>,
        keys: &[u8],
    ) -> Result<(), CoseError> {
        let payload = match self.payload {
            Some(p) => p,
            None => payload_buf.ok_or(ErrorImpl::MissingPayload)?,
        };

        let aad = MacStructure {
            context: "MAC",
            body_protected: self.protected.inner_bytes()?,
            external_aad: &[],
            payload,
        };

        let mut to_be_maced = heapless::Vec::<u8, MAX_SUPPORTED_ACCESSTOKEN_LEN>::new();
        minicbor::encode(aad, minicbor_adapters::WriteToHeapless(&mut to_be_maced))?;

        // Buffer given to write the corresponding CEK.
        let mut cek: heapless::Vec<u8, MAX_CEK_KEY_LEN> = heapless::Vec::new();

        let mut saw_unsupported = false;

        // Try to get a key from each recipient, stop as soon as a key is found.
        for cr in self.recipients.get()?.filter_map(Result::ok) {
            match cr.decrypt_process(keys, &mut cek) {
                Ok(()) => {
                    // We ahve founderd a key to decrypt the recipient, we can now verif.
                    return verify_mac::verify_mac(&cek, &to_be_maced, self.tag);
                }
                Err(e) => {
                    if matches!(e.source, ErrorImpl::UnexpectedMacAlg) {
                        // Unsupported algo
                        saw_unsupported = true;
                        continue;
                    }
                }
            }
        }

        if saw_unsupported {
            Err(ErrorImpl::UnexpectedMacAlg.into())
        } else {
            Err(ErrorImpl::InconsistentDetails.into())
        }
    }
}
