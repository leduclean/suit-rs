use crate::common::{BstrHeaderMap, HeaderMap, MAX_SUPPORTED_ACCESSTOKEN_LEN};
use crate::errors::{CoseError, ErrorImpl};
use minicbor::{Decode, Encode};
use suit_cbor::iter_wrapper;

#[cfg(any(feature = "es256", feature = "ed25519", feature = "hss_lms"))]
use crate::sign::verify_sign;

/// A `COSE_Sign1` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseSign1<'a> {
    #[cbor(b(0))]
    protected: BstrHeaderMap<'a>, // protected is a bstr .cbor header map / or a bstr .size 0
    #[b(1)]
    unprotected: HeaderMap<'a>, //
    #[cbor(b(2), with = "minicbor::bytes")]
    payload: Option<&'a [u8]>,
    #[cbor(b(3), with = "minicbor::bytes")]
    signature: &'a [u8],
}

/// This structure will be used for Encrypting process on [`CoseSign1`]
/// to feed the AAD during the cryptographic process.
#[derive(minicbor::Encode)]
#[cbor(array)]
struct Sig1Structure<'a> {
    #[n(0)]
    context: &'static str, // "Signature1"
    #[cbor(b(1), with = "minicbor::bytes")]
    body_protected: &'a [u8],
    #[cbor(b(2), with = "minicbor::bytes")]
    external_aad: &'a [u8],
    #[cbor(b(3), with = "minicbor::bytes")]
    payload: &'a [u8],
}

impl CoseSign1<'_> {
    /// Verification process for a single signature detailled in 4.4 of RFC 9052.
    ///
    /// Only supports the ES256, Ed25519 and hss algs for now.
    pub fn suit_verify_cose_sign1(
        &self,
        payload_buf: Option<&[u8]>,
        keys: &[u8],
    ) -> Result<(), CoseError> {
        let headers = self.unprotected.updated_with(&self.protected.get()?);
        let payload = match self.payload {
            Some(p) => p,
            None => payload_buf.ok_or(ErrorImpl::MissingPayload)?,
        };

        let aad = Sig1Structure {
            context: "Signature1",
            body_protected: self.protected.inner_bytes()?,
            external_aad: &[],
            payload,
        };
        let mut signed_data = heapless::Vec::<u8, MAX_SUPPORTED_ACCESSTOKEN_LEN>::new();
        minicbor::encode(aad, minicbor_adapters::WriteToHeapless(&mut signed_data))?;
        verify_sign::verify_cose_sign(keys, &signed_data, headers, self.signature)
    }
}

iter_wrapper!(IterCoseSignature, CoseSignature<'a>);

/// A `COSE_Sign` structure to handle multiple signature as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
#[allow(dead_code)]
pub struct CoseSign<'a> {
    #[b(0)]
    protected: BstrHeaderMap<'a>,
    #[b(1)]
    unprotected: HeaderMap<'a>,
    // Payload could also be nil, but we don't support detached signatures here right now.
    #[cbor(b(2), with = "minicbor::bytes")]
    payload: Option<&'a [u8]>,
    #[b(3)]
    signature: IterCoseSignature<'a>,
}

/// A `CoseSignature` structure as defined in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html)
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
struct CoseSignature<'a> {
    #[b(0)]
    protected: BstrHeaderMap<'a>,
    #[b(1)]
    unprotected: HeaderMap<'a>,
    #[cbor(b(3), with = "minicbor::bytes")]
    signature: &'a [u8],
}
/// This structure will be used for Encrypting process on [`CoseSign`]
/// to feed the AAD during the cryptographic process.
#[allow(dead_code)]
#[derive(minicbor::Encode)]
pub(crate) struct SigStructure<'a> {
    #[n(0)]
    context: &'static str, // "Signature"
    #[cbor(b(1), with = "minicbor::bytes")]
    body_protected: &'a [u8],
    #[cbor(b(2), with = "minicbor::bytes")]
    sign_protected: &'a [u8],
    #[cbor(b(3), with = "minicbor::bytes")]
    external_aad: &'a [u8],
    #[cbor(b(4), with = "minicbor::bytes")]
    payload: &'a [u8],
}

impl CoseSign<'_> {
    /// Verification process for multiple signature detailled in 4.4 of RFC 9052.
    ///
    /// Only supports the ES256, Ed25519 and hss algs for now.
    pub fn suit_verify_cose_sign(
        &self,
        payload_buf: Option<&[u8]>,
        keys: &[u8],
    ) -> Result<(), CoseError> {
        let payload = match self.payload {
            Some(p) => p,
            None => payload_buf.ok_or(ErrorImpl::MissingPayload)?,
        };
        self.signature
            .get()?
            .filter_map(Result::ok)
            .try_for_each(|sign| -> Result<(), CoseError> {
                let headers = sign.unprotected.updated_with(&sign.protected.get()?);
                let aad = SigStructure {
                    context: "Signature",
                    body_protected: self.protected.inner_bytes()?,
                    sign_protected: sign.protected.inner_bytes()?,
                    external_aad: &[],
                    payload,
                };
                let mut to_be_signed = heapless::Vec::<u8, MAX_SUPPORTED_ACCESSTOKEN_LEN>::new();
                minicbor::encode(aad, minicbor_adapters::WriteToHeapless(&mut to_be_signed))?;
                verify_sign::verify_cose_sign(keys, &to_be_signed, headers, sign.signature)
            })
    }
}
