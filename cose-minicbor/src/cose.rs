use crate::errors::{CoseError, ErrorImpl};
use crate::keys::{CoseKeySet, KeyMaterial, KeyOp, KeyType};
use crate::verify;
use minicbor::{Decode, Encode};
use suit_cbor::{bstr_wrapper, iter_wrapper};

const MAX_SUPPORTED_ACCESSTOKEN_LEN: usize = 256;

/// HeaderMap as described in RCF 9052.
///
/// Refer to COSE Header [Parameters
/// registry](https://www.iana.org/assignments/cose/cose.xhtml#header-parameters).
#[derive(Decode, Encode, Debug)]
#[cbor(map)]
#[non_exhaustive]
pub struct HeaderMap<'a> {
    #[n(1)]
    // Might be extended as more exotic algorithms are supported
    pub alg: Option<CoseAlg>,

    #[cbor(b(4), with = "minicbor::bytes")]
    pub(crate) kid: Option<&'a [u8]>,

    #[cbor(b(5), with = "minicbor::bytes")]
    pub(crate) iv: Option<&'a [u8]>,
}

impl HeaderMap<'_> {
    /// Merge two header maps, using the latter's value in case of conflict.
    fn updated_with(&self, other: &Self) -> Self {
        Self {
            alg: self.alg.or(other.alg),
            kid: self.kid.or(other.kid),
            iv: self.iv.or(other.iv),
        }
    }
}

/// COSE Algorithm and Curve identifiers as defined by IANA.
/// Used as Key Type Parameters in COSE Keys:
/// <https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>
#[derive(Decode, Debug, Encode, PartialEq, Copy, Clone)]
#[cbor(index_only)]
#[non_exhaustive]
pub enum CoseAlg {
    /// Key Wrap: AES-128
    #[n(-3)]
    A128KW,
    /// Key Wrap: AES-256
    #[n(-5)]
    A256KW,
    /// ECDH-ES + AES Key Wrap 128
    #[n(-29)]
    ECDHESA128KW,
    /// ES256 / P-256 signature
    #[n(-9)]
    ES256P256,
    /// ES256 deprecated / retro-compatible
    #[n(-7)]
    ES256,
    /// Ed25519 signature
    #[n(-19)]
    ED25519,
    /// HSS/LMS signature
    #[n(-46)]
    HSSLMS,
    /// HMAC truncated 64 bits
    #[n(4)]
    HMAC25664,
    /// HMAC 256 bits
    #[n(5)]
    HMAC256256,
}

bstr_wrapper!(BstrHeaderMap, HeaderMap<'a>);

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
        verify::verify_cose_sign(keys, &signed_data, headers, self.signature)
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
struct SigStructure<'a> {
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
                verify::verify_cose_sign(keys, &to_be_signed, headers, sign.signature)
            })
    }
}

iter_wrapper!(IterCoseRecipient, CoseRecipient<'a>);

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
struct MacStructure<'a> {
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

        let key_set: CoseKeySet = minicbor::decode(keys)?;
        if let KeyMaterial::Symmetric(key) = key_set.match_and_get_key(
            KeyType::Symmetric,
            headers.alg,
            KeyOp::MACVerify,
            headers.kid,
        )? {
            if !matches!(
                headers.alg,
                Some(CoseAlg::HMAC256256) | Some(CoseAlg::HMAC25664)
            ) {
                Err(ErrorImpl::UnexpectedMacAlg.into())
            } else {
                verify::verify_mac(key, &to_be_maced, self.tag)
            }
        } else {
            // We should get the correct material
            Err(ErrorImpl::UnvalidKeySet.into())
        }
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

/// Cose Recipient for key exchanges in HMAC process as described in RCF 9052.
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
#[non_exhaustive]
struct CoseRecipient<'a> {
    #[b(0)]
    protected: BstrHeaderMap<'a>,

    #[b(1)]
    unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    ciphertext: Option<&'a [u8]>,
    // could have been recipients field (not supported)
}
