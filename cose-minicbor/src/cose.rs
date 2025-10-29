use minicbor::{Decode, Encode};
use suit_cbor::{bstr_wrapper, iter_wrapper};

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
