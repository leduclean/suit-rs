use crate::cose_keys::CoseKey;
use minicbor::{Decode, Encode};
use suit_cbor::bstr_wrapper;

#[allow(dead_code)]
pub(crate) const MAX_SUPPORTED_ACCESSTOKEN_LEN: usize = 256;

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

    #[b(-1)]
    pub(crate) ephemeral_key: Option<CoseKey<'a>>,
}

impl HeaderMap<'_> {
    /// Merge two header maps, using the latter's value in case of conflict.
    #[allow(unused)]
    pub fn updated_with(&self, other: &Self) -> Self {
        Self {
            alg: self.alg.or(other.alg),
            kid: self.kid.or(other.kid),
            iv: self.iv.or(other.iv),
            ephemeral_key: self
                .ephemeral_key
                .as_ref()
                .copied()
                .or(other.ephemeral_key.as_ref().copied()),
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
