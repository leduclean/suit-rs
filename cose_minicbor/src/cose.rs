use crate::cose_keys::{CoseKey, CoseKeySet, KeyMaterial, KeyOp, KeyType};
use crate::crypto;
use crate::errors::{CoseError, ErrorImpl};
use crate::multitype::NulOrBytes;
use crate::verify_mac;
use crate::verify_sign;

use minicbor::{Decode, Encode};
use suit_cbor::{bstr_wrapper, iter_wrapper};

const MAX_SHARED_SECRET_LEN: usize = 66;
const MAX_SUPPORTED_ACCESSTOKEN_LEN: usize = 256;
const MAX_CEK_KEY_LEN: usize = 64;

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
    ephemeral_key: Option<CoseKey<'a>>,
}

impl HeaderMap<'_> {
    /// Merge two header maps, using the latter's value in case of conflict.
    fn updated_with(&self, other: &Self) -> Self {
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
                verify_sign::verify_cose_sign(keys, &to_be_signed, headers, sign.signature)
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
                verify_mac::verify_mac(key, &to_be_maced, self.tag)
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

impl CoseMac<'_> {
    #[cfg(feature = "hmac")]
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
                    // Founded !
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

fn unwrap_symmetric_kek<const N: usize>(
    kek: &[u8],
    ciphertext: &[u8],
    out: &mut heapless::Vec<u8, N>,
) -> Result<(), CoseError> {
    // Kek `unwrap()` needs exactly this size of output buffer.
    out.resize_default(ciphertext.len() - 8)?;
    crypto::unwrap_aes_kw(kek, ciphertext, out)?;
    Ok(())
}

fn derive_ecdh_kek(z: &[u8], context_bytes: &[u8]) -> Result<[u8; 16], CoseError> {
    let mut kek_bytes = [0u8; 16];
    let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, z);
    hk.expand(context_bytes, &mut kek_bytes)
        .map_err(|_| ErrorImpl::InconsistentDetails)?;
    Ok(kek_bytes)
}

impl<'a> CoseRecipient<'a> {
    /// Try to decrypt a Cose Recipient
    fn decrypt_process<const N: usize>(
        &self,
        key_bytes: &'a [u8],
        out: &'a mut heapless::Vec<u8, N>,
    ) -> Result<(), CoseError> {
        let key_set: CoseKeySet = minicbor::decode(key_bytes)?;
        let protected_bytes = self.protected.inner_bytes()?;
        let headers = if !protected_bytes.is_empty() {
            &self.unprotected.updated_with(&self.protected.get()?)
        } else {
            &self.unprotected
        };

        let ciphertext = self.ciphertext.ok_or(ErrorImpl::InconsistentDetails)?;

        match headers.alg {
            #[cfg(any(feature = "a128kw", feature = "a256kw"))]
            Some(CoseAlg::A128KW) | Some(CoseAlg::A256KW) => {
                self.decrypt_aes_kw(&key_set, headers.alg, ciphertext, out)
            }

            #[cfg(feature = "ecdh_es")]
            Some(CoseAlg::ECDHESA128KW) => self.decrypt_ecdh_es(&key_set, headers, out),

            _ => Err(ErrorImpl::UnexpectedMacAlg.into()),
        }
    }

    #[cfg(any(feature = "a128kw", feature = "a256kw"))]
    fn decrypt_aes_kw<const N: usize>(
        &self,
        key_set: &CoseKeySet,
        alg: Option<CoseAlg>,
        ciphertext: &[u8],
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), CoseError> {
        if let KeyMaterial::Symmetric(kek) = key_set.match_and_get_key(
            KeyType::Symmetric,
            alg,
            KeyOp::UnwrapKey,
            self.unprotected.kid,
        )? {
            unwrap_symmetric_kek(kek, ciphertext, out)?;
            Ok(())
        } else {
            Err(ErrorImpl::InconsistentDetails.into())
        }
    }

    #[cfg(feature = "ecdh_es")]
    fn decrypt_ecdh_es<const N: usize>(
        &self,
        key_set: &CoseKeySet,
        headers: &HeaderMap<'_>,
        out: &mut heapless::Vec<u8, N>,
    ) -> Result<(), CoseError> {
        let private =
            key_set.match_and_get_key(KeyType::Ec2, headers.alg, KeyOp::DeriveBits, headers.kid)?;

        let ephemeral = headers.ephemeral_key.ok_or(ErrorImpl::MissingKeyValue)?;
        let mut z = [0u8; MAX_SHARED_SECRET_LEN];

        if let KeyMaterial::Ec2 { x, y, crv } = ephemeral.try_into()? {
            match private {
                KeyMaterial::Private { d, crv: priv_crv } => {
                    priv_crv.check_curve(crv)?;
                    crypto::perform_ecdh_es(d, x, y, crv, &mut z)?;
                }
                _ => return Err(ErrorImpl::UnvalidKeySet.into()),
            }
        }

        let kdf_context = CoseKdfContext {
            alg_id: CoseAlg::A128KW,
            party_u_info: PartyInfo {
                identity: NulOrBytes::Nul,
                nonce: NulOrBytes::Nul,
                other: NulOrBytes::Nul,
            },
            party_v_info: PartyInfo {
                identity: NulOrBytes::Nul,
                nonce: NulOrBytes::Nul,
                other: NulOrBytes::Nul,
            },
            sup_pub_info: SuppPubInfo {
                key_length: 128,
                protected_bytes: self.protected.inner_bytes()?,
            },
        };

        let mut context_bytes: heapless::Vec<u8, 64> = heapless::Vec::new();
        minicbor::encode(
            kdf_context,
            minicbor_adapters::WriteToHeapless(&mut context_bytes),
        )?;

        let kek_bytes = derive_ecdh_kek(&z, &context_bytes)?;
        unwrap_symmetric_kek(&kek_bytes, self.ciphertext.unwrap(), out)?;
        Ok(())
    }
}

/// Context information structure for KDF process.
/// As decrypted in [RFC 9053 5.2](https://www.rfc-editor.org/rfc/rfc9053#section-5.2)
#[derive(Encode)]
struct CoseKdfContext<'a> {
    #[n(0)]
    alg_id: CoseAlg,
    #[n(1)]
    party_u_info: PartyInfo<'a>,
    #[n(2)]
    party_v_info: PartyInfo<'a>,
    #[n(3)]
    sup_pub_info: SuppPubInfo<'a>,
}

/// Context field structure to wrap PartyUInfo and PartyVInfo.
#[derive(Encode)]
struct PartyInfo<'a> {
    #[cbor(b(0))]
    identity: NulOrBytes<'a>,
    #[cbor(b(1))]
    nonce: NulOrBytes<'a>,
    #[cbor(b(2))]
    other: NulOrBytes<'a>,
}

/// Context field structure that contains information that is mutually known to both parties
#[derive(Encode)]
struct SuppPubInfo<'a> {
    #[n(0)]
    key_length: u32,
    #[cbor(b(1), with = "minicbor::bytes")]
    protected_bytes: &'a [u8],
}
