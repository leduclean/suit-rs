use crate::common::{BstrHeaderMap, HeaderMap};
use crate::errors::{CoseError, ErrorImpl};
use minicbor::{Decode, Encode};
use suit_cbor::iter_wrapper;

#[allow(dead_code)]
const MAX_SHARED_SECRET_LEN: usize = 66;

iter_wrapper!(IterCoseRecipient, CoseRecipient<'a>);

/// Cose Recipient for key exchanges in HMAC process as described in RCF 9052.
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
#[non_exhaustive]
pub struct CoseRecipient<'a> {
    #[b(0)]
    protected: BstrHeaderMap<'a>,

    #[b(1)]
    unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    ciphertext: Option<&'a [u8]>,
    // could have been recipients field (not supported)
}

#[cfg(any(feature = "a128kw", feature = "a256kw", feature = "ecdh_es"))]
use crate::cose_keys::{CoseAlg, CoseKeySet, KeyMaterial, KeyOp, KeyType};
#[cfg(any(feature = "a128kw", feature = "a256kw", feature = "ecdh_es"))]
use crate::crypto;

#[cfg(feature = "ecdh_es")]
use crate::multitype::NulOrBytes;

#[cfg(any(feature = "a128kw", feature = "a256kw", feature = "ecdh_es"))]
impl<'a> CoseRecipient<'a> {
    /// Try to decrypt a Cose Recipient
    pub fn decrypt_process<const N: usize>(
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
            // Kek `unwrap()` needs exactly this size of output buffer.
            out.resize_default(ciphertext.len() - 8)?;
            crypto::unwrap_aes_kw(kek, ciphertext, out)?;
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
        use crate::multitype::NulOrBytes;

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

        let mut kek_bytes = [0u8; 16];
        let hk = hkdf::Hkdf::<sha2::Sha256>::new(None, &z);
        hk.expand(&context_bytes, &mut kek_bytes)
            .map_err(|_| ErrorImpl::InconsistentDetails)?;

        out.resize_default(self.ciphertext.unwrap().len() - 8)?;
        crypto::unwrap_aes_kw(&kek_bytes, self.ciphertext.unwrap(), out)?;
        Ok(())
    }
}

// Stub implementation: compiled when decrypt feature is present but no backend is enabled ---
// keep the method available but return an explicit unsupported error
#[cfg(not(any(feature = "a128kw", feature = "a256kw", feature = "ecdh_es")))]
impl<'a> CoseRecipient<'a> {
    pub fn decrypt_process<const N: usize>(
        &self,
        _key_bytes: &'a [u8],
        _out: &'a mut heapless::Vec<u8, N>,
    ) -> Result<(), CoseError> {
        Err(ErrorImpl::UnsupportedFeature("No crytpo backend enabled").into())
    }
}

/// Context information structure for KDF process.
/// As decrypted in [RFC 9053 5.2](https://www.rfc-editor.org/rfc/rfc9053#section-5.2)
#[cfg(feature = "ecdh_es")]
#[allow(dead_code)]
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
#[cfg(feature = "ecdh_es")]
#[allow(dead_code)]
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
#[cfg(feature = "ecdh_es")]
#[allow(dead_code)]
#[derive(Encode)]
struct SuppPubInfo<'a> {
    #[n(0)]
    key_length: u32,
    #[cbor(b(1), with = "minicbor::bytes")]
    protected_bytes: &'a [u8],
}
