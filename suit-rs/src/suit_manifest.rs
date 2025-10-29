use crate::{SuitError, flat_seq::FlatSequence};
use cose_minicbor::cose::{CoseMac, CoseMac0, CoseSign, CoseSign1};
use minicbor::{Decode, Decoder, Encode, bytes::ByteSlice, decode};
use suit_cbor::{bstr_wrapper, errors::CborError, iter_wrapper};

type Rfc4122Uuid = [u8; 16];

/* -------------------------------------------------------------------------- */
/*                    bstr Wrappers exposed to the public api                 */
/* -------------------------------------------------------------------------- */
bstr_wrapper!(BstrSuitAuthentication, SuitAuthentication<'a>);
bstr_wrapper!(BstrSuitDigest, SuitDigest<'a>);
bstr_wrapper!(BstrSuitCommon, SuitCommon<'a>);
bstr_wrapper!(BstrSuitCommandSequence, SuitCommandSequence<'a>);
bstr_wrapper!(BstrSuitTextMap, SuitTextMap<'a>);
bstr_wrapper!(BstrSuitManifest, SuitManifest<'a>);
bstr_wrapper!(BstrSuitSharedSequence, SuitSharedSequence<'a>);
/* -------------------------------------------------------------------------- */
/*             lazy iterable element Wrappers exposed to the public api       */
/* -------------------------------------------------------------------------- */
iter_wrapper!(
    IterableSuitSeverableManifestMember,
    SuitSeverableManifestMembers<'a>
);
iter_wrapper!(IterableSuitPayload, SuitPayload<'a>);
iter_wrapper!(IterableComponentIdentifier, SuitComponentIdentifier<'a>);
iter_wrapper!(IterableByteSlice, &'a ByteSlice);
iter_wrapper!(IterableU64, u64);
iter_wrapper!(IterBstrSuitSharedSequence, BstrSuitSharedSequence<'a>);
iter_wrapper!(IterBstrSuitCommandSequence, BstrSuitCommandSequence<'a>);
iter_wrapper!(IterSuitTextComponentPair, SuitTextComponentPair<'a>);
iter_wrapper!(IterSuitTagAndTextLmap, (Tag38LTag<'a>, SuitTextLMap<'a>));

// Wrapping structure helper to show the inner cbor structure you are trying to decode
// ! Make sure it doesn't exists anymore on release
#[cfg(debug_assertions)]
#[allow(dead_code)]
#[derive(Encode, Debug)]
#[cbor(transparent)]
pub struct Debug<T>(pub T);

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitEnvelope<'a> {
    #[b(2)] // we borrow a bstr so we need #[b()] instead of #[n()]
    pub(crate) wrapper: BstrSuitAuthentication<'a>,
    #[b(3)]
    pub manifest: BstrSuitManifest<'a>,
    #[n(4)]
    manifest_members: Option<IterableSuitSeverableManifestMember<'a>>,
    #[n(5)]
    pub payload: Option<IterableSuitPayload<'a>>,
}

#[derive(Debug, Encode, Decode)]
pub struct SuitPayload<'a> {
    #[n(0)]
    pub key: &'a str,
    #[cbor(n(1), with = "minicbor::bytes")]
    pub value: &'a [u8],
}

/// ? should it stay private or we should support independent SuitAuthentication process by user ?
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub(crate) struct SuitAuthentication<'a> {
    #[cbor(b(0), with = "minicbor::bytes")] // we will treat it directly so Bstr is not needed
    digest: &'a [u8],
    #[cbor(b(1), with = "minicbor::bytes")] // we will treat it directly so Bstr is not needed
    authentication_block: &'a [u8], // we only support one authentication block
}

impl SuitAuthentication<'_> {
    /// Verify the cose signature of the authentication block.
    pub(crate) fn suit_verify_cose(&self, keys: &[u8]) -> Result<(), SuitError> {
        let mut d = Decoder::new(self.authentication_block);
        let tag = d.tag()?;
        match tag.as_u64() {
            17 => {
                let mac0: CoseMac0 = d.decode()?;
                mac0.suit_verify_mac0(Some(self.digest), keys)?;
                Ok(())
            }
            18 => {
                let sign1: CoseSign1 = d.decode()?;
                sign1.suit_verify_cose_sign1(Some(self.digest), keys)?;
                Ok(())
            }
            97 => {
                let mac: CoseMac = d.decode()?;
                mac.suit_verify_mac(Some(self.digest), keys)?;
                Ok(())
            }
            98 => {
                let sign: CoseSign = d.decode()?;
                sign.suit_verify_cose_sign(Some(self.digest), keys)?;
                Ok(())
            }
            _ => Err(minicbor::decode::Error::tag_mismatch(tag)
                .with_message("SuitAuthenticationBlock: unexpected tag value")
                .into()),
        }
    }

    /// Verify the digest of the [`SuitAuthentication`] block (computed) over bstr wrapped
    ///  [`SuitEnvelope::manifest`] bytes.
    pub(crate) fn suit_verify_digest(&self, manifest_bytes: &[u8]) -> Result<(), SuitError> {
        let digest: SuitDigest = decode(self.digest)?;
        digest.suit_verify_digest(manifest_bytes)
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct SuitDigest<'a> {
    #[n(0)]
    pub hash_alg: HashAlg,
    #[cbor(b(1), with = "minicbor::bytes")]
    pub bytes: &'a [u8],
}

#[derive(Debug, Encode, Decode)]
#[cbor(index_only)]
pub enum HashAlg {
    #[n(-16)]
    Sha256,
    #[n(-18)]
    Shake128,
    #[n(-43)]
    Sha384,
    #[n(-44)]
    Sha512,
    #[n(-45)]
    Shake256,
}

impl SuitDigest<'_> {
    /// Verify a Suit Digest computed over a `buffer`.
    ///
    /// Supports Sha256, Sha384, Sha512
    pub fn suit_verify_digest(&self, buffer: &[u8]) -> Result<(), SuitError> {
        match self.hash_alg {
            HashAlg::Sha256 => self.verify_sha256(buffer),
            HashAlg::Sha384 => self.verify_sha384(buffer),
            HashAlg::Sha512 => self.verify_sha512(buffer),
            HashAlg::Shake128 => Err(SuitError::unexpected_hash_alg(-18)),
            HashAlg::Shake256 => Err(SuitError::unexpected_hash_alg(-45)),
        }
    }

    /// Verify a Suit Digest computed over a `buffer` with Sha256.
    fn verify_sha256(&self, buffer: &[u8]) -> Result<(), SuitError> {
        use sha2::{Digest, Sha256};
        use subtle::ConstantTimeEq;
        let mut hasher = Sha256::new();

        hasher.update(buffer);
        let finalized = hasher.finalize();
        let computed = finalized;

        if computed.ct_eq(self.bytes).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(SuitError::invalid_digest())
        }
    }

    /// Verify a Suit Digest computed over a `buffer` with Sha384.
    fn verify_sha384(&self, buffer: &[u8]) -> Result<(), SuitError> {
        use sha2::Sha384;
        use sha3::Digest;
        use subtle::ConstantTimeEq;

        let mut hasher = Sha384::new();

        hasher.update(buffer);
        let finalized = hasher.finalize();
        let computed = finalized;

        if computed.ct_eq(self.bytes).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(SuitError::default())
        }
    }

    /// Verify a Suit Digest computed over a `buffer` with Sha512.
    fn verify_sha512(&self, buffer: &[u8]) -> Result<(), SuitError> {
        use sha2::Sha512;
        use sha3::Digest;
        use subtle::ConstantTimeEq;

        let mut hasher = Sha512::new();

        hasher.update(buffer);
        let finalized = hasher.finalize();
        let computed = finalized;

        if computed.ct_eq(self.bytes).unwrap_u8() == 1 {
            Ok(())
        } else {
            Err(SuitError::default())
        }
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitManifest<'a> {
    #[n(1)]
    pub version: u64, // must be 1

    #[n(2)]
    pub sequence_number: u64,

    #[b(3)] // we borrow a bstr so we need #[b()] instead of #[n()]
    pub common: BstrSuitCommon<'a>,

    #[n(4)]
    pub reference_uri: Option<&'a str>,

    // Unseverable members (top-level keys in manifest: 7,8,9)
    // SUIT_Unseverable_Members are not under a single key: they are individual optional keys.
    #[b(7)]
    pub validate: Option<BstrSuitCommandSequence<'a>>, // ? suit-validate

    #[b(8)]
    pub load: Option<BstrSuitCommandSequence<'a>>, // ? suit-load

    #[b(9)]
    pub invoke: Option<BstrSuitCommandSequence<'a>>, // ? suit-invoke

    // Severable members choice (top-level keys: 16,20,23)
    // each may be a Digest or a bstr.cbor SUIT_Command_Sequence / SUIT_Text_Map
    #[b(16)]
    pub payload_fetch: Option<DigestOrCbor<'a, BstrSuitCommandSequence<'a>>>,

    #[b(20)]
    pub install: Option<DigestOrCbor<'a, BstrSuitCommandSequence<'a>>>,

    #[b(23)]
    pub text: Option<DigestOrCbor<'a, BstrSuitTextMap<'a>>>,
    // Any future extensions will be ignored/omitted by derive (or add a catch-all decode if needed)
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitSeverableManifestMembers<'a> {
    #[b(16)]
    pub payload_fetch: Option<BstrSuitCommandSequence<'a>>,

    #[b(20)]
    pub install: Option<BstrSuitCommandSequence<'a>>,

    #[b(23)]
    pub text: Option<BstrSuitTextMap<'a>>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitIntegratedPayload<'a> {
    #[cbor(n(0), with = "minicbor::bytes")]
    pub key: &'a [u8],
    #[n(1)]
    pub value: &'a str,
}

#[derive(Debug, Encode)]
pub enum DigestOrCbor<'a, T: 'a> {
    #[n(1)]
    Digest(#[n(0)] SuitDigest<'a>),
    #[n(2)]
    Cbor(#[n(0)] T),
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitCommon<'a> {
    #[n(2)]
    pub components: SuitComponents<'a>,
    #[b(4)] // we borrow bstr
    pub shared_seq: Option<BstrSuitSharedSequence<'a>>,
}
#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitComponents<'a>(#[cbor(borrow)] IterableComponentIdentifier<'a>); // += at least 1

impl<'a> SuitComponents<'a> {
    pub fn get(
        &self,
    ) -> Result<impl Iterator<Item = Result<SuitComponentIdentifier<'a>, CborError>>, SuitError>
    {
        self.0.get().map_err(|e| e.into())
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitComponentIdentifier<'a>(#[cbor(borrow)] IterableByteSlice<'a>);

impl<'a> SuitComponentIdentifier<'a> {
    pub fn get(&self) -> Result<impl Iterator<Item = Result<&'a ByteSlice, CborError>>, SuitError> {
        self.0.get().map_err(|e| e.into())
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitSharedSequence<'a>(#[b(0)] pub(crate) FlatSequence<'a>); // + = at least 1

#[derive(Debug, Encode, Decode)]
pub enum SuitSharedCommand<'a> {
    #[n(12)]
    SetComponentIndex(#[n(0)] IndexArg<'a>),
    #[b(32)]
    RunSequence(
        #[b(0)]
        // we borrow a bstr so we need #[b()] instead of #[n()]
        BstrSuitSharedSequence<'a>,
    ),
    #[n(15)]
    TryEach(#[n(0)] SuitDirectiveTryEachArgumentShared<'a>),
    #[n(20)]
    OverrideParameters(#[n(0)] SuitParameters<'a>), // TODO should 1 +
}

#[derive(Debug, Encode)]
pub enum IndexArg<'a> {
    #[n(0)]
    Single(#[n(0)] u64), // uint
    #[n(1)]
    True(#[n(0)] bool), // true
    #[n(2)]
    Multiple(#[n(0)] IterableU64<'a>), // [+uint]
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitDirectiveTryEachArgumentShared<'a> {
    #[cbor(borrow)]
    pub sequences: Option<IterBstrSuitSharedSequence<'a>>, // 2* bstr.cbor SUIT_Shared_Sequence
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitCommandSequence<'a>(#[b(0)] pub(crate) FlatSequence<'a>);

#[derive(Debug, Encode)]
pub enum CommandCustomValue<'a> {
    #[n(0)]
    Bytes(#[n(0)] &'a [u8]),
    #[n(1)]
    Text(#[n(0)] &'a str),
    #[n(2)]
    Integer(#[n(0)] i64),
    #[n(3)]
    Nil,
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitRepPolicy(pub SuitReportingBits);

bitflags::bitflags! {
    #[derive(Debug)]
    pub struct SuitReportingBits: u8 {
        const SEND_RECORD_SUCCESS  = 0b0001;
        const SEND_RECORD_FAILURE  = 0b0010;
        const SEND_SYSINFO_SUCCESS = 0b0100;
        const SEND_SYSINFO_FAILURE = 0b1000;
    }
}

#[derive(Debug, Encode, Decode)]
pub enum SuitCondition {
    #[n(1)]
    VendorIdentifier(#[n(0)] SuitRepPolicy),

    #[n(2)]
    ClassIdentifier(#[n(0)] SuitRepPolicy),

    #[n(3)]
    ImageMatch(#[n(0)] SuitRepPolicy),

    #[n(5)]
    ComponentSlot(#[n(0)] SuitRepPolicy),

    #[n(6)]
    CheckContent(#[n(0)] SuitRepPolicy),

    #[n(14)]
    Abort(#[n(0)] SuitRepPolicy),

    #[n(24)]
    DeviceIdentifier(#[n(0)] SuitRepPolicy),
}
impl SuitCondition {
    pub fn policy(&self) -> &SuitReportingBits {
        match self {
            SuitCondition::VendorIdentifier(SuitRepPolicy(p))
            | SuitCondition::ClassIdentifier(SuitRepPolicy(p))
            | SuitCondition::ImageMatch(SuitRepPolicy(p))
            | SuitCondition::ComponentSlot(SuitRepPolicy(p))
            | SuitCondition::CheckContent(SuitRepPolicy(p))
            | SuitCondition::Abort(SuitRepPolicy(p))
            | SuitCondition::DeviceIdentifier(SuitRepPolicy(p)) => p,
        }
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub enum SuitDirective<'a> {
    #[n(18)]
    Write(#[n(0)] SuitRepPolicy),

    #[n(12)]
    SetComponentIndex(#[n(0)] IndexArg<'a>),

    #[n(32)]
    RunSequence(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        BstrSuitCommandSequence<'a>,
    ),

    #[b(15)]
    TryEach(#[n(0)] SuitDirectiveTryEachArgument<'a>),

    #[b(20)]
    OverrideParameters(#[n(0)] SuitParameters<'a>),

    #[n(21)]
    Fetch(#[n(0)] SuitRepPolicy),

    #[n(22)]
    Copy(#[n(0)] SuitRepPolicy),

    #[n(31)]
    Swap(#[n(0)] SuitRepPolicy),

    #[n(23)]
    Invoke(#[n(0)] SuitRepPolicy),
}

impl SuitDirective<'_> {
    pub fn policy(&self) -> Option<&SuitReportingBits> {
        match self {
            SuitDirective::Write(SuitRepPolicy(p))
            | SuitDirective::Fetch(SuitRepPolicy(p))
            | SuitDirective::Copy(SuitRepPolicy(p))
            | SuitDirective::Swap(SuitRepPolicy(p))
            | SuitDirective::Invoke(SuitRepPolicy(p)) => Some(p),
            _ => None,
        }
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitDirectiveTryEachArgument<'a>(#[cbor(borrow)] pub IterBstrSuitCommandSequence<'a>);

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitParameters<'a> {
    #[cbor(n(1), decode_with = "crate::suit_decode::decode_uuid_or_cborpen")]
    pub vendor_identifier: Option<&'a [u8]>, // Rfc4122Uuid / cbor-pen
    #[cbor(n(2), with = "minicbor::bytes")]
    pub class_identifier: Option<Rfc4122Uuid>,
    #[b(3)] // We borrow the bstr
    pub image_digest: Option<BstrSuitDigest<'a>>,
    #[n(5)]
    pub component_slot: Option<u64>,
    #[n(12)]
    pub strict_order: Option<bool>,
    #[n(13)]
    pub soft_failure: Option<bool>,
    #[n(14)]
    pub image_size: Option<u64>,
    #[cbor(n(18), with = "minicbor::bytes")]
    pub content: Option<&'a [u8]>,
    #[n(21)]
    pub uri: Option<&'a str>,
    #[n(22)]
    pub source_component: Option<u64>,
    #[cbor(n(23), with = "minicbor::bytes")]
    pub invoke_args: Option<&'a [u8]>,
    #[n(24)]
    pub device_identifier: Option<Rfc4122Uuid>,
    #[cbor(n(25), with = "minicbor::bytes")]
    pub fetch_args: Option<&'a [u8]>,
    // custom: Option<CustomParameterValue,
}

// #[derive(Debug, Clone, Encode, Decode)]
// pub enum CustomParameterValue {
//     #[n(0)]
//     Int(#[n(0)] i64),
//     #[n(1)]ByteDecodeVec
//     Bool(#[n(0)] bool),
//     #[n(2)]
//     Text(#[n(0)] &'a str),
//     #[n(3)]
//     Bytes(#[n(0)] &'a ByteSlice),
// }

#[derive(Debug, Encode, Hash, Eq, PartialEq)]
#[cbor(transparent)]
pub struct Tag38LTag<'a>(pub &'a str);

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitTextMap<'a> {
    #[cbor(borrow)]
    pub entries: IterSuitTagAndTextLmap<'a>,
}

#[derive(Debug, Encode, Decode)]
pub struct SuitTextLMap<'a> {
    #[b(0)]
    pub text_keys: SuitTextKeys<'a>,
    #[b(1)]
    pub components: IterSuitTextComponentPair<'a>,
}
#[derive(Debug, Encode, Decode)]
pub struct SuitTextComponentPair<'a> {
    #[b(0)]
    pub key: SuitComponentIdentifier<'a>,
    #[b(1)]
    pub text_component: SuitTextComponentKeys<'a>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitTextComponentKeys<'a> {
    #[n(1)]
    pub vendor_name: Option<&'a str>,
    #[n(2)]
    pub model_name: Option<&'a str>,
    #[n(3)]
    pub vendor_domain: Option<&'a str>,
    #[n(4)]
    pub model_info: Option<&'a str>,
    #[n(5)]
    pub component_description: Option<&'a str>,
    #[n(6)]
    pub component_version: Option<&'a str>,
}

#[derive(Debug, Decode, Encode)]
#[cbor(map)]
pub struct SuitTextKeys<'a> {
    #[n(1)]
    pub description: Option<&'a str>,
    #[n(2)]
    pub update_description: Option<&'a str>,
    #[n(3)]
    pub manifest_json_source: Option<&'a str>,
    #[n(4)]
    pub manifest_yaml_source: Option<&'a str>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_digest_verify() {
        use super::*;
        use minicbor::decode;

        let digest: SuitDigest = decode(&cbor_macro::cbo!(
            r#" [
                    / algorithm-id / -16 / "sha256" /,
                    / digest-bytes /
    h'6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af'
                ] "#
        ))
        .unwrap();
        let manifest_bytes = &cbor_macro::cbo!(
            r#"<< {
                / manifest-version / 1:1,
                / manifest-sequence-number / 2:0,
                / common / 3:<< {
                    / components / 2:[
                        [h'00']
                    ],
                    / shared-sequence / 4:<< [
                        / directive-override-parameters / 20,{
                            / vendor-id /
    1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-
    be9d-e663e4d41ffe /,
                            / class-id /
    2:h'1492af1425695e48bf429b2d51f2ab45' /
    1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                            / image-digest / 3:<< [
                                / algorithm-id / -16 / "sha256" /,
                                / digest-bytes /
    h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                            ] >>,
                            / image-size / 14:34768
                        },
                        / condition-vendor-identifier / 1,15,
                        / condition-class-identifier / 2,15
                    ] >>
                } >>,
                / validate / 7:<< [
                    / condition-image-match / 3,15
                ] >>,
                / invoke / 9:<< [
                    / directive-invoke / 23,2
                ] >>
            } >>"#
        );
        digest.suit_verify_digest(manifest_bytes).unwrap()
    }
}
