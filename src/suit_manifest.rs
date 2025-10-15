use crate::suit_cose::*;
use crate::{bstr_struct::BstrStruct, errors::SuitError, flat_seq::FlatSequence};
use minicbor::{
    Decode, Encode,
    bytes::{ByteArray, ByteSlice},
};

type Rfc4122Uuid = ByteArray<16>;

/* -------------------------------------------------------------------------- */
/*                                bstr Wrappers                               */
/* -------------------------------------------------------------------------- */
bstr_wrapper!(BstrSuitDigest, SuitDigest<'a>);
bstr_wrapper!(BstrSuitAuthenticationBlock, SuitAuthenticationBlock<'a>);
bstr_wrapper!(BstrSuitAuthentication, SuitAuthentication<'a>);
bstr_wrapper!(BstrSuitCommon, SuitCommon<'a>);
bstr_wrapper!(BstrSuitCommandSequence, SuitCommandSequence<'a>);
bstr_wrapper!(BstrSuitTextMap, SuitTextMap<'a>);
bstr_wrapper!(BstrSuitManifest, SuitManifest<'a>);
bstr_wrapper!(BstrSuitSharedSequence, SuitSharedSequence<'a>);
/* -------------------------------------------------------------------------- */
/*                                lazy iterable element Wrappers               */
/* -------------------------------------------------------------------------- */
iter_wrapper!(
    IterableSuitSeverableManifestMember,
    SuitSeverableManifestMembers<'a>
);
iter_wrapper!(IterableSuitPayload, SuitPayload<'a>);
iter_wrapper!(IterableComponentIdentifier, ComponentIdentifier<'a>);
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
    pub wrapper: BstrSuitAuthentication<'a>,
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
    #[n(1)]
    pub value: &'a ByteSlice,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct SuitAuthentication<'a> {
    #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
    pub digest: BstrSuitDigest<'a>,
    #[b(1)]
    pub authentications_keys: Option<BstrSuitAuthenticationBlock<'a>>, //TODO  zero or more
}

#[derive(Debug, Encode)]
pub enum SuitAuthenticationBlock<'a> {
    /// COSE_Sign_Tagged (tag 98)
    #[n(0)]
    Sign(#[n(0)] CoseSign<'a>),

    /// COSE_Sign1_Tagged (tag 18)
    #[n(1)]
    Sign1(#[n(0)] CoseSign1<'a>),

    /// COSE_Mac_Tagged (tag 97)
    #[n(2)]
    Mac(#[n(0)] CoseMac<'a>),

    /// COSE_Mac0_Tagged (tag 17)
    #[n(3)]
    Mac0(#[n(0)] CoseMac0<'a>),
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct SuitDigest<'a> {
    #[n(0)]
    pub algorithm_id: SuitAlgorithmId,
    #[n(1)]
    bytes: &'a ByteSlice,
}
impl SuitDigest<'_> {
    pub fn bytes(&self) -> &[u8] {
        self.bytes.as_ref()
    }
}
#[derive(Debug, Encode, Decode)]
#[cbor(index_only)]
pub enum SuitAlgorithmId {
    #[n(0)]
    Invalid,
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
    #[n(0)]
    pub key: &'a ByteSlice,
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
    ) -> Result<impl Iterator<Item = Result<ComponentIdentifier<'a>, SuitError>>, SuitError> {
        self.0.get()
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct ComponentIdentifier<'a>(#[cbor(borrow)] IterableByteSlice<'a>);

impl<'a> ComponentIdentifier<'a> {
    pub fn get(&self) -> Result<impl Iterator<Item = Result<&'a ByteSlice, SuitError>>, SuitError> {
        self.0.get()
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
    #[n(1)]
    #[cbor(decode_with = "crate::suit_decode::decode_uuid_or_cborpen")]
    vendor_identifier: Option<&'a ByteSlice>, // Rfc4122Uuid / cbor-pen
    #[n(2)]
    class_identifier: Option<Rfc4122Uuid>,
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
    #[n(18)]
    pub content: Option<&'a ByteSlice>,
    #[n(21)]
    pub uri: Option<&'a str>,
    #[n(22)]
    pub source_component: Option<u64>,
    #[n(23)]
    pub invoke_args: Option<&'a ByteSlice>,
    #[n(24)]
    pub device_identifier: Option<Rfc4122Uuid>,
    #[n(25)]
    pub fetch_args: Option<&'a ByteSlice>,
    // custom: Option<CustomParameterValue,
}

impl SuitParameters<'_> {
    pub fn vendor_identifier(&self) -> Option<&[u8]> {
        self.vendor_identifier.map(|b| b.as_ref())
    }
    pub fn class_identifier(&self) -> Option<&[u8; 16]> {
        self.class_identifier.as_ref().map(|b| b.as_ref())
    }
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

#[derive(Debug, Encode, Decode, Hash, Eq, PartialEq)]
#[cbor(transparent)]
pub struct SuitComponentIdentifier<'a>(pub &'a str);

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
