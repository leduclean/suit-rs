use crate::lazycbor::LazyCbor;
use crate::suit_cose::*;
use heapless::Vec;
use minicbor::{
    Decode, Encode,
    bytes::{ByteArray, ByteSlice},
};

type Rfc4122Uuid = ByteArray<16>;

pub const SUIT_MAX_ARRAY_LENGTH: usize = 20;
const SUIT_MAX_KEY_NUM: usize = 6; // must be <=64

const SUIT_MAX_NAME_LENGTH: usize = 256; // the length of path or name such as component_identifier

const SUIT_MAX_URI_LENGTH: usize = 256; // the length of uri to fetch something

const SUIT_MAX_COMPONENT_NUM: usize = 3;

const SUIT_MAX_DEPENDENCY_NUM: usize = 1;

const SUIT_MAX_INDEX_NUM: usize = SUIT_MAX_COMPONENT_NUM + SUIT_MAX_DEPENDENCY_NUM;

const SUIT_MAX_ARGS_LENGTH: usize = 64;

const SUIT_MAX_DATA_SIZE: usize = 8 * 1024 * 1024;

// We overcharge the heapless Vec<T,N> to impl decode trait on it
#[derive(Debug)]
pub struct CborVec<T, const N: usize>(pub Vec<T, N>);

// Wrapping structure helper to show the inner cbor structure you are trying to decode
// ! Make sure it doesn't exists anymore on release
#[cfg(debug_assertions)]
#[allow(dead_code)]
#[derive(Encode, Debug)]
#[cbor(transparent)]
pub struct Debug<T>(pub T);

#[derive(Encode, Debug)]
pub enum SuitStart<'a> {
    #[n(0)]
    EnvelopeTagged(#[n(0)] SuitEnvelope<'a>),
    #[n(1)]
    ManifestTagged(#[n(0)] SuitManifest<'a>),
    #[n(2)]
    Start,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitEnvelope<'a> {
    #[b(2)] // we borrow a bstr so we need #[b()] instead of #[n()]
    pub wrapper: LazyCbor<'a, SuitAuthentication<'a>>,
    #[b(3)]
    manifest: LazyCbor<'a, SuitManifest<'a>>,
    #[n(4)]
    manifest_members: Option<CborVec<SuitSeverableManifestMembers<'a>, SUIT_MAX_ARRAY_LENGTH>>,
    #[n(5)]
    payload: Option<CborVec<SuitPayload<'a>, SUIT_MAX_ARRAY_LENGTH>>,
}

#[derive(Debug, Encode, Decode)]
struct SuitPayload<'a> {
    #[n(0)]
    key: &'a str,
    #[n(1)]
    value: &'a ByteSlice,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct SuitAuthentication<'a> {
    #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
    digest: LazyCbor<'a, SuitDigest<'a>>,
    #[b(1)]
    authentications_keys: Option<LazyCbor<'a, SuitAuthenticationBlock<'a>>>, //TODO  zero or more
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
    algorithm_id: SuitAlgorithmId,
    #[n(1)]
    bytes: &'a ByteSlice,
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
    version: u64, // must be 1

    #[n(2)]
    sequence_number: u64,

    #[b(3)] // we borrow a bstr so we need #[b()] instead of #[n()]
    common: LazyCbor<'a, SuitCommon<'a>>,

    #[n(4)]
    reference_uri: Option<&'a str>,

    // Unseverable members (top-level keys in manifest: 7,8,9)
    // SUIT_Unseverable_Members are not under a single key: they are individual optional keys.
    #[b(7)]
    validate: Option<LazyCbor<'a, SuitCommandSequence<'a>>>, // ? suit-validate

    #[b(8)]
    load: Option<LazyCbor<'a, SuitCommandSequence<'a>>>, // ? suit-load

    #[b(9)]
    invoke: Option<LazyCbor<'a, SuitCommandSequence<'a>>>, // ? suit-invoke

    // Severable members choice (top-level keys: 16,20,23)
    // each may be a Digest or a bstr.cbor SUIT_Command_Sequence / SUIT_Text_Map
    #[b(16)]
    payload_fetch: Option<DigestOrCbor<'a, LazyCbor<'a, SuitCommandSequence<'a>>>>,

    #[b(20)]
    install: Option<DigestOrCbor<'a, LazyCbor<'a, SuitCommandSequence<'a>>>>,

    #[b(23)]
    text: Option<DigestOrCbor<'a, LazyCbor<'a, SuitTextMap<'a>>>>,
    // Any future extensions will be ignored/omitted by derive (or add a catch-all decode if needed)
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitSeverableManifestMembers<'a> {
    #[b(16)]
    payload_fetch: Option<LazyCbor<'a, SuitCommandSequence<'a>>>,

    #[b(20)]
    install: Option<LazyCbor<'a, SuitCommandSequence<'a>>>,

    #[b(23)]
    text: Option<LazyCbor<'a, SuitTextMap<'a>>>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitIntegratedPayload<'a> {
    #[n(0)]
    key: &'a ByteSlice,
    #[n(1)]
    value: &'a str,
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
    components: SuitComponents<'a>, // TODO += at least 1
    #[b(4)] // we borrow bstr
    shared_seq: Option<LazyCbor<'a, SuitSharedSequence<'a>>>,
}
#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitComponents<'a>(#[cbor(borrow)] CborVec<ComponentIdentifier<'a>, SUIT_MAX_INDEX_NUM>); // += at least 1

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct ComponentIdentifier<'a>(#[cbor(borrow)] pub CborVec<&'a ByteSlice, SUIT_MAX_INDEX_NUM>);

#[derive(Debug, Encode)]
#[cbor(transparent)]
pub struct SuitSharedSequence<'a>(pub CborVec<SharedSequenceItem<'a>, SUIT_MAX_ARRAY_LENGTH>); // + = at least 1

#[derive(Debug, Encode, Decode)]
pub enum SharedSequenceItem<'a> {
    #[n(0)]
    Condition(#[n(0)] SuitCondition),
    #[n(1)]
    Command(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        SuitSharedCommand<'a>,
    ),
}

#[derive(Debug, Encode, Decode)]
pub enum SuitSharedCommand<'a> {
    #[n(12)]
    SetComponentIndex(#[n(0)] IndexArg),
    #[b(32)]
    RunSequence(
        #[b(0)]
        // we borrow a bstr so we need #[b()] instead of #[n()]
        LazyCbor<'a, SuitSharedSequence<'a>>,
    ),
    #[n(15)]
    TryEach(#[n(0)] SuitDirectiveTryEachArgumentShared<'a>),
    #[n(20)]
    OverrideParameters(#[n(0)] SuitParameters<'a>), // TODO should 1 +
}

#[derive(Debug, Encode)]
pub enum IndexArg {
    #[n(0)]
    Single(#[n(0)] u64), // uint
    #[n(1)]
    True(#[n(0)] bool), // true
    #[n(2)]
    Multiple(#[n(0)] CborVec<u64, SUIT_MAX_INDEX_NUM>), // [+uint]
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitDirectiveTryEachArgumentShared<'a> {
    #[cbor(borrow)]
    sequences: Option<CborVec<LazyCbor<'a, SuitSharedSequence<'a>>, SUIT_MAX_ARRAY_LENGTH>>, // 2* bstr.cbor SUIT_Shared_Sequence
}

#[derive(Debug, Encode)]
#[cbor(transparent)]
pub struct SuitCommandSequence<'a> {
    pub item: CborVec<SuitCommand<'a>, SUIT_MAX_ARRAY_LENGTH>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub enum SuitCommand<'a> {
    #[n(0)]
    Condition(#[n(0)] SuitCondition),
    #[n(1)]
    Directive(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        SuitDirective<'a>,
    ),
    #[n(2)]
    Custom(#[n(0)] CommandCustomValue<'a>),
}

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
pub struct SuitRepPolicy(SuitReportingBits);

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

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub enum SuitDirective<'a> {
    #[n(18)]
    Write(#[n(0)] SuitRepPolicy),

    #[n(12)]
    SetComponentIndex(#[n(0)] IndexArg),

    #[n(32)]
    RunSequence(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        LazyCbor<'a, SuitCommandSequence<'a>>,
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

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitDirectiveTryEachArgument<'a>(
    #[cbor(borrow)] CborVec<LazyCbor<'a, SuitCommandSequence<'a>>, SUIT_MAX_ARRAY_LENGTH>,
);

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitParameters<'a> {
    #[n(1)]
    #[cbor(decode_with = "crate::suit_decode::decode_uuid_or_cborpen")]
    vendor_identifier: Option<&'a ByteSlice>, // Rfc4122Uuid / cbor-pen
    #[n(2)]
    class_identifier: Option<Rfc4122Uuid>,
    #[b(3)] // We borrow the bstr
    image_digest: Option<LazyCbor<'a, SuitDigest<'a>>>,
    #[n(5)]
    component_slot: Option<u64>,
    #[n(12)]
    strict_order: Option<bool>,
    #[n(13)]
    soft_failure: Option<bool>,
    #[n(14)]
    image_size: Option<u64>,
    #[n(18)]
    content: Option<&'a ByteSlice>,
    #[n(21)]
    uri: Option<&'a str>,
    #[n(22)]
    source_component: Option<u64>,
    #[n(23)]
    invoke_args: Option<&'a ByteSlice>,
    #[n(24)]
    device_identifier: Option<Rfc4122Uuid>,
    #[n(25)]
    fetch_args: Option<&'a ByteSlice>,
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
    entries: CborVec<(Tag38LTag<'a>, SuitTextLMap<'a>), SUIT_MAX_ARRAY_LENGTH>,
}

#[derive(Debug, Encode, Decode)]
struct SuitTextLMap<'a> {
    #[b(0)]
    text_keys: SuitTextKeys<'a>,
    #[b(1)]
    components: CborVec<SuitTextComponentPair<'a>, SUIT_MAX_ARRAY_LENGTH>,
}
#[derive(Debug, Encode, Decode)]
struct SuitTextComponentPair<'a> {
    #[b(0)]
    key: SuitComponentIdentifier<'a>,
    #[b(1)]
    text_component: SuitTextComponentKeys<'a>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
struct SuitTextComponentKeys<'a> {
    #[n(1)]
    vendor_name: Option<&'a str>,
    #[n(2)]
    model_name: Option<&'a str>,
    #[n(3)]
    vendor_domain: Option<&'a str>,
    #[n(4)]
    model_info: Option<&'a str>,
    #[n(5)]
    component_descripiton: Option<&'a str>,
    #[n(6)]
    component_version: Option<&'a str>,
}

#[derive(Debug, Encode, Decode, Hash, Eq, PartialEq)]
#[cbor(transparent)]
pub struct SuitComponentIdentifier<'a>(&'a str);

#[derive(Debug, Decode, Encode)]
#[cbor(map)]
struct SuitTextKeys<'a> {
    #[n(1)]
    description: Option<&'a str>,
    #[n(2)]
    update_description: Option<&'a str>,
    #[n(3)]
    manifest_json_source: Option<&'a str>,
    #[n(4)]
    manifest_yaml_source: Option<&'a str>,
}
