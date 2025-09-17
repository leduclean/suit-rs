use crate::lazycbor::LazyCbor;
use crate::suit_cose::*;
use minicbor::{
    Decode, Encode,
    bytes::{ByteArray, ByteSlice, ByteVec},
};
use std::collections::HashMap;

type Rfc4122Uuid = ByteArray<16>;

// Wrapping structure helper to show the inner cbor structure you are trying to decode
// ! Make sure it doesn't exists anymore on release
#[cfg(debug_assertions)]
#[allow(dead_code)]
#[derive(Encode, Debug)]
#[cbor(transparent)]
pub struct Debug<T>(pub T);

#[derive(Encode, Debug)]
pub enum SuitStart<'b> {
    #[n(0)]
    EnvelopeTagged(#[n(0)] SuitEnvelope<'b>),
    #[n(1)]
    ManifestTagged(#[n(0)] SuitManifest<'b>),
    #[n(2)]
    Start,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitEnvelope<'b> {
    #[b(2)] // we borrow a bstr so we need #[b()] instead of #[n()]
    pub wrapper: LazyCbor<'b, SuitAuthentication<'b>>,
    #[b(3)]
    manifest: LazyCbor<'b, SuitManifest<'b>>,
    #[n(4)]
    manifest_members: Option<Vec<SuitSeverableManifestMembers<'b>>>,
    #[n(5)]
    payload: Option<Vec<SuitPayload>>,
}

#[derive(Debug, Encode, Decode)]
struct SuitPayload {
    #[n(0)]
    key: String,
    #[n(1)]
    value: ByteVec,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct SuitAuthentication<'b> {
    #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
    digest: LazyCbor<'b, SuitDigest>,
    #[b(1)]
    authentications_keys: Option<LazyCbor<'b, SuitAuthenticationBlock>>, //TODO  zero or more
}

#[derive(Debug, Encode)]
pub enum SuitAuthenticationBlock {
    /// COSE_Sign_Tagged (tag 98)
    #[n(0)]
    Sign(#[n(0)] CoseSign),

    /// COSE_Sign1_Tagged (tag 18)
    #[n(1)]
    Sign1(#[n(0)] CoseSign1),

    /// COSE_Mac_Tagged (tag 97)
    #[n(2)]
    Mac(#[n(0)] CoseMac),

    /// COSE_Mac0_Tagged (tag 17)
    #[n(3)]
    Mac0(#[n(0)] CoseMac0),
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct SuitDigest {
    #[n(0)]
    algorithm_id: SuitAlgorithmId,
    #[n(1)]
    #[cbor(with = "minicbor::bytes")]
    bytes: ByteVec,
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
pub struct SuitManifest<'b> {
    #[n(1)]
    version: u64, // must be 1

    #[n(2)]
    sequence_number: u64,

    #[b(3)] // we borrow a bstr so we need #[b()] instead of #[n()]
    common: LazyCbor<'b, SuitCommon<'b>>,

    #[n(4)]
    reference_uri: Option<String>,

    // Unseverable members (top-level keys in manifest: 7,8,9)
    // SUIT_Unseverable_Members are not under a single key: they are individual optional keys.
    #[b(7)]
    validate: Option<LazyCbor<'b, SuitCommandSequence<'b>>>, // ? suit-validate

    #[b(8)]
    load: Option<LazyCbor<'b, SuitCommandSequence<'b>>>, // ? suit-load

    #[b(9)]
    invoke: Option<LazyCbor<'b, SuitCommandSequence<'b>>>, // ? suit-invoke

    // Severable members choice (top-level keys: 16,20,23)
    // each may be a Digest or a bstr.cbor SUIT_Command_Sequence / SUIT_Text_Map
    #[b(16)]
    payload_fetch: Option<DigestOrCbor<LazyCbor<'b, SuitCommandSequence<'b>>>>,

    #[b(20)]
    install: Option<DigestOrCbor<LazyCbor<'b, SuitCommandSequence<'b>>>>,

    #[b(23)]
    text: Option<DigestOrCbor<LazyCbor<'b, SuitTextMap>>>,
    // Any future extensions will be ignored/omitted by derive (or add a catch-all decode if needed)
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitSeverableManifestMembers<'b> {
    #[b(16)]
    payload_fetch: Option<LazyCbor<'b, SuitCommandSequence<'b>>>,

    #[b(20)]
    install: Option<LazyCbor<'b, SuitCommandSequence<'b>>>,

    #[b(23)]
    text: Option<LazyCbor<'b, SuitTextMap>>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitIntegratedPayload<'b> {
    #[n(0)]
    key: &'b ByteSlice,
    #[n(1)]
    value: &'b str,
}

#[derive(Debug, Encode)]
pub enum DigestOrCbor<T> {
    #[n(1)]
    Digest(#[n(0)] SuitDigest),
    #[n(2)]
    Cbor(#[n(0)] T),
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitCommon<'b> {
    #[n(2)]
    components: SuitComponents, // TODO += at least 1
    #[b(4)] // we borrow bstr
    shared_seq: Option<LazyCbor<'b, SuitSharedSequence<'b>>>,
}
#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitComponents(Vec<ComponentIdentifier>); // += at least 1

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct ComponentIdentifier(Vec<ByteVec>);

#[derive(Debug, Encode)]
#[cbor(transparent)]
pub struct SuitSharedSequence<'b>(pub Vec<SharedSequenceItem<'b>>); // + = at least 1

#[derive(Debug, Encode, Decode)]
pub enum SharedSequenceItem<'b> {
    #[n(0)]
    Condition(#[n(0)] SuitCondition),
    #[n(1)]
    Command(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        Box<SuitSharedCommand<'b>>,
    ),
}

#[derive(Debug, Encode, Decode)]
pub enum SuitSharedCommand<'b> {
    #[n(12)]
    SetComponentIndex(#[n(0)] IndexArg),
    #[b(32)]
    RunSequence(
        #[b(0)]
        // we borrow a bstr so we need #[b()] instead of #[n()]
        LazyCbor<'b, SuitSharedSequence<'b>>,
    ),
    #[n(15)]
    TryEach(#[n(0)] SuitDirectiveTryEachArgumentShared<'b>),
    #[n(20)]
    OverrideParameters(#[n(0)] SuitParameters<'b>), // TODO should 1 +
}

#[derive(Debug, Encode)]
pub enum IndexArg {
    #[n(0)]
    Single(#[n(0)] u64), // uint
    #[n(1)]
    True(#[n(0)] bool), // true
    #[n(2)]
    Multiple(#[n(0)] Vec<u64>), // [+uint]
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitDirectiveTryEachArgumentShared<'b> {
    #[cbor(borrow)]
    sequences: Option<Vec<LazyCbor<'b, SuitSharedSequence<'b>>>>, // 2* bstr.cbor SUIT_Shared_Sequence
}

#[derive(Debug, Encode)]
#[cbor(transparent)]
// Implement
pub struct SuitCommandSequence<'b> {
    pub item: Vec<SuitCommand<'b>>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub enum SuitCommand<'b> {
    #[n(0)]
    Condition(#[n(0)] SuitCondition),
    #[n(1)]
    Directive(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        SuitDirective<'b>,
    ),
    #[n(2)]
    Custom(#[n(0)] CommandCustomValue),
}

#[derive(Debug, Encode)]
pub enum CommandCustomValue {
    #[n(0)]
    Bytes(#[n(0)] Vec<u8>),
    #[n(1)]
    Text(#[n(0)] String),
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
pub enum SuitDirective<'b> {
    #[n(18)]
    Write(#[n(0)] SuitRepPolicy),

    #[n(12)]
    SetComponentIndex(#[n(0)] IndexArg),

    #[n(32)]
    RunSequence(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        LazyCbor<'b, SuitCommandSequence<'b>>,
    ),

    #[b(15)]
    TryEach(#[n(0)] SuitDirectiveTryEachArgument<'b>),

    #[b(20)]
    OverrideParameters(#[n(0)] SuitParameters<'b>),

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
pub struct SuitDirectiveTryEachArgument<'b>(
    #[cbor(borrow)] Vec<LazyCbor<'b, SuitCommandSequence<'b>>>,
);

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
pub struct SuitParameters<'b> {
    #[n(1)]
    #[cbor(decode_with = "crate::suit_decode::decode_uuid_or_cborpen")]
    vendor_identifier: Option<Vec<u8>>, // Rfc4122Uuid / cbor-pen
    #[n(2)]
    class_identifier: Option<Rfc4122Uuid>,
    #[b(3)] // We borrow the bstr
    image_digest: Option<LazyCbor<'b, SuitDigest>>,
    #[n(5)]
    component_slot: Option<u64>,
    #[n(12)]
    strict_order: Option<bool>,
    #[n(13)]
    soft_failure: Option<bool>,
    #[n(14)]
    image_size: Option<u64>,
    #[n(18)]
    content: Option<ByteVec>,
    #[n(21)]
    uri: Option<String>,
    #[n(22)]
    source_component: Option<u64>,
    #[n(23)]
    invoke_args: Option<ByteVec>,
    #[n(24)]
    device_identifier: Option<Rfc4122Uuid>,
    #[n(25)]
    fetch_args: Option<ByteVec>,
    // custom: Option<CustomParameterValue,
}

// #[derive(Debug, Clone, Encode, Decode)]
// pub enum CustomParameterValue {
//     #[n(0)]
//     Int(#[n(0)] i64),
//     #[n(1)]
//     Bool(#[n(0)] bool),
//     #[n(2)]
//     Text(#[n(0)] String),
//     #[n(3)]
//     Bytes(#[n(0)] Vec<u8>),
// }

#[derive(Debug, Encode, Hash, Eq, PartialEq)]
#[cbor(transparent)]
pub struct Tag38LTag(pub String);

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
pub struct SuitTextMap {
    entries: Vec<(Tag38LTag, SuitTextLMap)>,
}

#[derive(Debug, Encode, Decode)]
struct SuitTextLMap {
    #[n(0)]
    text_keys: SuitTextKeys,
    #[n(1)]
    components: HashMap<SuitComponentIdentifier, SuitTextComponentKeys>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
struct SuitTextComponentKeys {
    #[n(1)]
    vendor_name: Option<String>,
    #[n(2)]
    model_name: Option<String>,
    #[n(3)]
    vendor_domain: Option<String>,
    #[n(4)]
    model_info: Option<String>,
    #[n(5)]
    component_descripiton: Option<String>,
    #[n(6)]
    component_version: Option<String>,
}

#[derive(Debug, Encode, Decode, Hash, Eq, PartialEq)]
#[cbor(transparent)]
pub struct SuitComponentIdentifier(String);

#[derive(Debug, Decode, Encode)]
#[cbor(map)]
struct SuitTextKeys {
    #[n(1)]
    description: Option<String>,
    #[n(2)]
    update_description: Option<String>,
    #[n(3)]
    manifest_json_source: Option<String>,
    #[n(4)]
    manifest_yaml_source: Option<String>,
}
