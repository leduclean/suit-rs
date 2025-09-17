use crate::flat_ops::decode_flat_pairs;
use core::marker::PhantomData;
use minicbor::{
    Decode, Decoder, Encode, Encoder,
    bytes::{ByteArray, ByteSlice, ByteVec},
    data::Type,
    decode::Error as DecodeError,
    display,
    encode::Error as EncodeError,
};
use regex::Regex;
use std::collections::HashMap;

type Rfc4122Uuid = ByteArray<16>;

/// Lazy wrapper: on decode, for .bstr cbor T, we store the bytes slice but do NOT decode inner T.
/// Call `.decode_inner(ctx)` to decode T later if you need acces to data.
// we borrow a bstr so we need #[b()] instead of #[n()] of each struct using this
#[derive(Debug)]
pub struct LazyCbor<'b, T: 'b> {
    pub bytes: &'b [u8],
    _ty: PhantomData<&'b T>, // We use phantom data that any reference in T are valid for 'b (the bstr entry)
}

impl<'b, T, Ctx> Decode<'b, Ctx> for LazyCbor<'b, T>
where
    // T must itself implement decoding so we can decode on demand
    T: Decode<'b, Ctx>,
{
    fn decode(d: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let bytes = d.bytes()?; // returns &'b [u8] (handles definite/indefinite)
        Ok(LazyCbor {
            bytes,
            _ty: PhantomData,
        })
    }
}
impl<'b, T, Ctx> Encode<Ctx> for LazyCbor<'b, T>
where
    T: Encode<Ctx>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), EncodeError<W::Error>> {
        e.bytes(self.bytes)?;
        Ok(())
    }
}

// helper to decode when needed:
impl<'b, T> LazyCbor<'b, T> {
    pub fn decode_inner<C>(&self, ctx: &mut C) -> Result<T, DecodeError>
    where
        T: Decode<'b, C>,
    {
        let mut sub = Decoder::new(self.bytes);
        T::decode(&mut sub, ctx)
    }
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
#[derive(Encode, Debug)]
#[cbor(transparent)]
struct Debug<T>(T);

impl<'b, T, Ctx> Decode<'b, Ctx> for Debug<T>
where
    T: Decode<'b, Ctx>,
{
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        println!("Decoding struct: {}", core::any::type_name::<Self>());

        let inner = decode_with_debug::<T, Ctx>(d, ctx)?;
        Ok(Debug(inner))
    }
}

#[cfg(debug_assertions)]
#[allow(dead_code)]
fn decode_with_debug<'b, T, Ctx>(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<T, DecodeError>
where
    T: Decode<'b, Ctx>,
{
    println!("Decoding with debug...");
    let bytes = d.input();
    println!("Shared sequence raw: {}", display(bytes));
    let inner = T::decode(d, ctx)?;
    Ok(inner)
}

#[derive(Encode, Debug)]
pub enum SuitStart<'b> {
    #[n(0)]
    EnvelopeTagged(#[n(0)] SuitEnvelope<'b>),
    #[n(1)]
    ManifestTagged(#[n(0)] SuitManifest<'b>),
    #[n(2)]
    Start,
}
impl<'b> Decode<'b, ()> for SuitStart<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut ()) -> Result<Self, minicbor::decode::Error> {
        match d.tag()?.as_u64() {
            107 => Ok(SuitStart::EnvelopeTagged(
                d.decode_with::<(), SuitEnvelope>(ctx)?,
            )),
            1070 => Ok(SuitStart::ManifestTagged(
                d.decode_with::<(), SuitManifest>(ctx)?,
            )),
            0 => Ok(SuitStart::Start),
            other => Err(minicbor::decode::Error::message(format!(
                "unexpected tag {other}"
            ))),
        }
    }
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

impl<'b, Ctx> Decode<'b, Ctx> for SuitAuthenticationBlock {
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
        match d.tag()?.as_u64() {
            98 => Ok(SuitAuthenticationBlock::Sign(
                d.decode_with::<Ctx, CoseSign>(ctx)?,
            )),
            18 => Ok(SuitAuthenticationBlock::Sign1(
                d.decode_with::<Ctx, CoseSign1>(ctx)?,
            )),
            97 => Ok(SuitAuthenticationBlock::Mac(
                d.decode_with::<Ctx, CoseMac>(ctx)?,
            )),
            17 => Ok(SuitAuthenticationBlock::Mac0(
                d.decode_with::<Ctx, CoseMac0>(ctx)?,
            )),

            other => Err(minicbor::decode::Error::message(format!(
                "unexpected tag {other}"
            ))),
        }
    }
}

#[derive(Debug, Encode)]
enum SuitAuthenticationBlock {
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
pub struct CoseSign1 {
    #[n(0)]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>, // detached mode => None

    #[n(3)]
    pub signature: ByteVec,
}

/// Pour COSE_Sign (similaire mais avec plusieurs signatures)
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseSign {
    #[n(0)]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>,

    #[n(3)]
    pub signatures: Vec<CoseSignature>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseSignature {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub signature: ByteVec,
}

/// Pour COSE_Mac
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseMac {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>,

    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub tag: ByteVec,

    #[n(4)]
    pub recipients: Vec<CoseRecipient>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseRecipient {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub ciphertext: Option<ByteVec>,
}

/// Pour COSE_Mac0
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseMac0 {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>,

    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub tag: ByteVec,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
struct SuitDigest {
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
struct SuitSeverableManifestMembers<'b> {
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
enum DigestOrCbor<T> {
    #[n(1)]
    Digest(#[n(0)] SuitDigest),
    #[n(2)]
    Cbor(#[n(0)] T),
}

impl<'b, Ctx, T> Decode<'b, Ctx> for DigestOrCbor<T>
where
    T: Decode<'b, Ctx>,
{
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        match d.datatype()? {
            // bstr.cbor case (or generic bytes wrapper for the CBOR value)
            // Call T::decode on the current decoder: if T is LazyCbor<'b, >,
            // it will call d.bytes() and then decode the inner CBOR.
            Type::Bytes => {
                let t = T::decode(d, ctx)?;
                Ok(DigestOrCbor::Cbor(t))
            }

            // Digest is encoded as a CBOR array [algorithm_id, bytes]
            // so we expect an Array here and decode SuitDigest
            Type::Array => {
                let digest = SuitDigest::decode(d, ctx)?;
                Ok(DigestOrCbor::Digest(digest))
            }

            other => Err(DecodeError::message(format!(
                "unexpected type for DigestOrCbor: {other:?} (expected bstr.cbor or Digest array)"
            ))),
        }
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
struct SuitCommon<'b> {
    #[n(2)]
    components: SuitComponents, // TODO += at least 1
    #[b(4)] // we borrow bstr
    shared_seq: Option<LazyCbor<'b, SuitSharedSequence<'b>>>,
}
#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
struct SuitComponents(Vec<ComponentIdentifier>); // += at least 1

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
struct ComponentIdentifier(Vec<ByteVec>);

#[derive(Debug, Encode)]
#[cbor(transparent)]
struct SuitSharedSequence<'b>(Vec<SharedSequenceItem<'b>>); // + = at least 1

// We implement this to decode because the shared sequence is flat encoded
// it means [key, value, key, value] instead of [[key,value],[key, value]]
impl<'b, Ctx> Decode<'b, Ctx> for SuitSharedSequence<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let mut items: Vec<SharedSequenceItem<'b>> = Vec::new();

        // handler closure called for each op; it must consume the argument.
        decode_flat_pairs(d, ctx, |op, dec, ctx| {
            match op {
                // Commands
                12 => {
                    let idx = IndexArg::decode(dec, ctx)?;
                    items.push(SharedSequenceItem::Command(Box::new(
                        SuitSharedCommand::SetComponentIndex(idx),
                    )));
                }
                32 => {
                    let seq = LazyCbor::<SuitSharedSequence>::decode(dec, ctx)?;
                    items.push(SharedSequenceItem::Command(Box::new(
                        SuitSharedCommand::RunSequence(seq),
                    )));
                }
                15 => {
                    let arg = SuitDirectiveTryEachArgumentShared::decode(dec, ctx)?;
                    items.push(SharedSequenceItem::Command(Box::new(
                        SuitSharedCommand::TryEach(arg),
                    )));
                }
                20 => {
                    let params = SuitParameters::decode(dec, ctx)?;
                    items.push(SharedSequenceItem::Command(Box::new(
                        SuitSharedCommand::OverrideParameters(params),
                    )));
                }

                // Conditions (all consume SuitRepPolicy)
                1 | 2 | 3 | 5 | 6 | 14 | 24 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    let cond = match op {
                        1 => SuitCondition::VendorIdentifier(policy),
                        2 => SuitCondition::ClassIdentifier(policy),
                        3 => SuitCondition::ImageMatch(policy),
                        5 => SuitCondition::ComponentSlot(policy),
                        6 => SuitCondition::CheckContent(policy),
                        14 => SuitCondition::Abort(policy),
                        24 => SuitCondition::DeviceIdentifier(policy),
                        _ => unreachable!(),
                    };
                    items.push(SharedSequenceItem::Condition(cond));
                }

                other => {
                    return Err(DecodeError::message(format!(
                        "unknown shared-sequence op id {other}"
                    )));
                }
            }
            Ok(())
        })?;
        Ok(SuitSharedSequence(items))
    }
}

#[derive(Debug, Encode, Decode)]
enum SharedSequenceItem<'b> {
    #[n(0)]
    Condition(#[n(0)] SuitCondition),
    #[n(1)]
    Command(
        #[b(0)] // we borrow a bstr so we need #[b()] instead of #[n()]
        Box<SuitSharedCommand<'b>>,
    ),
}

#[derive(Debug, Encode, Decode)]
enum SuitSharedCommand<'b> {
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
enum IndexArg {
    #[n(0)]
    Single(#[n(0)] u64), // uint
    #[n(1)]
    True(#[n(0)] bool), // true
    #[n(2)]
    Multiple(#[n(0)] Vec<u64>), // [+uint]
}
impl<'b, Ctx> minicbor::Decode<'b, Ctx> for IndexArg {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<Self, minicbor::decode::Error> {
        use minicbor::data;

        match d.datatype()? {
            data::Type::U8 | data::Type::U16 | data::Type::U32 | data::Type::U64 => {
                let v = d.u64()?;
                Ok(IndexArg::Single(v))
            }

            data::Type::Bool => {
                let b = d.bool()?;
                Ok(IndexArg::True(b))
            }

            data::Type::Array => {
                let len = d.array()?;
                let mut vec = Vec::new();
                if let Some(n) = len {
                    for _ in 0..n {
                        vec.push(d.u64()?);
                    }
                } else {
                    loop {
                        if let data::Type::Break = d.datatype()? {
                            break;
                        }
                        vec.push(d.u64()?);
                    }
                }
                Ok(IndexArg::Multiple(vec))
            }

            other => Err(minicbor::decode::Error::message(format!(
                "unexpected type for IndexArg: {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
struct SuitDirectiveTryEachArgumentShared<'b> {
    #[cbor(borrow)]
    sequences: Option<Vec<LazyCbor<'b, SuitSharedSequence<'b>>>>, // 2* bstr.cbor SUIT_Shared_Sequence
}

#[derive(Debug, Encode)]
#[cbor(transparent)]
// Implement
struct SuitCommandSequence<'b> {
    item: Vec<SuitCommand<'b>>,
}
impl<'b, Ctx> Decode<'b, Ctx> for SuitCommandSequence<'b> {
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let mut items: Vec<SuitCommand> = Vec::new();
        decode_flat_pairs(d, ctx, |op, dec, ctx| {
            match op {
                // Conditions
                1 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::VendorIdentifier(
                        policy,
                    )));
                }
                2 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::ClassIdentifier(
                        policy,
                    )));
                }
                3 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::ImageMatch(policy)));
                }
                5 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::ComponentSlot(policy)));
                }
                6 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::CheckContent(policy)));
                }
                14 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::Abort(policy)));
                }
                24 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::DeviceIdentifier(
                        policy,
                    )));
                }

                // Directives
                18 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Write(policy)));
                }
                12 => {
                    let idx = IndexArg::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::SetComponentIndex(
                        idx,
                    )));
                }
                32 => {
                    let seq = LazyCbor::<SuitCommandSequence<'b>>::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::RunSequence(seq)));
                }
                15 => {
                    let arg = SuitDirectiveTryEachArgument::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::TryEach(arg)));
                }
                20 => {
                    let params = SuitParameters::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::OverrideParameters(
                        params,
                    )));
                }
                21 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Fetch(policy)));
                }
                22 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Copy(policy)));
                }
                31 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Swap(policy)));
                }
                23 => {
                    let policy = SuitRepPolicy::decode(dec, ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Invoke(policy)));
                }

                // Custom commands (negative int keys)
                other if other < 0 => {
                    let v = CommandCustomValue::decode(dec, ctx)?;
                    items.push(SuitCommand::Custom(v));
                }

                unknown => {
                    return Err(DecodeError::message(format!(
                        "unknown command op id {unknown}"
                    )));
                }
            }
            Ok(())
        })?;
        Ok(SuitCommandSequence { item: items })
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
enum SuitCommand<'b> {
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
enum CommandCustomValue {
    #[n(0)]
    Bytes(#[n(0)] Vec<u8>),
    #[n(1)]
    Text(#[n(0)] String),
    #[n(2)]
    Integer(#[n(0)] i64),
    #[n(3)]
    Nil,
}
impl<'b, Ctx> minicbor::Decode<'b, Ctx> for CommandCustomValue {
    fn decode(
        d: &mut minicbor::Decoder<'b>,
        _ctx: &mut Ctx,
    ) -> Result<Self, minicbor::decode::Error> {
        use minicbor::data;

        // debug helper
        eprintln!(
            "CommandCustomValue: pos={:?}, next={:?}, remaining={}",
            d.position(),
            d.datatype()?,
            minicbor::display(d.input())
        );

        match d.datatype()? {
            data::Type::Bytes => {
                let v = d.bytes()?.to_vec();
                Ok(CommandCustomValue::Bytes(v))
            }

            data::Type::String => {
                let s = d.str()?;
                Ok(CommandCustomValue::Text(s.to_string()))
            }

            data::Type::U8 | data::Type::U16 | data::Type::U32 | data::Type::U64 => {
                let v = d.u64()? as i64;
                Ok(CommandCustomValue::Integer(v))
            }

            data::Type::I8 | data::Type::I16 | data::Type::I32 | data::Type::I64 => {
                let v = d.i64()?;
                Ok(CommandCustomValue::Integer(v))
            }

            data::Type::Null => {
                d.null()?;
                Ok(CommandCustomValue::Nil)
            }

            other => Err(minicbor::decode::Error::message(format!(
                "unexpected type for CommandCustomValue: {other:?}"
            ))),
        }
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(transparent)]
struct SuitRepPolicy(#[cbor(with = "impl_for_bitflags")] SuitReportingBits);

bitflags::bitflags! {
    #[derive(Debug)]
    struct SuitReportingBits: u8 {
        const SEND_RECORD_SUCCESS  = 0b0001;
        const SEND_RECORD_FAILURE  = 0b0010;
        const SEND_SYSINFO_SUCCESS = 0b0100;
        const SEND_SYSINFO_FAILURE = 0b1000;
    }
}
mod impl_for_bitflags {
    use super::*;
    use minicbor::{Decoder, decode::Error};
    pub fn encode<W: minicbor::encode::Write, Ctx>(
        val: &SuitReportingBits,
        e: &mut Encoder<W>,
        _: &mut Ctx,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        e.u8(val.bits())?;
        println!("bytes decoded");
        Ok(())
    }

    pub fn decode<'b, Ctx>(d: &mut Decoder<'b>, _: &mut Ctx) -> Result<SuitReportingBits, Error> {
        let bits = d.u8()?;
        Ok(SuitReportingBits::from_bits_truncate(bits))
    }
}

#[derive(Debug, Encode, Decode)]
enum SuitCondition {
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
enum SuitDirective<'b> {
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
struct SuitDirectiveTryEachArgument<'b>(#[cbor(borrow)] Vec<LazyCbor<'b, SuitCommandSequence<'b>>>);

/// Helper : accept RFC4122 UUID (bstr len 16) or cbor-pen tag (#6.112 (bstr))
pub fn decode_uuid_or_cborpen<'b, Ctx>(
    d: &mut Decoder<'b>,
    _ctx: &mut Ctx,
) -> Result<Option<Vec<u8>>, DecodeError> {
    match d.datatype()? {
        minicbor::data::Type::Tag => {
            let t = d.tag()?;
            if t.as_u64() == 112 {
                let b = d.bytes()?;
                let mut uuid = Vec::with_capacity(16);
                uuid.extend_from_slice(b);
                Ok(Some(uuid))
            } else {
                Err(minicbor::decode::Error::message(
                    "expected tag 112 for cbor-pen",
                ))
            }
        }
        minicbor::data::Type::Bytes => {
            let b = d.bytes()?;
            Ok(Some(b.to_vec()))
        }
        other => Err(minicbor::decode::Error::message(format!(
            "expected UUID or cbor-pen, got {other:?}"
        ))),
    }
}

#[derive(Debug, Encode, Decode)]
#[cbor(map)]
struct SuitParameters<'b> {
    #[n(1)]
    #[cbor(decode_with = "decode_uuid_or_cborpen")]
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
struct Tag38LTag(String);

// Only accept regex matching tags
impl<'b, C> Decode<'b, C> for Tag38LTag {
    fn decode(d: &mut Decoder<'b>, _: &mut C) -> Result<Self, DecodeError> {
        let tag = String::from_utf8_lossy(d.bytes()?);
        let re = Regex::new(r"^[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*$").unwrap();
        if re.is_match(&tag) {
            return Ok(Tag38LTag(tag.into_owned()));
        }
        Err(DecodeError::message("Invalid tag38-ltag format"))
    }
}

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
