use crate::flat_ops::decode_flat_pairs;
use crate::lazycbor::LazyCbor;
use crate::suit_cose::*;
use crate::suit_manifest::*;
use core::str;
use core::usize;
use heapless::Vec;
use minicbor::bytes::ByteSlice;
use minicbor::{
    Decode, Decoder,
    data::Type,
    decode::{ArrayIterWithCtx, Error as DecodeError},
};

#[cfg(feature = "alloc")]
use minicbor::display;

#[cfg(feature = "alloc")]
impl<'a, T, Ctx> Decode<'a, Ctx> for Debug<T>
where
    T: Decode<'a, ()>,
{
    fn decode(d: &mut Decoder<'a>, _: &mut Ctx) -> Result<Self, DecodeError> {
        defmt::info!("Decoding struct: {}", core::any::type_name::<Self>());
        defmt::info!("Decoding with debug...");
        let bytes = d.input();
        defmt::info!("Shared sequence raw: {}", display(bytes));
        let inner = T::decode(d, &mut ())?;
        Ok(Debug(inner))
    }
}

// helper to log with defmt::info! the right Type encountered
pub fn type_to_str(t: Type) -> &'static str {
    match t {
        Type::U8 => "U8",
        Type::U16 => "U16",
        Type::U32 => "U32",
        Type::U64 => "U64",
        Type::I8 => "I8",
        Type::I16 => "I16",
        Type::I32 => "I32",
        Type::I64 => "I64",
        Type::F16 => "Float16",
        Type::F32 => "Float32",
        Type::F64 => "Float64",
        Type::Bytes => "Bytes",
        Type::String => "String",
        Type::Array => "Array",
        Type::Map => "Map",
        Type::Tag => "Tag",
        Type::Simple => "Simple",
        Type::Bool => "Bool",
        Type::Null => "Null",
        Type::Undefined => "Undefined",
        Type::Break => "Break",
        _ => "Unknown",
    }
}

impl<'a, T, Ctx, const N: usize> Decode<'a, Ctx> for CborVec<T, N>
where
    T: Decode<'a, Ctx>,
{
    fn decode(d: &mut Decoder<'a>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let iter: ArrayIterWithCtx<_, T> = d.array_iter_with(ctx)?;
        let mut v: Vec<T, N> = Vec::new();

        for x in iter {
            let item = x?;
            v.push(item).map_err(|_item| {
                defmt::error!("Too many items in a heapless Vec");
                DecodeError::message("Too many items in a Vec")
            })?;
        }

        Ok(CborVec(v))
    }
}

impl<'a> Decode<'a, ()> for SuitStart<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut ()) -> Result<Self, DecodeError> {
        match d.tag()?.as_u64() {
            107 => Ok(SuitStart::EnvelopeTagged(
                d.decode_with::<(), SuitEnvelope>(_ctx)?,
            )),
            1070 => Ok(SuitStart::ManifestTagged(
                d.decode_with::<(), SuitManifest>(_ctx)?,
            )),
            0 => Ok(SuitStart::Start),
            other => {
                defmt::error!("SuitStart: unexpected tag: {:?}", other);
                Err(minicbor::decode::Error::message(
                    "unexpected tag for SuitStart",
                ))
            }
        }
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for SuitAuthenticationBlock {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        match d.tag()?.as_u64() {
            98 => Ok(SuitAuthenticationBlock::Sign(
                d.decode_with::<Ctx, CoseSign>(_ctx)?,
            )),
            18 => Ok(SuitAuthenticationBlock::Sign1(
                d.decode_with::<Ctx, CoseSign1>(_ctx)?,
            )),
            97 => Ok(SuitAuthenticationBlock::Mac(
                d.decode_with::<Ctx, CoseMac>(_ctx)?,
            )),
            17 => Ok(SuitAuthenticationBlock::Mac0(
                d.decode_with::<Ctx, CoseMac0>(_ctx)?,
            )),

            other => {
                defmt::error!("SuitAuthenticationBlock: unexpected tag: {:?}", other);
                Err(minicbor::decode::Error::message(
                    "unexpected tag for SuitAuthenticationBlock",
                ))
            }
        }
    }
}

impl<'a, Ctx, T> Decode<'a, Ctx> for DigestOrCbor<'a, T>
where
    T: Decode<'a, Ctx>,
{
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        match d.datatype()? {
            // bstr.cbor case (or generic bytes wrapper for the CBOR value)
            // Call T::decode on the current decoder: if T is LazyCbor<'a, >,
            // it will call d.bytes() and then decode the inner CBOR.
            Type::Bytes => {
                let t = T::decode(d, _ctx)?;
                Ok(DigestOrCbor::Cbor(t))
            }

            // Digest is encoded as a CBOR array [algorithm_id, bytes]
            // so we expect an Array here and decode SuitDigest
            Type::Array => {
                let digest = SuitDigest::decode(d, _ctx)?;
                Ok(DigestOrCbor::Digest(digest))
            }
            other => {
                defmt::error!(
                    "SuitAuthenticationBlock: unexpected type: {:?}",
                    type_to_str(other)
                );
                Err(minicbor::decode::Error::message(
                    "unexpected type for SuitAuthenticationBlock",
                ))
            }
        }
    }
}
// We implement this to decode because the shared sequence is flat encoded
// it means [key, value, key, value] instead of [[key,value],[key, value]]
impl<'a, Ctx> Decode<'a, Ctx> for SuitSharedSequence<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let mut items: Vec<SharedSequenceItem<'a>, SUIT_MAX_ARRAY_LENGTH> = Vec::new();

        // handler closure called for each op; it must consume the argument.
        decode_flat_pairs(d, |op, dec| {
            match op {
                // Commands
                12 => {
                    let idx = IndexArg::decode(dec, _ctx)?;
                    items.push(SharedSequenceItem::Command(
                        SuitSharedCommand::SetComponentIndex(idx),
                    ));
                }
                32 => {
                    let seq = LazyCbor::<SuitSharedSequence>::decode(dec, _ctx)?;
                    items.push(SharedSequenceItem::Command(SuitSharedCommand::RunSequence(
                        seq,
                    )));
                }
                15 => {
                    let arg = SuitDirectiveTryEachArgumentShared::decode(dec, _ctx)?;
                    items.push(SharedSequenceItem::Command(SuitSharedCommand::TryEach(arg)));
                }
                20 => {
                    let params = SuitParameters::decode(dec, _ctx)?;
                    items.push(SharedSequenceItem::Command(
                        SuitSharedCommand::OverrideParameters(params),
                    ));
                }

                // Conditions (all consume SuitRepPolicy)
                1 | 2 | 3 | 5 | 6 | 14 | 24 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
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
                    defmt::error!("unknow SharedSequence op id: {:?}", other);
                    return Err(minicbor::decode::Error::message(
                        "unknow SharedSequence op id",
                    ));
                }
            }
            Ok(())
        })?;
        Ok(SuitSharedSequence(CborVec(items)))
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for IndexArg {
    fn decode(
        d: &mut minicbor::Decoder<'a>,
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
                Ok(IndexArg::Multiple(CborVec(vec)))
            }

            other => {
                defmt::error!("IndexArg: unexpected type: {:?}", type_to_str(other));
                Err(minicbor::decode::Error::message(
                    "unexpected type for IndexArg",
                ))
            }
        }
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for SuitCommandSequence<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let mut items: Vec<SuitCommand, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        decode_flat_pairs(d, |op, dec| {
            match op {
                // Conditions
                1 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::VendorIdentifier(
                        policy,
                    )));
                }
                2 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::ClassIdentifier(
                        policy,
                    )));
                }
                3 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::ImageMatch(policy)));
                }
                5 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::ComponentSlot(policy)));
                }
                6 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::CheckContent(policy)));
                }
                14 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::Abort(policy)));
                }
                24 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Condition(SuitCondition::DeviceIdentifier(
                        policy,
                    )));
                }

                // Directives
                18 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Write(policy)));
                }
                12 => {
                    let idx = IndexArg::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::SetComponentIndex(
                        idx,
                    )));
                }
                32 => {
                    let seq = LazyCbor::<SuitCommandSequence<'a>>::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::RunSequence(seq)));
                }
                15 => {
                    let arg = SuitDirectiveTryEachArgument::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::TryEach(arg)));
                }
                20 => {
                    let params = SuitParameters::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::OverrideParameters(
                        params,
                    )));
                }
                21 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Fetch(policy)));
                }
                22 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Copy(policy)));
                }
                31 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Swap(policy)));
                }
                23 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    items.push(SuitCommand::Directive(SuitDirective::Invoke(policy)));
                }

                // Custom commands (negative int keys)
                other if other < 0 => {
                    let v = CommandCustomValue::decode(dec, _ctx)?;
                    items.push(SuitCommand::Custom(v));
                }

                other => {
                    defmt::error!("unknow SuitCommandSequence op id: {:?}", other);
                    return Err(minicbor::decode::Error::message(
                        "unknow SharedSequence op id",
                    ));
                }
            }
            Ok(())
        })?;
        Ok(SuitCommandSequence {
            item: CborVec(items),
        })
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for CommandCustomValue<'a> {
    fn decode(
        d: &mut minicbor::Decoder<'a>,
        _ctx: &mut Ctx,
    ) -> Result<Self, minicbor::decode::Error> {
        use minicbor::data;

        match d.datatype()? {
            data::Type::Bytes => Ok(CommandCustomValue::Bytes(d.bytes()?)),

            data::Type::String => Ok(CommandCustomValue::Text(d.str()?)),

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

            other => {
                defmt::error!(
                    "CommandCustomValue: unexpected type: {:?}",
                    type_to_str(other)
                );
                Err(minicbor::decode::Error::message(
                    "unexpected type for CommandCustomValue",
                ))
            }
        }
    }
}

/// Helper : accept RFC4122 UUID (bstr len 16) or cbor-pen tag (#6.112 (bstr))
pub fn decode_uuid_or_cborpen<'a, Ctx>(
    d: &mut Decoder<'a>,
    _ctx: &mut Ctx,
) -> Result<Option<&'a ByteSlice>, DecodeError> {
    match d.datatype()? {
        minicbor::data::Type::Tag => {
            let t = d.tag()?;
            if t.as_u64() == 112 {
                let b = d.bytes()?;
                if b.len() > 16 {
                    defmt::error!("The UUID is too long (more than 16 bytes)");
                    Err(minicbor::decode::Error::message(
                        "expected UUID or cbor-pen got other type",
                    ))
                } else {
                    Ok(Some(d.bytes().map(<&ByteSlice>::from)?))
                }
            } else {
                Err(minicbor::decode::Error::message(
                    "expected tag 112 for cbor-pen",
                ))
            }
        }
        minicbor::data::Type::Bytes => Ok(Some(d.bytes().map(<&ByteSlice>::from)?)),
        other => {
            defmt::error!("expected UUID or cbor-pen, got {:?}", type_to_str(other));
            Err(minicbor::decode::Error::message(
                "expected UUID or cbor-pen got other type",
            ))
        }
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for SuitReportingBits {
    fn decode(d: &mut Decoder<'a>, _: &mut Ctx) -> Result<Self, DecodeError> {
        let bits = d.u8()?;
        Ok(SuitReportingBits::from_bits_truncate(bits))
    }
}

// Only accept valid  tags (if working with owned tag should be at least more than 43 caract)
impl<'a, C> Decode<'a, C> for Tag38LTag<'a> {
    fn decode(d: &mut Decoder<'a>, _: &mut C) -> Result<Self, DecodeError> {
        let tag_bytes = d.bytes()?;
        if is_valid_tag38ltag(tag_bytes) {
            Ok(Tag38LTag(str::from_utf8(&tag_bytes).map_err(|e| {
                defmt::error!("Utf8 error for tag38ltag at: {:?}", e.valid_up_to());
                DecodeError::message("Utf8 parsing error for Tag38LTag")
            })?))
        } else {
            Err(DecodeError::message("Invalid tag38-ltag format"))
        }
    }
}
// Helper to assert  [a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})* tag format (Regex not possible in no_std)
fn is_valid_tag38ltag(bytes: &[u8]) -> bool {
    let mut i = 0;
    let len = bytes.len();

    let mut count = 0;
    while i < len && bytes[i].is_ascii_alphabetic() {
        i += 1;
        count += 1;
        if count > 8 {
            return false;
        }
    }
    if count == 0 {
        return false;
    }

    while i < len {
        if bytes[i] != b'-' {
            return false;
        }
        i += 1;
        count = 0;
        while i < len && (bytes[i].is_ascii_alphanumeric()) {
            i += 1;
            count += 1;
            if count > 8 {
                return false;
            }
        }
        if count == 0 {
            return false;
        }
    }

    true
}
