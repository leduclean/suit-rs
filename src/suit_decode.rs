use crate::flat_ops::decode_flat_pairs;
use crate::lazycbor::LazyCbor;
use crate::suit_cose::*;
use crate::suit_manifest::*;
use minicbor::{Decode, Decoder, data::Type, decode::Error as DecodeError, display};
use regex::Regex;

impl<'b, T, Ctx> Decode<'b, Ctx> for Debug<T>
where
    T: Decode<'b, Ctx>,
{
    fn decode(d: &mut Decoder<'b>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        println!("Decoding struct: {}", core::any::type_name::<Self>());
        println!("Decoding with debug...");
        let bytes = d.input();
        println!("Shared sequence raw: {}", display(bytes));
        let inner = T::decode(d, ctx)?;
        Ok(Debug(inner))
    }
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

impl<'b, Ctx> Decode<'b, Ctx> for SuitReportingBits {
    fn decode(d: &mut Decoder<'b>, _: &mut Ctx) -> Result<Self, DecodeError> {
        let bits = d.u8()?;
        Ok(SuitReportingBits::from_bits_truncate(bits))
    }
}

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
