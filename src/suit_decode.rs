use crate::flat_ops::decode_flat_pairs;
use crate::lazycbor::LazyCbor;
use crate::suit_cose::*;
use crate::suit_manifest::*;
use core::str;
use heapless::Vec;
use minicbor::bytes::ByteSlice;
use minicbor::{
    Decode, Decoder,
    data::Type,
    decode::{ArrayIterWithCtx, Error as DecodeError},
};

#[cfg(all(feature = "alloc", feature = "defmt"))]
use minicbor::display;

#[cfg(all(feature = "alloc", feature = "defmt"))]
impl<'a, T, Ctx> Decode<'a, Ctx> for Debug<T>
where
    T: Decode<'a, ()>,
{
    fn decode(d: &mut Decoder<'a>, _: &mut Ctx) -> Result<Self, DecodeError> {
        info!("Decoding struct: {}", core::any::type_name::<Self>());
        info!("Decoding with debug...");
        let bytes = d.input();
        info!("Shared sequence raw: {}", display(bytes));
        let inner = T::decode(d, &mut ())?;
        Ok(Debug(inner))
    }
}

#[cfg(any(feature = "std", feature = "defmt"))]
// helper to log with info! the right Type encountered
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
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!("Too many items in a heapless Vec");
                DecodeError::message("Too many items in a Vec")
            })?;
        }

        Ok(CborVec(v))
    }
}

impl<'a> Decode<'a, ()> for SuitStart<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut ()) -> Result<Self, DecodeError> {
        let tag = d.tag()?.as_u64();
        match tag {
            107 => Ok(SuitStart::EnvelopeTagged(
                d.decode_with::<(), SuitEnvelope>(_ctx)?,
            )),
            1070 => Ok(SuitStart::ManifestTagged(
                d.decode_with::<(), SuitManifest>(_ctx)?,
            )),
            0 => Ok(SuitStart::Start),
            _ => {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!("SuitStart: unexpected tag: {:?}", tag);
                Err(minicbor::decode::Error::message(
                    "unexpected tag for SuitStart",
                ))
            }
        }
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for SuitAuthenticationBlock<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let tag = d.tag()?.as_u64();
        match tag {
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

            _ => {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!("SuitAuthenticationBlock: unexpected tag: {:?}", tag);
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
        let ty = d.datatype()?;
        match ty {
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
            _ => {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!(
                    "SuitAuthenticationBlock: unexpected type: {:?}",
                    type_to_str(ty)
                );
                Err(minicbor::decode::Error::message(
                    "unexpected type for SuitAuthenticationBlock",
                ))
            }
        }
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for IndexArg {
    fn decode(
        d: &mut minicbor::Decoder<'a>,
        _ctx: &mut Ctx,
    ) -> Result<Self, minicbor::decode::Error> {
        let ty = d.datatype()?;
        match ty {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
                let v = d.u64()?;
                Ok(IndexArg::Single(v))
            }

            Type::Bool => {
                let b = d.bool()?;
                Ok(IndexArg::True(b))
            }

            Type::Array => {
                let len = d.array()?;
                let mut vec = Vec::new();
                if let Some(n) = len {
                    for _ in 0..n {
                        let _ = vec.push(d.u64()?);
                    }
                } else {
                    loop {
                        if let Type::Break = d.datatype()? {
                            break;
                        }
                        let _ = vec.push(d.u64()?);
                    }
                }
                Ok(IndexArg::Multiple(CborVec(vec)))
            }

            _ => {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!("IndexArg: unexpected type: {:?}", type_to_str(ty));
                Err(minicbor::decode::Error::message(
                    "unexpected type for IndexArg",
                ))
            }
        }
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for CommandCustomValue<'a> {
    fn decode(
        d: &mut minicbor::Decoder<'a>,
        _ctx: &mut Ctx,
    ) -> Result<Self, minicbor::decode::Error> {
        let ty = d.datatype()?;
        match ty {
            Type::Bytes => Ok(CommandCustomValue::Bytes(d.bytes()?)),

            Type::String => Ok(CommandCustomValue::Text(d.str()?)),

            Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
                let v = d.u64()? as i64;
                Ok(CommandCustomValue::Integer(v))
            }

            Type::I8 | Type::I16 | Type::I32 | Type::I64 => {
                let v = d.i64()?;
                Ok(CommandCustomValue::Integer(v))
            }

            Type::Null => {
                d.null()?;
                Ok(CommandCustomValue::Nil)
            }

            _ => {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!("CommandCustomValue: unexpected type: {:?}", type_to_str(ty));
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
    let ty = d.datatype()?;
    match ty {
        Type::Tag => {
            let t = d.tag()?;
            if t.as_u64() == 112 {
                let b = d.bytes()?;
                if b.len() > 16 {
                    #[cfg(any(feature = "defmt", feature = "std"))]
                    error!("The UUID is too long (more than 16 bytes)");
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
        Type::Bytes => Ok(Some(d.bytes().map(<&ByteSlice>::from)?)),
        _ => {
            #[cfg(any(feature = "defmt", feature = "std"))]
            error!("expected UUID or cbor-pen, got {:?}", type_to_str(ty));
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
            Ok(Tag38LTag(str::from_utf8(tag_bytes).map_err(|_e| {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!("Utf8 error for tag38ltag at: {:?}", _e.valid_up_to());
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

impl<'a> SuitSharedSequence<'a> {
    fn decode_and_dispatch<H>(&self, handler: &mut H) -> Result<(), DecodeError>
    where
        H: SuitSharedSequenceHandler<'a>,
    {
        let _ctx = &mut ();
        let mut commands: Vec<SuitSharedCommand<'a>, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut conditions: Vec<SuitCondition, SUIT_MAX_ARRAY_LENGTH> = Vec::new();

        // on match ici sur le tag qui nous permet d'identifier la variante mais ca serait la meme chose avec des champs à type multiple.
        let mut d = Decoder::new(self.0);
        decode_flat_pairs(&mut d, |op, dec| {
            match op {
                // Commands
                12 => {
                    let idx = IndexArg::decode(dec, _ctx)?;
                    let _ = commands.push(SuitSharedCommand::SetComponentIndex(idx));
                }
                32 => {
                    let seq = LazyCbor::<SuitSharedSequence>::decode(dec, _ctx)?;
                    let _ = commands.push(SuitSharedCommand::RunSequence(seq));
                }
                15 => {
                    let arg = SuitDirectiveTryEachArgumentShared::decode(dec, _ctx)?;
                    let _ = commands.push(SuitSharedCommand::TryEach(arg));
                }
                20 => {
                    let params = SuitParameters::decode(dec, _ctx)?;
                    let _ = commands.push(SuitSharedCommand::OverrideParameters(params));
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
                    let _ = conditions.push(cond);
                }

                _ => {
                    #[cfg(any(feature = "defmt", feature = "std"))]
                    error!("unknow SharedSequence op id: {:?}", op);
                    return Err(minicbor::decode::Error::message(
                        "unknow SharedSequence op id",
                    ));
                }
            }

            Ok(())
        })?;

        if !conditions.is_empty() {
            handler.on_conditions(conditions)?;
        }
        if !commands.is_empty() {
            handler.on_commands(commands)?;
        }
        Ok(())
    }
}

impl<'a> SuitCommandSequence<'a> {
    fn decode_and_dispatch<H>(&self, handler: &mut H) -> Result<(), DecodeError>
    where
        H: SuitCommandHandler<'a>,
    {
        let _ctx = &mut ();
        let mut conditions: Vec<SuitCondition, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut directives: Vec<SuitDirective, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut customs: Vec<CommandCustomValue, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut d = Decoder::new(self.item);

        decode_flat_pairs(&mut d, |op, dec| {
            match op {
                // Conditions
                1 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = conditions.push(SuitCondition::VendorIdentifier(policy));
                }
                2 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = conditions.push(SuitCondition::ClassIdentifier(policy));
                }
                3 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = conditions.push(SuitCondition::ImageMatch(policy));
                }
                5 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = conditions.push(SuitCondition::ComponentSlot(policy));
                }
                6 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = conditions.push(SuitCondition::CheckContent(policy));
                }
                14 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = conditions.push(SuitCondition::Abort(policy));
                }
                24 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = conditions.push(SuitCondition::DeviceIdentifier(policy));
                }

                // Directives
                18 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::Write(policy));
                }
                12 => {
                    let idx = IndexArg::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::SetComponentIndex(idx));
                }
                32 => {
                    let seq = LazyCbor::<SuitCommandSequence<'a>>::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::RunSequence(seq));
                }
                15 => {
                    let arg = SuitDirectiveTryEachArgument::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::TryEach(arg));
                }
                20 => {
                    let params = SuitParameters::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::OverrideParameters(params));
                }
                21 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::Fetch(policy));
                }
                22 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::Copy(policy));
                }
                31 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::Swap(policy));
                }
                23 => {
                    let policy = SuitRepPolicy::decode(dec, _ctx)?;
                    let _ = directives.push(SuitDirective::Invoke(policy));
                }

                // Custom commands (negative int keys)
                other if other < 0 => {
                    let v = CommandCustomValue::decode(dec, _ctx)?;
                    let _ = customs.push(v);
                }

                _ => {
                    #[cfg(any(feature = "defmt", feature = "std"))]
                    error!("unknow SuitCommandSequence op id: {:?}", op);
                    return Err(minicbor::decode::Error::message(
                        "unknow SharedSequence op id",
                    ));
                }
            }
            Ok(())
        })?;

        if !conditions.is_empty() {
            handler.on_conditions(conditions)?;
        }

        if !directives.is_empty() {
            handler.on_directives(directives)?;
        }

        if !customs.is_empty() {
            handler.on_customs(customs)?;
        }
        Ok(())
    }
}

mod tests {
    use super::*;
    struct TestHandler;
    impl<'a> SuitSharedSequenceHandler<'a> for TestHandler {
        fn on_conditions(
            &mut self,
            conditions: Vec<SuitCondition, SUIT_MAX_ARRAY_LENGTH>,
        ) -> Result<(), DecodeError> {
            for cond in conditions {
                assert!(matches!(
                    cond,
                    SuitCondition::VendorIdentifier(_)
                        | SuitCondition::ClassIdentifier(_)
                        | SuitCondition::ImageMatch(_)
                        | SuitCondition::ComponentSlot(_)
                        | SuitCondition::CheckContent(_)
                        | SuitCondition::Abort(_)
                        | SuitCondition::DeviceIdentifier(_)
                ));
            }
            Ok(())
        }

        fn on_commands(
            &mut self,
            commands: Vec<SuitSharedCommand<'a>, SUIT_MAX_ARRAY_LENGTH>,
        ) -> Result<(), DecodeError> {
            for cmd in commands {
                assert!(matches!(
                    cmd,
                    SuitSharedCommand::SetComponentIndex(_)
                        | SuitSharedCommand::RunSequence(_)
                        | SuitSharedCommand::TryEach(_)
                        | SuitSharedCommand::OverrideParameters(_)
                ));
            }
            Ok(())
        }
    }

    #[test]
    fn test_suit_shared_sequence_decode() {
        // Minimal flat shared sequence: 1 command + 1 condition
        const SUIT_SHARED_SEQUENCE_MINIMAL: &[u8] = &[
            0x84, // CBOR array of 4 elements → 2 pairs (op, arg)
            // -----------------------
            // COMMAND: directive-override-parameters (op = 20)
            0x14, // op 20
            0xA1, // map(1) → argument map for SuitParameters
            0x01, // key n(1) = vendor_identifier
            0x50, // bstr(16) → minimal vendor UUID
            0xFA, 0x6B, 0x4A, 0x53, 0xD5, 0xAD, 0x5F, 0xDF, 0xBE, 0x9D, 0xE6, 0x63, 0xE4, 0xD4,
            0x1F, 0xFE,
            // -----------------------
            // CONDITION: condition-vendor-identifier (op = 1)
            0x01, // op 1
            0x0F, // arg 15
        ];

        let seq = SuitSharedSequence(SUIT_SHARED_SEQUENCE_MINIMAL.into());
        let mut handler = TestHandler;
        seq.decode_and_dispatch(&mut handler).unwrap();
        assert!(seq.decode_and_dispatch(&mut handler).is_ok());
    }
}
