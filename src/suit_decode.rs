use crate::errors::SuitError;
use crate::handler::*;
use crate::raw_input::*;
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

impl<'a, T, Ctx, const N: usize> Decode<'a, Ctx> for CborVec<T, N>
where
    T: Decode<'a, Ctx> + core::fmt::Debug,
{
    fn decode(d: &mut Decoder<'a>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let iter: ArrayIterWithCtx<_, T> = d.array_iter_with(ctx)?;
        let mut vec: Vec<T, N> = Vec::new();

        for x in iter {
            let item = x?;
            vec.push(item)
                .map_err(|_| DecodeError::message("Inner decoding buffer is full"))?;
        }

        Ok(CborVec(vec))
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for SuitAuthenticationBlock<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let tag = d.tag()?;
        match tag.as_u64() {
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

            _ => Err(minicbor::decode::Error::tag_mismatch(tag)
                .with_message("SuitAuthenticationBlock: unexpected tag value")),
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
            // Call T::decode on the current decoder: if T is BstrStruct<'a, >,
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
            _ => Err(minicbor::decode::Error::type_mismatch(ty)
                .with_message("DigestOrCbor: expected Bytes (CBOR bstr.cbor) or Array (digest)")),
        }
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for IndexArg {
    fn decode(d: &mut minicbor::Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
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
                let mut vec: Vec<u64, SUIT_MAX_INDEX_NUM> = Vec::new();
                if let Some(n) = len {
                    for _ in 0..n {
                        vec.push(d.u64()?).map_err(|_| {
                            DecodeError::message("Inner Index Arg decoding buffer is full")
                        })?;
                    }
                } else {
                    loop {
                        if let Type::Break = d.datatype()? {
                            break;
                        }
                    }
                }
                Ok(IndexArg::Multiple(CborVec(vec)))
            }

            _ => Err(minicbor::decode::Error::type_mismatch(ty)
                .with_message("IndexArg: expected Number | Bool | Array")),
        }
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for CommandCustomValue<'a> {
    fn decode(d: &mut minicbor::Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
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

            _ => Err(minicbor::decode::Error::type_mismatch(ty)
                .with_message("CommandCustomValue: expected Bytes | String | number | Null")),
        }
    }
}

/// Helper : accept RFC4122 UUID (bstr len 16) or cbor-pen tag (#6.112 (bstr))
pub(crate) fn decode_uuid_or_cborpen<'a, Ctx>(
    // TODO: refactor by using [cbor(tag=112)] in new VendorIdentifier type
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
                    Err(minicbor::decode::Error::message(
                        "UUID is too long (more than 16 bytes)",
                    ))
                } else {
                    Ok(Some(<&ByteSlice>::from(b)))
                }
            } else {
                Err(minicbor::decode::Error::type_mismatch(ty)
                    .with_message("UUID/CborPen: unexpected tag"))
            }
        }
        Type::Bytes => Ok(Some(d.bytes().map(<&ByteSlice>::from)?)),
        _ => Err(minicbor::decode::Error::type_mismatch(ty)
            .with_message("UUID/CborPen: expected UUID or cbor-pen")),
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
        let tag = d.str()?;
        if is_valid_tag38ltag(tag) {
            Ok(Tag38LTag(tag))
        } else {
            Err(DecodeError::message("Invalid Tag38LTag format"))
        }
    }
}
/// Helper to assert `[a-zA-Z]{1,8}(-[a-zA-Z0-9]{1,8})*` tag format.
/// (Regex not possible in no_std)
fn is_valid_tag38ltag(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    // First segment: only alphabetic, 1 to 8 chars
    let mut count = 0;
    while let Some(&c) = chars.peek() {
        if c.is_ascii_alphabetic() {
            chars.next();
            count += 1;
            if count > 8 {
                return false;
            }
        } else {
            break;
        }
    }
    if count == 0 {
        return false;
    }
    // Remaining segments: "-" followed by 1–8 alphanumeric chars
    while let Some(&c) = chars.peek() {
        if c != '-' {
            return false;
        }
        chars.next(); // consume '-'
        count = 0;
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphanumeric() {
                chars.next();
                count += 1;
                if count > 8 {
                    return false;
                }
            } else {
                break;
            }
        }
        if count == 0 {
            return false;
        }
    }
    true
}

impl<'a> SuitSharedSequence<'a> {
    #[allow(dead_code)]
    fn decode_and_dispatch<H>(&mut self, handler: &mut H) -> Result<(), SuitError>
    where
        H: SuitSharedSequenceHandler,
    {
        let pairs = self.0.collect_pairs()?;
        let cond_iter = iter_conditions(&pairs);
        let command_iter = iter_shared_command(&pairs);
        handler.on_conditions(cond_iter)?;
        handler.on_commands(command_iter)?;
        Ok(())
    }
}

impl<'a> SuitCommandSequence<'a> {
    #[allow(dead_code)]
    fn decode_and_dispatch<H>(&mut self, handler: &mut H) -> Result<(), SuitError>
    where
        H: SuitCommandHandler,
    {
        let pairs = self.0.collect_pairs()?;
        let cond_iter = iter_conditions(&pairs);
        let direct_iter = iter_directives(&pairs);
        let custom_iter = iter_custom(&pairs);
        handler.on_conditions(cond_iter)?;
        handler.on_directives(direct_iter)?;
        handler.on_customs(custom_iter)?;
        Ok(())
    }
}

/// Starting entry point to decode a SUIT structure and dispatch the decoded items to the handler.
pub(crate) fn decode_and_dispatch<H>(buf: &[u8], handler: &mut H) -> Result<(), SuitError>
where
    H: SuitStartHandler,
{
    // on match ici sur le tag qui nous permet d'identifier la variante mais ca serait la meme chose avec des champs à type multiple.
    let mut d = Decoder::new(buf);
    let tag = d.tag()?;
    let ctx = &mut ();
    match tag.as_u64() {
        107 => {
            let envelope = d.decode_with(ctx)?;
            handler.on_envelope(envelope)
        }
        1070 => {
            let manifest = d.decode_with(ctx)?;
            handler.on_manifest(manifest)
        }
        _ => Err(DecodeError::tag_mismatch(tag)
            .with_message("SuitStart: unexpected tag (expected 107:envelope or 1070:manifest)")
            .into()),
    }
}

mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::raw_input::*;

    #[allow(dead_code)]
    struct TestHandler;

    impl SuitSharedSequenceHandler for TestHandler {
        fn on_conditions(
            &mut self,
            conditions: impl Iterator<Item = Result<SuitCondition, SuitError>>,
        ) -> Result<(), SuitError> {
            for cond in conditions {
                assert!(matches!(
                    cond.unwrap(),
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

        fn on_commands<'a>(
            &mut self,
            commands: impl Iterator<Item = Result<SuitSharedCommand<'a>, SuitError>>,
        ) -> Result<(), SuitError> {
            for cmd in commands {
                assert!(matches!(
                    cmd.unwrap(),
                    SuitSharedCommand::SetComponentIndex(_)
                        | SuitSharedCommand::RunSequence(_)
                        | SuitSharedCommand::TryEach(_)
                        | SuitSharedCommand::OverrideParameters(_)
                ));
            }
            Ok(())
        }
    }

    impl SuitCommandHandler for TestHandler {
        fn on_conditions<'a>(
            &mut self,
            conditions: impl Iterator<Item = Result<SuitCondition, SuitError>>,
        ) -> Result<(), SuitError> {
            for cond in conditions {
                assert!(matches!(
                    cond.unwrap(),
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

        fn on_directives<'a>(
            &mut self,
            directives: impl Iterator<Item = Result<SuitDirective<'a>, SuitError>>,
        ) -> Result<(), SuitError> {
            for dir in directives {
                assert!(matches!(
                    dir.unwrap(),
                    SuitDirective::Write(_)
                        | SuitDirective::SetComponentIndex(_)
                        | SuitDirective::RunSequence(_)
                        | SuitDirective::TryEach(_)
                        | SuitDirective::OverrideParameters(_)
                        | SuitDirective::Fetch(_)
                        | SuitDirective::Copy(_)
                        | SuitDirective::Swap(_)
                        | SuitDirective::Invoke(_)
                ));
            }
            Ok(())
        }
        fn on_customs<'a>(
            &mut self,
            customs: impl Iterator<Item = Result<CommandCustomValue<'a>, SuitError>>,
        ) -> Result<(), SuitError> {
            for cust in customs {
                assert!(matches!(
                    cust.unwrap(),
                    CommandCustomValue::Bytes(_)
                        | CommandCustomValue::Text(_)
                        | CommandCustomValue::Integer(_)
                        | CommandCustomValue::Nil
                ))
            }
            Ok(())
        }
    }

    #[test]
    fn test_suit_shared_sequence_decode() {
        // Flat Shared sequence of B.6.Example 5 from ietf suit spec
        const SUIT_SHARED_SEQUENCE: cboritem::CborItem<'static> = cbor_macro::cbo!(
            r#"[
                    / directive-set-component-index / 12,0,
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
                    / condition-class-identifier / 2,15,
                    / directive-set-component-index / 12,1,
                    / directive-override-parameters / 20,{
                        / image-digest / 3:<< [
                            / algorithm-id / -16 / "sha256" /,
                            / digest-bytes /
h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                        ] >>,
                        / image-size / 14:76834
                    }
                ]"#
        );
        let mut seq = SuitCommandSequence(
            RawInput::decode(&mut Decoder::new(&SUIT_SHARED_SEQUENCE), &mut ()).unwrap(),
        );
        let mut handler = TestHandler;
        seq.decode_and_dispatch(&mut handler).unwrap();
        assert!(seq.decode_and_dispatch(&mut handler).is_ok());
    }

    #[test]
    fn test_suit_command_sequence() {
        // Flat command sequence from validate of B.6 Example 5 from ietf suit spec
        const SUIT_VALIDATE_COMMAND_SEQUENCE: cboritem::CborItem<'static> = cbor_macro::cbo!(
            r#"[
                / directive-set-component-index / 12,0,
                / condition-image-match / 3,15,
                / directive-set-component-index / 12,1,
                / condition-image-match / 3,15
            ] "#
        );
        let mut seq = SuitCommandSequence(
            RawInput::decode(&mut Decoder::new(&SUIT_VALIDATE_COMMAND_SEQUENCE), &mut ()).unwrap(),
        );
        let mut handler = TestHandler;
        seq.decode_and_dispatch(&mut handler).unwrap();
    }
}
