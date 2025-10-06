pub use crate::errors::SuitError;
use crate::flat_ops::decode_flat_pairs;
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

/// Helper to log if push failed in a heapless vec
fn vec_push_or_error<T: core::fmt::Debug, const N: usize>(
    vec: &mut heapless::Vec<T, N>,
    item: T,
    context: &'static str,
) -> Result<(), SuitError> {
    vec.push(item)
        .map_err(|_| SuitError::vec_overflow(N).with_ctx(context))
}

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

// We only want the input bytes given to this decoder, doing so, we can treat it after, calling `decode_and_dispatch()`
impl<'a, C> Decode<'a, C> for RawInput<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut C) -> Result<Self, DecodeError> {
        Ok(RawInput(d.input()))
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
                    error!(
                        "UUID/CborPen: invalid length {} (expected <= 16). Raw bytes (first 32 bytes): {:?}",
                        b.len(),
                        defmt::Debug2Format(&b[..core::cmp::min(b.len(), 32)])
                    );
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
        let tag_bytes = d.bytes()?;
        if is_valid_tag38ltag(tag_bytes) {
            Ok(Tag38LTag(str::from_utf8(tag_bytes).map_err(|_e| {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!(
                    "Utf8 error for Tag38LTag: valid_up_to={}, raw (first 32 bytes): {:?}",
                    _e.valid_up_to(),
                    defmt::Debug2Format(&tag_bytes[..core::cmp::min(tag_bytes.len(), 32)])
                );
                DecodeError::message("Utf8 parsing error for Tag38LTag")
            })?))
        } else {
            #[cfg(any(feature = "defmt", feature = "std"))]
            error!(
                "Invalid Tag38LTag format for bytes (len={}): {:?}",
                tag_bytes.len(),
                defmt::Debug2Format(&tag_bytes[..core::cmp::min(tag_bytes.len(), 32)])
            );
            Err(DecodeError::message("Invalid Tag38LTag format"))
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
    #[allow(dead_code)]
    fn decode_and_dispatch<H>(&self, handler: &mut H) -> Result<(), SuitError>
    where
        H: SuitSharedSequenceHandler,
    {
        let _ctx = &mut ();
        let mut commands: Vec<SuitSharedCommand<'a>, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut conditions: Vec<SuitCondition, SUIT_MAX_ARRAY_LENGTH> = Vec::new();

        let mut d = Decoder::new(self.0.0);
        decode_flat_pairs(&mut d, |op, dec| {
            match op {
                // Commands
                12 => {
                    let idx = IndexArg::decode(dec, _ctx)?;
                    vec_push_or_error(
                        &mut commands,
                        SuitSharedCommand::SetComponentIndex(idx),
                        "commands",
                    )?;
                }
                32 => {
                    let seq = BstrSuitSharedSequence::decode(dec, _ctx)?;
                    vec_push_or_error(
                        &mut commands,
                        SuitSharedCommand::RunSequence(seq),
                        "commands",
                    )?;
                }
                15 => {
                    let arg = SuitDirectiveTryEachArgumentShared::decode(dec, _ctx)?;
                    vec_push_or_error(&mut commands, SuitSharedCommand::TryEach(arg), "commands")?;
                }
                20 => {
                    let params = SuitParameters::decode(dec, _ctx)?;
                    vec_push_or_error(
                        &mut commands,
                        SuitSharedCommand::OverrideParameters(params),
                        "commands",
                    )?;
                }

                // Conditions
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
                    vec_push_or_error(&mut conditions, cond, "conditions")?;
                }

                _ => {
                    return Err(DecodeError::unknown_variant(op)
                        .with_message("SharedSequence: unknown op id")
                        .into());
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
    #[allow(dead_code)]
    fn decode_and_dispatch<H>(&self, handler: &mut H) -> Result<(), SuitError>
    where
        H: SuitCommandHandler,
    {
        let _ctx = &mut ();
        let mut conditions: Vec<SuitCondition, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut directives: Vec<SuitDirective, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut customs: Vec<CommandCustomValue, SUIT_MAX_ARRAY_LENGTH> = Vec::new();
        let mut d = Decoder::new(self.0.0);

        decode_flat_pairs(&mut d, |op, dec| {
            match op {
                // Conditions
                1 => vec_push_or_error(
                    &mut conditions,
                    SuitCondition::VendorIdentifier(SuitRepPolicy::decode(dec, _ctx)?),
                    "conditions",
                )?,
                2 => vec_push_or_error(
                    &mut conditions,
                    SuitCondition::ClassIdentifier(SuitRepPolicy::decode(dec, _ctx)?),
                    "conditions",
                )?,
                3 => vec_push_or_error(
                    &mut conditions,
                    SuitCondition::ImageMatch(SuitRepPolicy::decode(dec, _ctx)?),
                    "conditions",
                )?,
                5 => vec_push_or_error(
                    &mut conditions,
                    SuitCondition::ComponentSlot(SuitRepPolicy::decode(dec, _ctx)?),
                    "conditions",
                )?,
                6 => vec_push_or_error(
                    &mut conditions,
                    SuitCondition::CheckContent(SuitRepPolicy::decode(dec, _ctx)?),
                    "conditions",
                )?,
                14 => vec_push_or_error(
                    &mut conditions,
                    SuitCondition::Abort(SuitRepPolicy::decode(dec, _ctx)?),
                    "conditions",
                )?,
                24 => vec_push_or_error(
                    &mut conditions,
                    SuitCondition::DeviceIdentifier(SuitRepPolicy::decode(dec, _ctx)?),
                    "conditions",
                )?,

                // Directives
                18 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::Write(SuitRepPolicy::decode(dec, _ctx)?),
                    "directives",
                )?,
                12 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::SetComponentIndex(IndexArg::decode(dec, _ctx)?),
                    "directives",
                )?,
                32 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::RunSequence(BstrSuitCommandSequence::decode(dec, _ctx)?),
                    "directives",
                )?,
                15 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::TryEach(SuitDirectiveTryEachArgument::decode(dec, _ctx)?),
                    "directives",
                )?,
                20 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::OverrideParameters(SuitParameters::decode(dec, _ctx)?),
                    "directives",
                )?,
                21 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::Fetch(SuitRepPolicy::decode(dec, _ctx)?),
                    "directives",
                )?,
                22 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::Copy(SuitRepPolicy::decode(dec, _ctx)?),
                    "directives",
                )?,
                31 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::Swap(SuitRepPolicy::decode(dec, _ctx)?),
                    "directives",
                )?,
                23 => vec_push_or_error(
                    &mut directives,
                    SuitDirective::Invoke(SuitRepPolicy::decode(dec, _ctx)?),
                    "directives",
                )?,

                // Custom commands (negative int keys)
                other if other < 0 => vec_push_or_error(
                    &mut customs,
                    CommandCustomValue::decode(dec, _ctx)?,
                    "customs",
                )?,

                _ => {
                    return Err(DecodeError::unknown_variant(op)
                        .with_message("CommandSequence: unknown op id")
                        .into());
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

    #[allow(dead_code)]
    struct TestHandler;

    impl SuitSharedSequenceHandler for TestHandler {
        fn on_conditions<'a>(
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

        fn on_commands<'a>(
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

    impl SuitCommandHandler for TestHandler {
        fn on_conditions<'a>(
            &mut self,
            conditions: Vec<SuitCondition, SUIT_MAX_ARRAY_LENGTH>,
        ) -> Result<(), SuitError> {
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

        fn on_directives<'a>(
            &mut self,
            directives: Vec<SuitDirective<'a>, SUIT_MAX_ARRAY_LENGTH>,
        ) -> Result<(), SuitError> {
            for dir in directives {
                assert!(matches!(
                    dir,
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
            customs: Vec<CommandCustomValue<'a>, SUIT_MAX_ARRAY_LENGTH>,
        ) -> Result<(), SuitError> {
            for cust in customs {
                assert!(matches!(
                    cust,
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
        let seq = SuitSharedSequence(RawInput(SUIT_SHARED_SEQUENCE.as_ref()));
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
        let seq = SuitCommandSequence(RawInput(SUIT_VALIDATE_COMMAND_SEQUENCE.as_ref()));
        let mut handler = TestHandler;
        seq.decode_and_dispatch(&mut handler).unwrap();
    }
}
