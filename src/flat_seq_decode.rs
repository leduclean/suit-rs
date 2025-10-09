//! struct to decode "flat" op/arg sequences used by SUIT:
//! - SUIT_Shared_Sequence (flat: [ op, arg, op, arg, ... ])
//! - SUIT_Command_Sequence (flat: [ op, arg, op, arg, ... ])
//!
use crate::{errors::*, suit_manifest::*};
use heapless::Vec;
use minicbor::{Decode, Decoder, data::Type, decode::Error as DecodeError};

// Wrapping structure around the inner flat array content decoder
#[derive(Debug)]
pub struct FlatSequenceDecoder<'b>(pub Decoder<'b>);

/// We only want the input bytes given to this decoder, doing so, we can treat it when we want with `decode_and_dispatch()`
impl<'b, C> Decode<'b, C> for FlatSequenceDecoder<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        // We clone the main decoder to keep a decoding context
        let mut inner = d.clone();
        // We advance the main decoder to the next element
        d.skip()?;
        // consume the array header in the incoming decoder
        inner.array()?;
        Ok(FlatSequenceDecoder(inner))
    }
}

impl<'b> FlatSequenceDecoder<'b> {
    pub(crate) fn collect_pairs<const N: usize>(&mut self) -> Result<Vec<Pair<'b>, N>, SuitError> {
        let mut out: Vec<Pair<'b>, N> = Vec::new();
        loop {
            match self.read_next_pair() {
                Ok(Some(pair)) => {
                    out.push(pair).map_err(|_| SuitError::out_of_space(N))?;
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
    /// Read the next flat op/arg sequence and stock it into a `Pair`
    fn read_next_pair(&mut self) -> Result<Option<Pair<'b>>, SuitError> {
        let d = &mut self.0;
        match read_op_id(d)? {
            None => Ok(None),
            Some(op) => {
                let start = d.position();
                // we advance to next element
                d.skip()?;
                let end = d.position();
                // we get the bytes input from the next element
                let bytes = &d.input()[start..end];
                Ok(Some(Pair { op, bytes }))
            }
        }
    }
}
// helper to read an op id (accept unsigned or negative int)
fn read_op_id<'b>(d: &mut Decoder<'b>) -> Result<Option<i64>, SuitError> {
    match d.datatype() {
        Ok(ty) => match ty {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
                let u = d.u64()?;
                let i = i64::try_from(u).map_err(|_| DecodeError::message("op id too large"))?;
                Ok(Some(i))
            }
            Type::I8 | Type::I16 | Type::I32 | Type::I64 => {
                let i = d.i64()?;
                Ok(Some(i))
            }
            _ => Err(DecodeError::type_mismatch(ty)
                .with_message("expected integer op  id")
                .into()),
        },
        Err(e) => {
            if e.is_end_of_input() {
                Ok(None)
            } else {
                Err(e.into())
            }
        }
    }
}

// Give a `SuitCondition` Iterable struct
pub(crate) fn iter_conditions<'b>(pairs: &'b [Pair<'b>]) -> FlatSequenceIter<'b, SuitCondition> {
    FlatSequenceIter::new(pairs)
}

// Give a `SuitSharedCommand` Iterable struct
pub(crate) fn iter_shared_command<'b>(
    pairs: &'b [Pair<'b>],
) -> FlatSequenceIter<'b, SuitSharedCommand<'b>> {
    FlatSequenceIter::new(pairs)
}

// Give a `SuitSharedCommand` Iterable struct
pub(crate) fn iter_directives<'b>(
    pairs: &'b [Pair<'b>],
) -> FlatSequenceIter<'b, SuitDirective<'b>> {
    FlatSequenceIter::new(pairs)
}
// Give a `CustomCommand` Iterable struct
pub(crate) fn iter_custom<'b>(
    pairs: &'b [Pair<'b>],
) -> FlatSequenceIter<'b, CommandCustomValue<'b>> {
    FlatSequenceIter::new(pairs)
}

// Wrapper to be able to implement different iterator implementation depending on entry type
#[derive(Debug)]
pub struct FlatSequenceIter<'b, T> {
    inner: &'b [Pair<'b>],
    idx: usize,
    _marker: core::marker::PhantomData<T>,
}

impl<'b, T> FlatSequenceIter<'b, T> {
    pub fn new(slice: &'b [Pair<'b>]) -> Self {
        Self {
            inner: slice,
            idx: 0,
            _marker: core::marker::PhantomData,
        }
    }
}

impl<'b> Iterator for FlatSequenceIter<'b, SuitCondition> {
    type Item = Result<SuitCondition, SuitError>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.inner.len() {
            let p = &self.inner[self.idx];
            self.idx += 1;
            if matches!(p.op, 1 | 2 | 3 | 5 | 6 | 14 | 24) {
                let res: Result<SuitCondition, SuitError> = From::from(p);
                return Some(res);
            }
        }
        None
    }
}

impl<'b> Iterator for FlatSequenceIter<'b, SuitDirective<'b>> {
    type Item = Result<SuitDirective<'b>, SuitError>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.inner.len() {
            let p = &self.inner[self.idx];
            self.idx += 1;
            if matches!(p.op, 12 | 15 | 18 | 20 | 21 | 22 | 23 | 31 | 32) {
                let res: Result<SuitDirective<'b>, SuitError> = From::from(p);
                return Some(res);
            }
        }
        None
    }
}

impl<'b> Iterator for FlatSequenceIter<'b, SuitSharedCommand<'b>> {
    type Item = Result<SuitSharedCommand<'b>, SuitError>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.inner.len() {
            let p = &self.inner[self.idx];
            self.idx += 1;
            if matches!(p.op, 12 | 32 | 15 | 20) {
                let res: Result<SuitSharedCommand<'b>, SuitError> = From::from(p);
                return Some(res);
            }
        }
        None
    }
}

impl<'b> Iterator for FlatSequenceIter<'b, CommandCustomValue<'b>> {
    type Item = Result<CommandCustomValue<'b>, SuitError>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.idx < self.inner.len() {
            let p = &self.inner[self.idx];
            self.idx += 1;
            if p.op < 0 {
                let res: Result<CommandCustomValue<'b>, SuitError> = From::from(p);
                return Some(res);
            }
        }
        None
    }
}

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Pair<'b> {
    op: i64,
    bytes: &'b [u8],
}

// We want to be able to decode into a SuitCondition when iterrating using `next()``
impl<'b> From<&Pair<'b>> for Result<SuitCondition, SuitError> {
    fn from(pair: &Pair<'b>) -> Self {
        let _ctx = &mut ();
        let mut dec = Decoder::new(pair.bytes);
        match pair.op {
            1 => Ok(SuitCondition::VendorIdentifier(SuitRepPolicy::decode(
                &mut dec, _ctx,
            )?)),
            2 => Ok(SuitCondition::ClassIdentifier(SuitRepPolicy::decode(
                &mut dec, _ctx,
            )?)),
            3 => Ok(SuitCondition::ImageMatch(SuitRepPolicy::decode(
                &mut dec, _ctx,
            )?)),
            5 => Ok(SuitCondition::ComponentSlot(SuitRepPolicy::decode(
                &mut dec, _ctx,
            )?)),
            6 => Ok(SuitCondition::CheckContent(SuitRepPolicy::decode(
                &mut dec, _ctx,
            )?)),
            14 => Ok(SuitCondition::Abort(SuitRepPolicy::decode(&mut dec, _ctx)?)),
            24 => Ok(SuitCondition::DeviceIdentifier(SuitRepPolicy::decode(
                &mut dec, _ctx,
            )?)),
            _ => Err(SuitError::unknown_op(pair.op).with_ctx("SuitCondition")),
        }
    }
}

impl<'b> From<&Pair<'b>> for Result<SuitSharedCommand<'b>, SuitError> {
    fn from(pair: &Pair<'b>) -> Self {
        let _ctx = &mut ();
        let mut dec = Decoder::new(pair.bytes);
        match pair.op {
            12 => Ok(SuitSharedCommand::SetComponentIndex(IndexArg::decode(
                &mut dec, _ctx,
            )?)),
            32 => Ok(SuitSharedCommand::RunSequence(
                BstrSuitSharedSequence::decode(&mut dec, _ctx)?,
            )),
            15 => Ok(SuitSharedCommand::TryEach(
                SuitDirectiveTryEachArgumentShared::decode(&mut dec, _ctx)?,
            )),
            20 => Ok(SuitSharedCommand::OverrideParameters(
                SuitParameters::decode(&mut dec, _ctx)?,
            )),
            _ => Err(SuitError::unknown_op(pair.op).with_ctx("SuitSharedCommand")),
        }
    }
}

impl<'b> From<&Pair<'b>> for Result<SuitDirective<'b>, SuitError> {
    fn from(pair: &Pair<'b>) -> Self {
        let _ctx = &mut ();
        let mut dec = Decoder::new(pair.bytes);
        match pair.op {
            18 => Ok(SuitDirective::Write(SuitRepPolicy::decode(&mut dec, _ctx)?)),
            12 => Ok(SuitDirective::SetComponentIndex(IndexArg::decode(
                &mut dec, _ctx,
            )?)),
            32 => Ok(SuitDirective::RunSequence(BstrSuitCommandSequence::decode(
                &mut dec, _ctx,
            )?)),
            15 => Ok(SuitDirective::TryEach(
                SuitDirectiveTryEachArgument::decode(&mut dec, _ctx)?,
            )),
            20 => Ok(SuitDirective::OverrideParameters(SuitParameters::decode(
                &mut dec, _ctx,
            )?)),
            21 => Ok(SuitDirective::Fetch(SuitRepPolicy::decode(&mut dec, _ctx)?)),
            22 => Ok(SuitDirective::Copy(SuitRepPolicy::decode(&mut dec, _ctx)?)),
            31 => Ok(SuitDirective::Swap(SuitRepPolicy::decode(&mut dec, _ctx)?)),
            23 => Ok(SuitDirective::Invoke(SuitRepPolicy::decode(
                &mut dec, _ctx,
            )?)),
            _ => Err(SuitError::unknown_op(pair.op).with_ctx("SuitDirective")),
        }
    }
}

impl<'b> From<&Pair<'b>> for Result<CommandCustomValue<'b>, SuitError> {
    fn from(pair: &Pair<'b>) -> Self {
        let mut d = Decoder::new(pair.bytes);
        Ok(CommandCustomValue::decode(&mut d, &mut ())?)
    }
}

mod tests {
    use super::*;

    #[allow(dead_code)]
    const FLAT_SEQUENCE: cboritem::CborItem<'static> = cbor_macro::cbo!(
        r#"[
                / directive-override-parameters / 20,{
                    / uri / 21:"http://example.com/file.bin"
                },
                / directive-fetch / 21,2,
                / condition-image-match / 3,15
            ]"#
    );

    #[allow(dead_code)]
    fn get_test_flat_seq_decode(cbor_bytes: &'static [u8]) -> FlatSequenceDecoder<'static> {
        let mut d = Decoder::new(cbor_bytes);
        d.decode().expect("Cbor provided is not an array")
    }

    #[test]
    fn flat_sequence_decode() {
        let mut main_d = Decoder::new(&FLAT_SEQUENCE);
        let flat_sequence_decoder = main_d.decode::<FlatSequenceDecoder>().unwrap();
        // We skip the array part in the main decoder and delegue it to sub decoder
        // so after delegation, main should be at end of input
        assert!(
            main_d
                .datatype()
                .expect_err("Should be an error")
                .is_end_of_input()
        );
        assert!(
            flat_sequence_decoder
                .0
                .datatype()
                .expect("Type should be valid")
                != Type::Array
        )
    }

    #[test]
    fn decode_advances_main_decoder() {
        let ci = cbor_macro::cbo!(r#"[ [1,2] ]"#);
        let mut main = Decoder::new(&ci);
        let _fsd = main
            .decode::<FlatSequenceDecoder>()
            .expect("Expected top level array");
        assert!(
            main.datatype()
                .expect_err("Expected an Error")
                .is_end_of_input()
        );
    }

    #[test]
    fn test_read_op() {
        let mut decoder_on_op =
            get_test_flat_seq_decode(&cbor_macro::cbo!(r#"[1, 2, ["not and int"]]"#)).0;
        // we start decoding the array as FlatSequenceDecoder would do
        assert_eq!(
            1,
            read_op_id(&mut decoder_on_op)
                .unwrap()
                .expect("Missing op id")
        );
        assert_eq!(
            2,
            read_op_id(&mut decoder_on_op)
                .unwrap()
                .expect("Missing op id")
        );
        assert!(read_op_id(&mut decoder_on_op).is_err_and(|e| e.is_decode_error()))
    }

    #[test]
    fn test_read_next_two() {
        let mut sequence = get_test_flat_seq_decode(&FLAT_SEQUENCE);
        let firt_pair = sequence.read_next_pair().unwrap().expect("Missing pair");
        let first_expected_pair = Pair {
            op: 20,
            bytes: &cbor_macro::cbo!(
                r#"{
                    / uri / 21:"http://example.com/file.bin"
                }"#
            ),
        };

        let second_pair = sequence.read_next_pair().unwrap().expect("Missing pair");
        let second_expected_pair = Pair {
            op: 21,
            bytes: &[2u8],
        };

        let third_pair = sequence.read_next_pair().unwrap().expect("Missing Pair");
        let third_expected_pair = Pair {
            op: 3,
            bytes: &[15u8],
        };
        assert_eq!(first_expected_pair, firt_pair);
        assert_eq!(second_expected_pair, second_pair);
        assert_eq!(third_expected_pair, third_pair);

        // No more item
        assert!(sequence.read_next_pair().unwrap().is_none());
    }

    #[test]
    fn test_collect_pairs() {
        let mut test_flat_seq = get_test_flat_seq_decode(&cbor_macro::cbo!(r#"[1,2,3,4]"#));
        let collected = test_flat_seq.collect_pairs::<2>().unwrap();

        assert_eq!(
            Pair {
                op: 1,
                bytes: &[2u8]
            },
            collected[0]
        );
        assert_eq!(
            Pair {
                op: 3,
                bytes: &[4u8]
            },
            collected[1]
        );

        let mut test_flat_seq = get_test_flat_seq_decode(&cbor_macro::cbo!(r#"[1,2,3,4]"#));
        assert!(
            test_flat_seq
                .collect_pairs::<0>()
                .is_err_and(|e| e.is_out_of_space())
        );
    }

    #[test]
    fn test_iterator_conditions_correctly() {
        let ci = cbor_macro::cbo!(r#"[1, 15, 2, 15] "#);
        let pairs = get_test_flat_seq_decode(&ci).collect_pairs::<4>().unwrap();
        let mut cond_iter = iter_conditions(&pairs);
        assert!(cond_iter.next().is_some());
        assert!(cond_iter.next().is_some());
        assert!(cond_iter.next().is_none());
    }

    #[test]
    fn from_pair_unknown_op_errors() {
        let p = Pair {
            op: -10,
            bytes: &[0u8],
        };

        assert!(<Result<SuitCondition, SuitError>>::from(&p).is_err_and(|e| e.is_unknown_op()));
        assert!(<Result<SuitSharedCommand, SuitError>>::from(&p).is_err_and(|e| e.is_unknown_op()));
        assert!(<Result<SuitDirective, SuitError>>::from(&p).is_err_and(|e| e.is_unknown_op()));
        assert!(
            <Result<CommandCustomValue, SuitError>>::from(&p)
                .is_ok_and(|res| matches!(res, CommandCustomValue::Integer(_)))
        );
    }
}
