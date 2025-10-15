//! struct to decode "flat" op/arg sequences used by SUIT:
//! - SUIT_Shared_Sequence (flat: [ op, arg, op, arg, ... ])
//! - SUIT_Command_Sequence (flat: [ op, arg, op, arg, ... ])
use crate::{
    errors::SuitError,
    suit_manifest::{
        BstrSuitCommandSequence, BstrSuitSharedSequence, CommandCustomValue, IndexArg,
        SuitCondition, SuitDirective, SuitDirectiveTryEachArgument,
        SuitDirectiveTryEachArgumentShared, SuitParameters, SuitRepPolicy, SuitSharedCommand,
    },
};
use heapless::Vec;
use minicbor::{Decode, Decoder, data::Type, decode::Error as DecodeError};

/// Wrapping structure around the inner CBOR flat array bytes.
#[derive(Debug)]
pub(crate) struct FlatSequence<'a>(pub(crate) &'a [u8]);

impl<'b, C> Decode<'b, C> for FlatSequence<'b> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut C) -> Result<Self, DecodeError> {
        let start = d.position();
        let input = d.input();
        // We advance the main decoder to the next element
        d.skip()?;

        let end = d.position();

        let inner = &input[start..end];
        Ok(FlatSequence(inner))
    }
}

impl<'b> FlatSequence<'b> {
    /// Collect the pairs relative to the [`FlatSequence`] inner bytes.
    pub(crate) fn collect_pairs<const N: usize>(&self) -> Result<Vec<Pair<'b>, N>, SuitError> {
        let mut d = Decoder::new(self.0);
        d.array()
            .map_err(|e| e.with_message("expected top level array in Sequence"))?;
        let mut out: Vec<Pair<'b>, N> = Vec::new();
        loop {
            match read_next_pair(&mut d) {
                Ok(Some(pair)) => {
                    out.push(pair).map_err(|_| SuitError::out_of_space(N))?;
                }
                Ok(None) => break,
                Err(e) => return Err(e),
            }
        }
        Ok(out)
    }
}

/// Read the next flat op/arg sequence and stock it into a `Pair`
fn read_next_pair<'b>(d: &mut Decoder<'b>) -> Result<Option<Pair<'b>>, SuitError> {
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

/// helper to read an op id (accept unsigned or negative int)
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

#[derive(Debug)]
#[cfg_attr(test, derive(PartialEq, Eq))]
pub struct Pair<'b> {
    op: i64,
    bytes: &'b [u8],
}

// We want to be able to decode into a SuitCondition when iterrating using `next()``
impl<'b> TryFrom<&Pair<'b>> for SuitCondition {
    type Error = SuitError;
    fn try_from(pair: &Pair<'b>) -> Result<SuitCondition, Self::Error> {
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

impl<'b> TryFrom<&Pair<'b>> for SuitSharedCommand<'b> {
    type Error = SuitError;
    fn try_from(pair: &Pair<'b>) -> Result<Self, Self::Error> {
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

impl<'b> TryFrom<&Pair<'b>> for SuitDirective<'b> {
    type Error = SuitError;
    fn try_from(pair: &Pair<'b>) -> Result<Self, Self::Error> {
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

impl<'b> TryFrom<&Pair<'b>> for CommandCustomValue<'b> {
    type Error = SuitError;
    fn try_from(pair: &Pair<'b>) -> Result<CommandCustomValue<'b>, Self::Error> {
        let mut d = Decoder::new(pair.bytes);
        Ok(CommandCustomValue::decode(&mut d, &mut ())?)
    }
}

/// A small view returned by *targeted* iterators.
/// Carries the `op` so caller can inspect it before decoding, using [`PairView::op()`].
///
/// It exposes [`PairView::get()`] which returns the concrete target type without
/// requiring a turbofish because the iterator's Item is already specialized with `T`.
#[derive(Debug, Clone, Copy)]
pub struct PairView<'b, T> {
    pair: &'b Pair<'b>,
    _ty: core::marker::PhantomData<&'b T>,
}
impl<'b, T> PairView<'b, T>
where
    T: TryFrom<&'b Pair<'b>, Error = SuitError>,
{
    fn new(pair: &'b Pair<'b>) -> Self {
        Self {
            pair,
            _ty: core::marker::PhantomData,
        }
    }

    ///  *Op* of the current [`PairView`].
    pub fn op(&self) -> i64 {
        self.pair.op
    }

    /// *Inner bytes* of the [`PairView`]
    pub fn bytes(&self) -> &'b [u8] {
        self.pair.bytes
    }
    /// Decodes and returns the concrete value of type `T`.
    ///
    /// Returns an error if the pair cannot be converted into `T`.
    pub fn get(&self) -> Result<T, SuitError> {
        T::try_from(self.pair)
    }
}

pub(crate) fn iter_conditions<'b>(
    pairs: &'b [Pair<'b>],
) -> impl Iterator<Item = PairView<'b, SuitCondition>> {
    pairs
        .iter()
        .filter(|p| matches!(p.op, 1 | 2 | 3 | 5 | 6 | 14 | 24))
        .map(PairView::new)
}

pub(crate) fn iter_directives<'b>(
    pairs: &'b [Pair<'b>],
) -> impl Iterator<Item = PairView<'b, SuitDirective<'b>>> {
    pairs
        .iter()
        .filter(|p| matches!(p.op, 12 | 15 | 18 | 20 | 21 | 22 | 23 | 31 | 32))
        .map(PairView::new)
}

pub(crate) fn iter_shared_commands<'b>(
    pairs: &'b [Pair<'b>],
) -> impl Iterator<Item = PairView<'b, SuitSharedCommand<'b>>> {
    pairs
        .iter()
        .filter(|p| matches!(p.op, 12 | 32 | 15 | 20))
        .map(PairView::new)
}

pub(crate) fn iter_custom<'b>(
    pairs: &'b [Pair<'b>],
) -> impl Iterator<Item = PairView<'b, CommandCustomValue<'b>>> {
    pairs.iter().filter(|p| p.op < 0).map(PairView::new)
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
    fn get_test_flat_seq_decoder(cbor_bytes: &'static [u8]) -> Decoder<'static> {
        let mut d = Decoder::new(cbor_bytes);
        d.array().expect("expect top level array");
        d
    }

    #[test]
    fn decode_advances_main_decoder() {
        let ci = cbor_macro::cbo!(r#"[ [1,2] ]"#);
        let mut main = Decoder::new(&ci);
        let _fsd = main
            .decode::<FlatSequence>()
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
            get_test_flat_seq_decoder(&cbor_macro::cbo!(r#"[1, 2, ["not and int"]]"#));
        // we start decoding the array as FlatSequence would do
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
        let mut d = get_test_flat_seq_decoder(&FLAT_SEQUENCE);
        let firt_pair = read_next_pair(&mut d).unwrap().expect("Missing pair");
        let first_expected_pair = Pair {
            op: 20,
            bytes: &cbor_macro::cbo!(
                r#"{
                    / uri / 21:"http://example.com/file.bin"
                }"#
            ),
        };

        let second_pair = read_next_pair(&mut d).unwrap().expect("Missing pair");
        let second_expected_pair = Pair {
            op: 21,
            bytes: &[2u8],
        };

        let third_pair = read_next_pair(&mut d).unwrap().expect("Missing Pair");
        let third_expected_pair = Pair {
            op: 3,
            bytes: &[15u8],
        };
        assert_eq!(first_expected_pair, firt_pair);
        assert_eq!(second_expected_pair, second_pair);
        assert_eq!(third_expected_pair, third_pair);

        // No more item
        assert!(read_next_pair(&mut d).unwrap().is_none());
    }

    #[test]
    fn test_collect_pairs() {
        let test_flat_seq = FlatSequence(&cbor_macro::cbo!(r#"[1,2,3,4]"#));
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

        let test_flat_seq = FlatSequence(&cbor_macro::cbo!(r#"[1,2,3,4]"#));
        assert!(
            test_flat_seq
                .collect_pairs::<0>()
                .is_err_and(|e| e.is_out_of_space())
        );
    }

    #[test]
    fn test_iterator_conditions_correctly() {
        let ci = cbor_macro::cbo!(r#"[1, 15, 2, 15] "#);
        let pairs = FlatSequence(&ci).collect_pairs::<4>().unwrap();
        let mut cond_iter = iter_conditions(&pairs);
        let first_cond = cond_iter.next().expect("Expected first condition");
        let second_cond = cond_iter.next().expect("Expected second condition");

        assert_eq!(first_cond.op(), 1);
        assert_eq!(second_cond.op(), 2);
        assert!(matches!(
            first_cond
                .get()
                .expect("First condition decoding should be ok"),
            SuitCondition::VendorIdentifier(_)
        ));
        assert!(matches!(
            second_cond
                .get()
                .expect("Second condition decoding should be ok"),
            SuitCondition::ClassIdentifier(_)
        ));

        assert!(cond_iter.next().is_none());
    }

    #[test]
    fn from_pair_unknown_op_errors() {
        let p = Pair {
            op: -10,
            bytes: &[0u8],
        };

        assert!(<SuitCondition>::try_from(&p).is_err_and(|e| e.is_unknown_op()));
        assert!(<SuitSharedCommand>::try_from(&p).is_err_and(|e| e.is_unknown_op()));
        assert!(<SuitDirective>::try_from(&p).is_err_and(|e| e.is_unknown_op()));
        assert!(
            <CommandCustomValue>::try_from(&p)
                .is_ok_and(|res| matches!(res, CommandCustomValue::Integer(_)))
        );
    }
}
