//! Helpers to decode "flat" op/arg sequences used by SUIT:
//! - SUIT_Shared_Sequence (flat: [ op, arg, op, arg, ... ])
//! - SUIT_Command_Sequence (flat: [ op, arg, op, arg, ... ])
//!
#[cfg(any(feature = "std", feature = "defmt"))]
use crate::suit_decode::type_to_str;

use minicbor::{Decoder, data::Type, decode::Error as DecodeError};

pub fn decode_flat_pairs<'b, F>(d: &mut Decoder<'b>, mut f: F) -> Result<(), DecodeError>
where
    F: FnMut(i64, &mut Decoder<'b>) -> Result<(), DecodeError>,
{
    // require top-level array
    let ty = d.datatype()?;
    match ty {
        Type::Array => {}
        _ => {
            #[cfg(any(feature = "defmt", feature = "std"))]
            error!(
                "expected top-level array for flat op/arg sequencebut got {:?}",
                type_to_str(ty)
            );
            return Err(DecodeError::message(
                "expected top-level array for flat op/arg sequence",
            ));
        }
    }
    let arr_len = d.array()?; // consume array header

    if let Some(mut remaining) = arr_len {
        // definite-length array: must be an even number
        if remaining % 2 != 0 {
            #[cfg(any(feature = "defmt", feature = "std"))]
            error!("flat op/arg array length must be even");
            return Err(DecodeError::message(
                "flat op/arg array length must be even",
            ));
        }

        while remaining > 0 {
            let op = read_op_id(d)?;
            // handler consumes the argument item (next top-level item)
            f(op, d)?;
            remaining = remaining
                .checked_sub(2)
                .ok_or_else(|| DecodeError::message("array length underflow"))?;
        }
    } else {
        // indefinite-length: loop until break
        loop {
            if let Type::Break = d.datatype()? {
                // consume Break token and stop
                d.skip()?;
                break;
            }
            let op = read_op_id(d)?;
            f(op, d)?;
        }
    }

    Ok(())
}

// helper to read an op id (accept unsigned or negative int)
fn read_op_id<'b>(d: &mut Decoder<'b>) -> Result<i64, DecodeError> {
    let ty = d.datatype()?;
    match ty {
        Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
            let u = d.u64()?;
            let i = i64::try_from(u).map_err(|_| DecodeError::message("op id too large"))?;
            Ok(i)
        }
        Type::I8 | Type::I16 | Type::I32 | Type::I64 => {
            let i = d.i64()?;
            Ok(i)
        }
        _ => {
            #[cfg(any(feature = "defmt", feature = "std"))]
            error!("expected integer op id but got {:?}", type_to_str(ty));
            Err(DecodeError::message("expected integer op id"))
        }
    }
}
