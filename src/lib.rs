#![cfg_attr(not(feature = "std"), no_std)]
// We declare as error those lint warnings
// #![deny(variant_size_differences)]
// #![deny(clippy::large_enum_variant)]

#[cfg(feature = "alloc")]
extern crate alloc;
// modules
#[macro_use]
mod suit_debug_log;

mod flat_ops;
mod lazycbor;
mod suit_cose;
mod suit_decode;
mod suit_encode;
pub mod suit_manifest;

use minicbor::{Decode, Decoder, decode::Error as DecodeError};
use suit_manifest::SuitStart;
/// Decode a SUIT manifest from a byte slice.
///
/// This function takes a byte slice containing the raw SUIT manifest data
/// and attempts to decode it into a `SuitStart` structure using `minicbor`.
///
/// # Arguments
///
/// * `data` - A byte slice (`&[u8]`) containing the encoded SUIT manifest.
///
/// # Returns
///
/// * `Ok(SuitStart)` if decoding is successful.
/// * `Err(DecodeError)` if the data could not be decoded.
///
pub fn suit_decode(data: &[u8]) -> Result<SuitStart<'_>, DecodeError> {
    let mut d = Decoder::new(data);
    SuitStart::decode(&mut d, &mut ())
}
