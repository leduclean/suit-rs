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

use minicbor::decode::Error as DecodeError;
/// Decode a SUIT manifest from raw bytes into a handler.
///
/// # Arguments
///
/// * `data` - Raw bytes containing the encoded SUIT manifest
/// * `handler` - Handler that will process the decoded manifest components
///
/// # Returns
///
/// * `Ok(())` on success
/// * `Err(DecodeError)` if decoding fails
///
pub fn suit_decode<'a, H>(data: &'a [u8], handler: &mut H) -> Result<(), DecodeError>
where
    H: suit_manifest::SuitStartHandler<'a>,
{
    suit_decode::decode_and_dispatch(data, handler)
}
