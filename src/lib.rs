#![cfg_attr(not(feature = "std"), no_std)]
// We declare as error those lint warnings
// #![deny(variant_size_differences)]
// #![deny(clippy::large_enum_variant)]

#[cfg(feature = "alloc")]
extern crate alloc;
// modules
#[macro_use]
mod suit_debug_log;

mod bstr_struct;
mod errors;
mod flat_seq;
mod suit_cose;
mod suit_decode;
mod suit_encode;

pub mod handler;
pub mod suit_manifest;

pub use errors::SuitError;
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
/// * `Err(SuitError)` if decoding fails
///
pub fn suit_decode<H>(data: &[u8], handler: &mut H) -> Result<(), SuitError>
where
    H: handler::SuitStartHandler,
{
    suit_decode::decode_and_dispatch(data, handler)
}
