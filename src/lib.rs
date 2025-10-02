#![cfg_attr(not(feature = "std"), no_std)]
// We declare as error those lint warnings
#![deny(variant_size_differences)]
#![deny(clippy::large_enum_variant)]

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
