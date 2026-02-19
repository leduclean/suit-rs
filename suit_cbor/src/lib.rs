//! Lightweight `no_std` utilities for lazy CBOR decoding.
//!
//! This crate provides zero-copy wrappers over CBOR arrays and
//! `bstr .cbor` encoded structures, enabling deferred decoding.
//!
//! Designed for constrained environments and SUIT/COSE workflows.
#![no_std]

mod bstr_struct;
mod cbor_iter;
pub mod errors;
mod suit_macros;

pub use bstr_struct::BstrStruct;
pub use cbor_iter::CborIter;
