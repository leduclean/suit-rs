//! Intern Crate used to expose lazy decoded structures.
#![no_std]

#[macro_use]
mod suit_macros;
mod bstr_struct;
mod cbor_iter;
pub mod errors;

pub use bstr_struct::BstrStruct;
pub use cbor_iter::CborIter;
