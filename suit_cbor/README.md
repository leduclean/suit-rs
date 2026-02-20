# suit_cbor

Lightweight `no_std` utilities for lazy CBOR decoding.

This crate provides:

- `CborIter` for lazy array decoding
- `BstrStruct` for `bstr .cbor` wrappers
- ergonomic wrapper macros

Designed for SUIT / COSE workflows and constrained environments.

> This is an early release (0.1.0). Some edge cases (e.g., indefinite-length arrays) may not yet be fully tested.
