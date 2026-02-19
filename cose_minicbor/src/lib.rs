//! No std CBOR Object Signing and Encryption, Cose [RFC 9052 ](https://datatracker.ietf.org/doc/html/rfc9052)/ [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053).
//!
//!
//! This crate provides lightweight, `no_std`-friendly methods and structure for **decoding** COSE
//! message types (e.g. [`cose::CoseSign`], [`cose::CoseSign1`], [`cose::CoseMac`], [`cose::CoseMac0`]) using [minicbor](https://crates.io/crates/minicbor).
//!
//! It is inspired by [cose-rust](https://crates.io/crates/cose-rust) but targeted at constrained / embedded environments:
//! the emphasis is on borrowed decoding, minimal allocations and lazy parsing.
//!
//! The implementation targets the COSE/CBOR stack specified by:
//! - [RFC 9052 — COSE](https://datatracker.ietf.org/doc/html/rfc9052)
//! - [RFC 9053 — CBOR Object Signing and Encryption (COSE)](https://datatracker.ietf.org/doc/html/rfc9053)
//!
//! And supports the cryptographic profiles depicted in:
//! - [Cryptographic Algorithms for IoT (SUIT MTI draft)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-mti/23/)
//!
//! ## Scope & goals
//! - **Decode-first**: focus on *decoding* COSE structures and exposing ergonomic Rust types to inspect and verify messages.
//! - **no_std-friendly**: designed to build on targets without `std` or `alloc`.
//!
//! ## Key types
//! - [`cose::CoseSign`], [`cose::CoseSign1`] — COSE signature structures (single / multi-signature).
//! - [`cose::CoseMac`], [`cose::CoseMac0`] — COSE MAC / authenticated structures.
//!
//! ## Cryptographic backends
//! Cryptographic verification is delegated to backend crates (enable via Cargo features).
//! Typical backends (links to crates):
//! - signature verification:
//!   - [`p256`](https://crates.io/crates/p256) — P-256 / ECDSA support.
//!   - [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) — Ed25519 signatures.
//!   - [`hbs-lms`](https://crates.io/crates/hbs-lms) — LMS (Leighton-Micali Signatures.
//! - MAC / digest:
//!   - [`hmac`](https://crates.io/crates/hmac) — HMAC interface.
//!   - [`sha2`](https://crates.io/crates/sha2) — SHA-2 family (SHA-256, SHA-384).
//!
//! Prefer enabling only the backends you need to reduce binary size. Re-exporting a chosen backend
//! from the application crate or gating it behind a Cargo feature is a recommended pattern.
//!
//! ## Security guidance
//! - Always validate inputs and *verify* signatures / MACs before trusting decoded data from untrusted sources.
//! - Keep crypto dependencies up-to-date and enable only audited backends for production.
//! - Document which algorithms/backends are supported and which are intentionally omitted.
//!
//! ## License
//! SPDX: MIT

#![no_std]

pub mod cose;
mod crypto;
pub mod errors;
pub mod keys;
mod multitype;
mod verify;
