//! No std CBOR Object Signing and Encryption, Cose [RFC 9052 ](https://datatracker.ietf.org/doc/html/rfc9052)/ [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053).
//!
//!
//! This crate provides lightweight, `no_std`-friendly methods and structure for **decoding** COSE
//! message types (e.g. `CoseSign`, `CoseSign1`, `CoseMac`, `CoseMac0`) using [minicbor](https://crates.io/crates/minicbor).
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
//!
//! ## Cryptographic backends
//! Cryptographic verification is delegated to backend crates (enable via Cargo features).
//! Typical backends (links to crates):
//! - signature verification:
//!   - [`p256`](https://crates.io/crates/p256) — P-256 / ECDSA support.
//!   - [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) — Ed25519 signatures.
//!   - [`hss_lms`](https://crates.io/crates/hbs-lms) — LMS (Leighton-Micali Signatures.
//! - MAC / digest:
//!   - [`hmac`](https://crates.io/crates/hmac) — HMAC interface.
//!   - [`sha2`](https://crates.io/crates/sha2) — SHA-2 family (SHA-256, SHA-384).
//!
//! ## Modularity and Feature Profiles
//!
//! This crate is designed to be highly modular: **each cryptographic backend and algorithm
//! is behind its own feature flag**. This allows users to compile only the code they
//! need, minimizing binary size — which is particularly important for `no_std` and embedded targets.
//!
//! ## SUIT MTI Profiles
//!
//! This crate provides predefined **cryptographic profiles** following the [SUIT MTI draft](https://datatracker.ietf.org/doc/draft-ietf-suit-mti/23/) for IoT device update verification.  
//!
//! Each MTI profile is a **bundle of features** corresponding to the cryptographic algorithms and workflows recommended by SUIT:
//!
//! | Profile | Description | Features Enabled |
//! |---------|-------------|----------------|
//! | `suit-sha256-hmac` | HMAC/SHA-256 only | `sha256`, `hmac256`, `decrypt` |
//! | `suit-sha256-hmac-a128kw` | HMAC/SHA-256 + AES-128 Key Wrap | `sha256`, `hmac256`, `a128kw` |
//! | `suit-sha256-hmac-a256kw` | HMAC/SHA-256 + AES-256 Key Wrap | `sha256`, `hmac256`, `a256kw` |
//! | `suit-sha256-hmac-ecdh_es-a256kw` | HMAC/SHA-256 + ECDH-ES + AES-256 Key Wrap | `sha256`, `hmac256`, `ecdh_es`, `a256kw` |
//! | `suit-sha256-es256` | SHA-256 + ES256 signatures | `sha256`, `es256` |
//! | `suit-sha256-ed25519` | SHA-256 + Ed25519 signatures | `sha256`, `ed25519` |
//! | `suit-sha256-hsslms` | SHA-256 + HSS/LMS signatures | `sha256`, `hss_lms` |
//!
//! > **Note:** Using these profiles ensures all required features for a given cryptographic workflow are enabled automatically. This avoids subtle bugs where functions such as `decrypt_process` or HMAC verification are unavailable due to missing features.
//!
//! ---
//!
//! ## Example: HMAC Verification with AES-128 KW
//!
//! This example demonstrates how to verify a `CoseMac` using an A128 Key Wrap KEK
//! following the SUIT HMAC profile.
//!
//! ```rust
//! # #[cfg(all(feature = "hmac", feature = "aeskw256"))] {
//! use cose_minicbor::cose::CoseMac;
//! use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, KeyOp, KeyType};
//! use hex_literal::hex;
//! use minicbor::Decode;
//!
//! // 1. Build a COSE Key Set containing a KEK for AES-128 KW
//! let mut builder: CoseKeySetBuilder<200> = CoseKeySetBuilder::try_new().unwrap();
//!
//! let mut key = CoseKey::new(KeyType::Symmetric);
//! key.alg(CoseAlg::A128KW);
//! key.k(&hex!("c1e60d0db5c6cbdac37e8473b412f6b0")).unwrap();
//! key.kid(b"our-secret");
//! key.key_op(KeyOp::UnwrapKey);
//!
//! builder.push_key(key).unwrap();
//! let key_set_bytes = builder.into_bytes().unwrap();
//!
//! // 2. Decode a COSE Mac from CBOR (example)
//! let mac_bytes = cbor_diag::parse_diag("
//! [
//!     /protected/ h'A10105',
//!     /unprotected/{},
//!     /payload/ h'546869732069732074686520636F6E74656E742E',
//!     /tag/ h'2bdcc89f058216b8a208ddc6d8b54aa91f48bd63484986565105c9ad5a6682f6',
//!     /recipients/ [
//!         [
//!             /protected/ h'',
//!             /unprotected/ {
//!                 /alg/ 1: -3,
//!                 /kid/ 4: h'6F75722D736563726574'
//!             },
//!             /ciphertext/ h'45f19543a4ea912e07fa280d14f7397da96f446a0246d983cd3457e038aec3e21fc286f139d1edd2'
//!         ]
//!     ]
//!
//! ]")
//!     .unwrap()
//!     .to_bytes();
//!
//! let mac: CoseMac = minicbor::decode(&mac_bytes).expect("Invalid CoseMac format");
//!
//! // 3. Verify the MAC using the COSE Key Set
//! mac.suit_verify_mac(None, &key_set_bytes)
//!     .expect("HMAC verification failed");
//! # }
//! ```
//!
//! ## License
//! SPDX: MIT

#![no_std]

mod common;
mod multitype;
mod verif_keys;

pub mod cose_keys;
pub mod errors;

#[cfg(feature = "hmac")]
mod hmac;

#[cfg(feature = "decrypt")]
mod crypto;

mod cose_recipient;

#[cfg(any(feature = "es256", feature = "ed25519", feature = "hss_lms"))]
mod sign;

pub mod cose {
    #[cfg(feature = "hmac")]
    pub use crate::hmac::cose_struct::{CoseMac, CoseMac0};

    #[cfg(any(feature = "es256", feature = "ed25519", feature = "hss_lms"))]
    pub use crate::sign::cose_struct::{CoseSign, CoseSign1};

    pub use crate::cose_recipient::CoseRecipient;
}

pub use errors::CoseError;
