# cose_minicbor

`cose_minicbor` is a **no_std-friendly Rust crate** for decoding COSE (CBOR Object Signing and Encryption) messages, following [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) and [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053).

This crate is designed for **constrained and embedded environments**, focusing on minimal allocations, lazy parsing, and borrowed decoding.

Inspired by [cose-rust](https://crates.io/crates/cose-rust), it provides lightweight abstractions for inspecting and verifying COSE messages using [minicbor](https://crates.io/crates/minicbor).

---

## Features

- **Decode-first**: ergonomic Rust types to inspect and verify COSE messages.
- **no_std-friendly**: works on targets without `std` or `alloc`.
- Supports common COSE message types:
  - [`CoseSign`] and [`CoseSign1`] — signature structures (single/multi-signature)
  - [`CoseMac`] and [`CoseMac0`] — MAC / authenticated structures

- Crypto verification can be enabled via Cargo features to minimize binary size.

---

## Cryptographic Backends

This crate **delegates cryptographic operations** to optional backend crates. Typical backends:

- **Signature verification**:
  - [`p256`](https://crates.io/crates/p256) — P-256 / ECDSA
  - [`ed25519-dalek`](https://crates.io/crates/ed25519-dalek) — Ed25519
  - [`hbs-lms`](https://crates.io/crates/hbs-lms) — LMS (Leighton-Micali Signatures)

- **MAC / digest**:
  - [`hmac`](https://crates.io/crates/hmac) — HMAC interface
  - [`sha2`](https://crates.io/crates/sha2) — SHA-2 family (SHA-256, SHA-384)
