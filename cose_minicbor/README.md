# `cose_minicbor`

[`cose_minicbor`] is a **no_std-friendly Rust crate** for decoding COSE (CBOR Object Signing and Encryption) messages, following [RFC 9052](https://datatracker.ietf.org/doc/html/rfc9052) and [RFC 9053](https://datatracker.ietf.org/doc/html/rfc9053).

This crate targets **constrained and embedded environments**, focusing on minimal allocations, lazy parsing, and borrowed decoding.

Inspired by [cose-rust](https://crates.io/crates/cose-rust), it provides ergonomic abstractions for inspecting and verifying COSE messages using [minicbor](https://crates.io/crates/minicbor).

---

## SUIT MTI Profiles

This crate provides predefined **cryptographic profiles** following the [SUIT MTI draft](https://datatracker.ietf.org/doc/draft-ietf-suit-mti/23/) for IoT device update verification.

Each MTI profile is a **bundle of features** corresponding to the cryptographic algorithms and workflows recommended by SUIT:

| Profile                           | Description                               | Features Enabled                         |
| --------------------------------- | ----------------------------------------- | ---------------------------------------- |
| `suit-sha256-hmac`                | HMAC/SHA-256 only                         | `sha256`, `hmac256`, `decrypt`           |
| `suit-sha256-hmac-a128kw`         | HMAC/SHA-256 + AES-128 Key Wrap           | `sha256`, `hmac256`, `a128kw`            |
| `suit-sha256-hmac-a256kw`         | HMAC/SHA-256 + AES-256 Key Wrap           | `sha256`, `hmac256`, `a256kw`            |
| `suit-sha256-hmac-ecdh_es-a256kw` | HMAC/SHA-256 + ECDH-ES + AES-256 Key Wrap | `sha256`, `hmac256`, `ecdh_es`, `a256kw` |
| `suit-sha256-es256`               | SHA-256 + ES256 signatures                | `sha256`, `es256`                        |
| `suit-sha256-ed25519`             | SHA-256 + Ed25519 signatures              | `sha256`, `ed25519`                      |
| `suit-sha256-hsslms`              | SHA-256 + HSS/LMS signatures              | `sha256`, `hss_lms`                      |

> **Note:** Using these profiles ensures all required features for a given cryptographic workflow are enabled automatically. This avoids subtle bugs where functions such as `decrypt_process` or HMAC verification are unavailable due to missing features.

---

## Features

- **Decode-first** — ergonomic Rust types for COSE messages.
- **no_std-friendly** — works without `std` or `alloc`.
- **Modular cryptography** — only enable the backends you need.

Supported COSE message types (feature-gated):

- [`CoseSign`] / [`CoseSign1`] — signature structures (requires `es256`, `ed25519`, or `hss_lms`)
- [`CoseMac`] / [`CoseMac0`] — MAC / authenticated structures (requires `hmac`)
- [`CoseRecipient`] — key exchange recipient structures (requires `decrypt`)

---

## Example: HMAC Verification (SUIT MTI Profile)

```rust
# #[cfg(feature = "hmac")] {
use cose_minicbor::cose::CoseMac;
use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, KeyOp, KeyType};
use hex_literal::hex;
use minicbor::Decode;

// Build a COSE Key Set containing a KEK for AES-128 KW
let mut builder: CoseKeySetBuilder<200> = CoseKeySetBuilder::try_new().unwrap();
let mut key = CoseKey::new(KeyType::Symmetric);
key.alg(CoseAlg::A128KW);
key.k(&hex!("c1e60d0db5c6cbdac37e8473b412f6b0")).unwrap();
key.kid(b"our-secret");
key.key_op(KeyOp::UnwrapKey);
builder.push_key(key).unwrap();
let key_set_bytes = builder.into_bytes().unwrap();

// Decode a COSE Mac from CBOR
let mac_bytes = include_bytes!("mac_source");
let mac: CoseMac = minicbor::decode(mac_bytes).unwrap();

// Verify the MAC
mac.suit_verify_mac(None, &key_set_bytes).unwrap();
# }
```
