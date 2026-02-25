# SUIT Validator

A Rust implementation of the [SUIT (Software Updates for Internet of Things)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest) manifest parser with cryptographic signature verification.

This implementation targets **draft-ietf-suit-manifest-34** of the SUIT manifest specification.

## Features

- **`no_std` Compatible**: Designed for embedded systems and IoT devices
- **Safe CBOR Decoding**: Type-safe manifest parsing with zero unsafe code
- **Signature Verification**: COSE signatures validated against trusted keys
- **Custom Handlers**: Flexible trait-based handler system for manifest processing
- **Advanced Inspections**: Direct access to CBOR pairs via `PairView` for manual validation

## Quick Start

```rust
use suit_validator::handler::GenericStartHandler;
use suit_validator::SuitError;
use cose_minicbor::cose_keys::{CoseKey, CoseKeySetBuilder, KeyType, CoseAlg};

// Build trusted keys
let mut keys = CoseKeySetBuilder::<1>::try_new()?;
let mut key = CoseKey::new(KeyType::Ec2);
key.alg(CoseAlg::ES256P256);
key.x(x_bytes)?;
key.y(y_bytes)?;
keys.push_key(key)?;
let keys_bytes = keys.into_bytes()?;

// Decode manifest
let data: &[u8] = /* CBOR encoded SUIT manifest */;
let mut handler = GenericStartHandler {
    on_envelope: |env| {
        println!("Sequence: {}", env.manifest.sequence_number);
    },
    on_manifest: |_| {},
};

suit_validator::suit_decode(&data, &mut handler, &keys_bytes)?;
```

## Backend Cryptography

By default, `suit_validator` uses the [`cose_minicbor`] crate as its cryptographic backend.  
The default enabled features include:

- `hmac` — HMAC-based signatures
- `decrypt` — COSE decryption support
- `es256` — ECDSA P-256 signatures (ES256)
- `sha256` — SHA-256 digest computation

You can create a `CoseCrypto` instance with:

```rust
use suit_validator::crypto::CoseCrypto;

let keys_bytes = vec![0u8; 32]; // CBOR CoseKeySet for testing
let crypto = CoseCrypto::new(&keys_bytes);

```

## Manifest Structure

```
SUIT_Envelope (Tag 107)
├── SUIT_Authentication
│ ├── COSE_Sign1 (signature)
│ └── SuitDigest (SHA-256)
├── SUIT_Manifest (Tag 1070)
│ ├── version
│ ├── sequence-number
│ ├── common
│ │ └── shared-sequence
│ ├── invoke
│ ├── install
│ ├── fetch
│ ├── validate
│ └── load
└── severable-package-members

```

## Implementation

For custom manifest processing, implement [`handler::SuitStartHandler`](src/handler.rs):

```rust
struct MyHandler;

impl SuitStartHandler for MyHandler {
    fn on_envelope<'a>(&mut self, env: SuitEnvelope<'a>) -> Result<(), SuitError> {
        // Process authenticated manifest
        Ok(())
    }

    fn on_manifest<'a>(&mut self, manifest: SuitManifest<'a>) -> Result<(), SuitError> {
        // Process bare manifest
        Ok(())
    }
}

suit_validator::suit_decode(&data, &mut MyHandler, &keys)?;
```

For advanced CBOR pair inspection within handlers, use `PairView` to iterate and selectively decode manifest elements.

## References

- [SUIT Manifest Specification](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest)
- [CBOR RFC 8949](https://tools.ietf.org/html/rfc8949)
- [COSE Signatures RFC 8152](https://tools.ietf.org/html/rfc8152)

## License

See LICENSE file.
