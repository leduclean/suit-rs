# Suit-rs

Rust implementation of the IETF **SUIT** manifest ecosystem — compact, `no_std`-friendly, multi-crate.

**Targets:** `draft-ietf-suit-manifest-34`.

## What this repo contains

- [`cose_minicbor/`](./cose_minicbor): COSE (CBOR) stack, no_std-friendly
- [`suit_cbor/`](./suit_cbor): shared SUIT CBOR types & helpers
- [`suit_validator/`](./suit_validator): SUIT manifest parser & validator (digest + COSE verification)

See each crate README for usage, features and examples.

## License

See [`LICENSE`](./LICENSE).
