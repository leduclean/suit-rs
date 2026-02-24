#![cfg_attr(not(feature = "std"), no_std)]
// We declare as error those lint warnings
// #![deny(variant_size_differences)]
// #![deny(clippy::large_enum_variant)]

//! # SUIT Validator - CBOR Manifest Parser
//!
//! A NO Std Rust implementation of the SUIT (Software Updates for Internet of Things) manifest
//! format as defined in [draft-ietf-suit-manifest](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest).
//!
//! ## Overview
//!
//! This library provides a safe, efficient CBOR decoder for SUIT manifests for IoT firmware
//! updates and trusted invocation scenarios. It implements complete manifest structure
//! parsing with cryptographic signature verification.
//!
//! **Platform Support:**
//! - **`no_std` Compatible**: Designed for embedded systems and constrained devices
//! - `alloc` feature: Optional, for enhanced debugging only
//!
//! ## Core Components
//!
//! - **Manifest Decoder**: Parses CBOR-encoded SUIT structures (see [`suit_decode()`])
//! - **Multiple Handlers**: Process decoded components with custom logic via [`handler`]
//! - **Manifest Types**: SUIT data structures defined in [`suit_manifest`]
//! - **Error Handling**: Comprehensive error types in [`SuitError`]
//!
//! ## Quick Start
//!
//! Process a SUIT manifest with [`GenericStartHandler`](handler::GenericStartHandler) using closures:
//!
//! ```ignore
//! use suit_validator::handler::GenericStartHandler;
//! use cose_minicbor::cose_keys::{CoseKey, CoseKeySetBuilder, KeyType, CoseAlg};
//!
//! // Build trusted keys (CBOR-encoded COSE KeySet)
//! let mut keys_builder: CoseKeySetBuilder<1> = CoseKeySetBuilder::try_new()?;
//! let mut key = CoseKey::new(KeyType::Ec2);
//! key.alg(CoseAlg::ES256P256);
//! key.x(x_bytes)?;
//! key.y(y_bytes)?;
//! keys_builder.push_key(key)?;
//! let keys = keys_builder.into_bytes()?;
//!
//! // Decode and process
//! let data = vec![/* CBOR manifest */];
//! let mut handler = GenericStartHandler {
//!     on_envelope: |env| println!("Sequence: {}", env.manifest.sequence_number),
//!     on_manifest: |_| {},
//! };
//! suit_validator::suit_decode(&data, &mut handler, &keys)?;
//! # Ok::<(), SuitError>(())
//! ```
//!
//! For detailed cryptographic key setup, see the [README](../README.md).
//!
//! ## Custom Handler Implementation
//!
//! Implement [`handler::SuitStartHandler`], [`handler::SuitCommandHandler`] or [`handler::SuitSharedSequenceHandler`] to inspect manifests directly.
//! All iterators contain **[`flat_seq::PairView`]** objects for lazy decoding:
//!
//! ```ignore
//! use suit_validator::handler::SuitCommandHandler;
//! use suit_validator::suit_manifest::SuitCondition;
//! use suit_validator::SuitError;
//! use suit_validator::flat_seq::PairView;
//!
//! struct Inspector;
//!
//! impl SuitCommandHandler for Inspector {
//!     fn on_conditions<'a>(
//!         &mut self,
//!         conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
//!     ) -> Result<(), SuitError> {
//!         for pair in conditions {
//!             // pair.key = command code (no decode cost)
//!             // pair.get() = decode only if needed
//!             if pair.key == 3 {
//!                 if let Ok(cond) = pair.get() {
//!                     println!("Image match condition");
//!                 }
//!             }
//!         }
//!         Ok(())
//!     }
//!     // ... implement other methods
//! }
//! ```
//!
//! **Benefits**: Selective decoding, early filtering, error resilience, performance.
//! This is the **recommended pattern** for manifest processing.
//!
//! ## Security Considerations
//!
//! This library enforces critical security requirements from RFC 9124:
//!
//! - **Signature Verification**: All manifests are cryptographically signed (Section 6.2)
//! - **TOCTOU Protection**: Digest is verified before cryptographic operations (Section 8.3)
//! - **Rollback Protection**: Sequence numbers prevent downgrade attacks
//! - **Compatibility Checking**: Vendor/class IDs must match device
//!
//! See [`SuitError`] for possible error conditions.
//!
//! ## Handler Reference
//!
//! All handlers are trait-based for flexibility, with convenient generic implementations
//! for closure-based processing:
//!
//! | Handler | Purpose | Closure Fields |
//! |---------|---------|-----------------|
//! | [`handler::SuitStartHandler`] | Process top-level envelope or bare manifest | N/A (implement trait) |
//! | [`handler::GenericStartHandler`] | Closure wrapper for start handling | `on_envelope`, `on_manifest` |
//! | [`handler::SuitCommandHandler`] | Process command sequences (fetch, install, etc.) | N/A (implement trait) |
//! | [`handler::GenericCommandHandler`] | Closure wrapper for command sequences | `on_cond`, `on_dir`, `on_custom` |
//! | [`handler::SuitSharedSequenceHandler`] | Process shared sequence metadata | N/A (implement trait) |
//! | [`handler::GenericSharedSequenceHandler`] | Closure wrapper for shared sequences | `on_cond`, `on_com` |
//!
//! Choose:
//! - **Trait implementation** for complex stateful processing with PairView inspection
//! - **Generic handlers** for simple closure-based callbacks
//!
//!
//! ## References
//!
//! - [SUIT Manifest Specification](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest)
//! - [SUIT Requirements (RFC 9124)](https://www.rfc-editor.org/rfc/rfc9124)
//! - [SUIT Architecture (RFC 9019)](https://www.rfc-editor.org/rfc/rfc9019)

#[cfg(feature = "alloc")]
extern crate alloc;
// modules
#[macro_use]
mod suit_debug_log;

mod errors;
mod flat_seq;
mod suit_decode;
mod suit_encode;

pub mod handler;
pub mod suit_manifest;
pub use errors::SuitError;

/// Decodes a SUIT manifest from CBOR bytes and dispatches to a handler.
///
/// This is the primary public API for manifest processing. It handles both authenticated
/// manifests (SUIT_Envelope with COSE signatures) and bare manifests (for testing).
///
/// # Parameters
///
/// * `data` - Raw CBOR-encoded bytes containing either:
///   - SUIT_Envelope (Tag 107): Authenticated manifest with optional severable elements
///   - SUIT_Manifest (Tag 1070): Bare manifest (testing only, no signature verification)
///
/// * `handler` - Struct implementing [`handler::SuitStartHandler`] to process the decoded manifest.
///   The handler is called with either the envelope or manifest depending on the input format.
///
/// * `key_buf` - **COSE KeySet** encoded as CBOR bytes for signature verification.
///   This must be a CBOR-encoded array of COSE_Key objects (built using [`cose_minicbor::cose_keys::CoseKeySetBuilder`] as shown in [Cryptographic Signature Verification](#cryptographic-signature-verification)).
///   - **Required** for authenticated manifests (SUIT_Envelope, Tag 107)
///   - **Ignored** for bare manifests (SUIT_Manifest, Tag 1070)
///   - **Must not** be empty for authenticated manifests or `SuitError::KeysDecodeError` is returned
//
/// # Returns
///
/// * `Ok(())` - Successfully decoded and verified the manifest
/// * `Err(SuitError)` - Decoding, verification, or processing failed (see [`SuitError`] variants)
///
/// # Security Requirements
///
/// For authenticated manifests:
/// 1. CBOR decoding is performed safely with type validation
/// 2. Signature is verified against trusted keys in `key_buf`
/// 3. Digest verification occurs before cryptographic operations (TOCTOU protection)
/// 4. Handler rejects the manifest on any error
///
/// # Handler Implementation
///
/// Implement [`handler::SuitStartHandler`]:
///
/// ```ignore
/// use suit_validator::handler::*;
/// use suit_validator::suit_manifest::*;
/// use suit_validator::SuitError;
///
/// struct MyManifestProcessor;
/// impl SuitStartHandler for MyManifestProcessor {
///     fn on_envelope<'a>(&mut self, envelope: SuitEnvelope<'a>) -> Result<(), SuitError> {
///         // Process authenticated signed manifest
///         Ok(())
///     }
///     fn on_manifest<'a>(&mut self, manifest: SuitManifest<'a>) -> Result<(), SuitError> {
///         // Process bare manifest
///         Ok(())
///     }
/// }
/// ```
///
/// # References
///
/// - [SUIT Spec: Manifest Processor (Section 6)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-6)
/// - [SUIT Spec: CBOR Encoding (Section 8)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8)
/// - [RFC 9124: SUIT Requirements](https://www.rfc-editor.org/rfc/rfc9124)
pub fn suit_decode<H>(data: &[u8], handler: &mut H, key_buf: &[u8]) -> Result<(), SuitError>
where
    H: handler::SuitStartHandler,
{
    suit_decode::decode_and_dispatch(data, handler, key_buf)
}
