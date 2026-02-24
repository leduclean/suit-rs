//! CBOR Decoding for SUIT (Software Updates for Internet of Things) Manifests.
//!
//! This module provides functionality to decode SUIT manifest structures from CBOR-encoded
//! binary data according to the [SUIT Manifest Specification](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest).
//!
//! # Overview
//!
//! SUIT manifests are CBOR-encoded metadata bundles describing firmware updates and trusted invocation
//! processes. The manifest processor requires strict adherence to the specification for security.
//!
//! This module implements decoders for:
//! - **Command Sequences**: Lists of conditions and directives that define update/invocation procedures
//! - **Shared Sequences**: Common metadata and commands executed before other sequences
//! - **SUIT Digests**: Cryptographic integrity checks for manifest elements
//! - **Custom Commands**: Extensible application-specific commands
//!
//! # SUIT Manifest Processing Workflow
//!
//! According to Section 6 of the SUIT specification, the manifest processor follows these steps:
//!
//! 1. **Signature Verification**: Validate authentication (Section 8.3)
//! 2. **Applicability Check**: Verify vendor/class identifiers match device (Section 8.4.9.1)
//! 3. **Payload Fetch**: Obtain resources (Section 8.4.6)
//! 4. **Installation**: Apply updates (Section 8.4.6)
//! 5. **Validation**: Verify successful installation (Section 8.4.6)
//!
//! # Supported CBOR Types
//!
//! - **Bytes (bstr)**: For digest-over-CBOR and wrapped command sequences
//! - **Arrays**: For command sequences and try-each lists
//! - **Maps**: For command directives and parameters
//! - **Integers**: For command codes and numeric parameters
//! - **Strings**: For text metadata and URIs
//! - **CBOR Tags**: Tag 107 (Envelope), Tag 112 (CBOR-PEN UUID)
//!
//! # Error Handling
//!
//! Decoding errors are reported as [`SuitError`] types, which may indicate:
//! - CBOR type mismatches
//! - Invalid command sequences
//! - Malformed UUID formats
//! - Unsupported command types
//!
//! See [`SuitError`] for detailed error variants.
//!
//! # References
//!
//! - [SUIT Manifest Specification - Command Sequences (Section 8.4.6)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.4.6)
//! - [SUIT Manifest Specification - Digest Container (Section 10)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-10)

use crate::errors::SuitError;
use crate::flat_seq::*;
use crate::handler::*;
use crate::suit_manifest::*;
use core::str;
use minicbor::{Decode, Decoder, data::Type, decode::Error as DecodeError};

const SUIT_MAX_FLAT_PAIR: usize = 20;

#[cfg(all(feature = "alloc", feature = "defmt"))]
use minicbor::display;

#[cfg(all(feature = "alloc", feature = "defmt"))]
impl<'a, T, Ctx> Decode<'a, Ctx> for Debug<T>
where
    T: Decode<'a, ()>,
{
    fn decode(d: &mut Decoder<'a>, _: &mut Ctx) -> Result<Self, DecodeError> {
        info!("Decoding struct: {}", core::any::type_name::<Self>());
        info!("Decoding with debug...");
        let bytes = d.input();
        info!("Shared sequence raw: {}", display(bytes));
        let inner = T::decode(d, &mut ())?;
        Ok(Debug(inner))
    }
}

impl<'a, Ctx, T> Decode<'a, Ctx> for DigestOrCbor<'a, T>
where
    T: Decode<'a, Ctx>,
{
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let ty = d.datatype()?;
        match ty {
            // bstr.cbor case (or generic bytes wrapper for the CBOR value)
            // Call T::decode on the current decoder: if T is BstrStruct<'a, >,
            // it will call d.bytes() and then decode the inner CBOR.
            Type::Bytes => {
                let t = T::decode(d, _ctx)?;
                Ok(DigestOrCbor::Cbor(t))
            }

            // Digest is encoded as a CBOR array [algorithm_id, bytes]
            // so we expect an Array here and decode SuitDigest
            Type::Array => {
                let digest = SuitDigest::decode(d, _ctx)?;
                Ok(DigestOrCbor::Digest(digest))
            }
            _ => Err(minicbor::decode::Error::type_mismatch(ty)
                .with_message("DigestOrCbor: expected Bytes (CBOR bstr.cbor) or Array (digest)")),
        }
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for IndexArg<'a> {
    fn decode(d: &mut minicbor::Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let ty = d.datatype()?;
        match ty {
            Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
                let v = d.u64()?;
                Ok(IndexArg::Single(v))
            }

            Type::Bool => {
                let b = d.bool()?;
                Ok(IndexArg::True(b))
            }

            Type::Array => Ok(IndexArg::Multiple(IterableU64::decode(d, _ctx)?)),

            _ => Err(minicbor::decode::Error::type_mismatch(ty)
                .with_message("IndexArg: expected Number | Bool | Array")),
        }
    }
}

impl<'a, Ctx> minicbor::Decode<'a, Ctx> for CommandCustomValue<'a> {
    fn decode(d: &mut minicbor::Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let ty = d.datatype()?;
        match ty {
            Type::Bytes => Ok(CommandCustomValue::Bytes(d.bytes()?)),

            Type::String => Ok(CommandCustomValue::Text(d.str()?)),

            Type::U8 | Type::U16 | Type::U32 | Type::U64 => {
                let v = d.u64()? as i64;
                Ok(CommandCustomValue::Integer(v))
            }

            Type::I8 | Type::I16 | Type::I32 | Type::I64 => {
                let v = d.i64()?;
                Ok(CommandCustomValue::Integer(v))
            }

            Type::Null => {
                d.null()?;
                Ok(CommandCustomValue::Nil)
            }

            _ => Err(minicbor::decode::Error::type_mismatch(ty)
                .with_message("CommandCustomValue: expected Bytes | String | number | Null")),
        }
    }
}

/// Decodes and validates a UUID or CBOR-PEN (Private Enterprise Number) identifier.
///
/// # Description
///
/// This helper function decodes vendor and class identifiers which may be encoded as either:
/// - **RFC 4122 UUID**: A 16-byte binary string (Section 8.4.8.3 of SUIT spec)
/// - **CBOR-PEN Tag**: CBOR Tag 112 wrapping a byte string (Section 8.4.8.1 of SUIT spec)
///
/// Both encodings must not exceed 16 bytes in length. The CBOR-PEN encoding allows for
/// hierarchical Private Enterprise Number (PEN) based identifiers using the IANA PEN namespace.
///
/// # Parameters
///
/// * `d` - CBOR decoder at the current position
/// * `_ctx` - Decoder context (unused)
///
/// # Returns
///
/// * `Ok(Some(&[u8]))` - Successfully decoded identifier bytes (max 16 bytes)
/// * `Ok(None)` - Decoder was positioned at a null/nil value
/// * `Err(DecodeError)` - If:
///   - The UUID exceeds 16 bytes
///   - The CBOR tag is not 112
///   - The data type is neither bytes nor a tag
///
/// # References
///
/// - [SUIT Spec: Vendor Identifier (Section 8.4.8.3)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.4.8.3)
/// - [SUIT Spec: CBOR PEN UUID (Section 8.4.8.1)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.4.8.1)
/// - [RFC 4122: UUID Format](https://www.rfc-editor.org/rfc/rfc4122)
pub(crate) fn decode_uuid_or_cborpen<'a, Ctx>(
    // TODO: refactor by using [cbor(tag=112)] in new VendorIdentifier type
    d: &mut Decoder<'a>,
    _ctx: &mut Ctx,
) -> Result<Option<&'a [u8]>, DecodeError> {
    let ty = d.datatype()?;
    match ty {
        Type::Tag => {
            let t = d.tag()?;
            if t.as_u64() == 112 {
                let b = d.bytes()?;
                if b.len() > 16 {
                    Err(minicbor::decode::Error::message(
                        "UUID is too long (more than 16 bytes)",
                    ))
                } else {
                    Ok(Some(b))
                }
            } else {
                Err(minicbor::decode::Error::type_mismatch(ty)
                    .with_message("UUID/CborPen: unexpected tag"))
            }
        }
        Type::Bytes => {
            let b = d.bytes()?;
            Ok(Some(b))
        }
        _ => Err(minicbor::decode::Error::type_mismatch(ty)
            .with_message("UUID/CborPen: expected UUID or cbor-pen")),
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for SuitReportingBits {
    fn decode(d: &mut Decoder<'a>, _: &mut Ctx) -> Result<Self, DecodeError> {
        let bits = d.u8()?;
        Ok(SuitReportingBits::from_bits_truncate(bits))
    }
}

// Only accept valid  tags (if working with owned tag should be at least more than 43 caract)
impl<'a, C> Decode<'a, C> for Tag38LTag<'a> {
    fn decode(d: &mut Decoder<'a>, _: &mut C) -> Result<Self, DecodeError> {
        let tag = d.str()?;
        if is_valid_tag38ltag(tag) {
            Ok(Tag38LTag(tag))
        } else {
            Err(DecodeError::message("Invalid Tag38LTag format"))
        }
    }
}
/// Validates RFC 5646 language tag format used in SUIT text sections.
/// (Regex not possible in no_std)
pub(crate) fn is_valid_tag38ltag(s: &str) -> bool {
    let mut chars = s.chars().peekable();
    // First segment: only alphabetic, 1 to 8 chars
    let mut count = 0;
    while let Some(&c) = chars.peek() {
        if c.is_ascii_alphabetic() {
            chars.next();
            count += 1;
            if count > 8 {
                return false;
            }
        } else {
            break;
        }
    }
    if count == 0 {
        return false;
    }
    // Remaining segments: "-" followed by 1–8 alphanumeric chars
    while let Some(&c) = chars.peek() {
        if c != '-' {
            return false;
        }
        chars.next(); // consume '-'
        count = 0;
        while let Some(&c) = chars.peek() {
            if c.is_ascii_alphanumeric() {
                chars.next();
                count += 1;
                if count > 8 {
                    return false;
                }
            } else {
                break;
            }
        }
        if count == 0 {
            return false;
        }
    }
    true
}

impl<'a> SuitSharedSequence<'a> {
    /// Decodes the shared sequence and dispatches components to a handler.
    ///
    /// # Description
    ///
    /// The shared sequence is a command sequence executed prior to each other command sequence
    /// in the manifest. According to Section 8.4.5 of the SUIT specification, it contains:
    ///
    /// - **Conditions**: Tests for device compatibility (vendor ID, class ID, etc.)
    /// - **Shared Commands**: Common operations like `set-component-index`, `override-parameters`,
    ///   etc., which are reused across multiple sequences to reduce manifest size
    ///
    /// This method parses the flat sequence structure and invokes the handler's callbacks for
    /// conditions and commands separately, allowing custom processing of each type.
    ///
    /// # Parameters
    ///
    /// * `self` - The decoded shared sequence
    /// * `handler` - Implementation of [`SuitSharedSequenceHandler`] to process conditions and commands
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully processed all conditions and commands
    /// * `Err(SuitError)` - If:
    ///   - The sequence exceeds `SUIT_MAX_FLAT_PAIR` (20) pairs
    ///   - An unknown command or condition is encountered
    ///   - The handler rejects processing
    ///
    /// # Handler Callbacks
    ///
    /// The handler is invoked with:
    /// - `on_conditions()`: Iterator over [`SuitCondition`] items with their indices
    /// - `on_commands()`: Iterator over [`SuitSharedCommand`] items with their indices
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use suit_validator::handler::*;
    /// # use suit_validator::suit_manifest::SuitSharedSequence;
    /// struct MyHandler;
    /// impl SuitSharedSequenceHandler for MyHandler {
    ///     fn on_conditions<'a>(
    ///         &mut self,
    ///         conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
    ///     ) -> Result<(), suit_validator::SuitError> {
    ///         for cond in conditions {
    ///             println!("Condition code: {:?}", cond.key);
    ///         }
    ///         Ok(())
    ///     }
    ///     fn on_commands<'a>(
    ///         &mut self,
    ///         commands: impl Iterator<Item = PairView<'a, SuitSharedCommand<'a>>>,
    ///     ) -> Result<(), suit_validator::SuitError> {
    ///         Ok(())
    ///     }
    /// }
    /// ```
    ///
    /// # References
    ///
    /// - [SUIT Spec: suit-shared-sequence (Section 8.4.5)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.4.5)
    /// - [SUIT Spec: Common Metadata (Section 5.3.2)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-5.3.2)
    pub fn decode_and_dispatch<H>(&self, handler: &mut H) -> Result<(), SuitError>
    where
        H: SuitSharedSequenceHandler,
    {
        let pairs = self.0.collect_pairs::<SUIT_MAX_FLAT_PAIR>()?;
        let cond_iter = iter_conditions(&pairs);
        let command_iter = iter_shared_commands(&pairs);
        handler.on_conditions(cond_iter)?;
        handler.on_commands(command_iter)?;
        Ok(())
    }
}

impl<'a> SuitCommandSequence<'a> {
    /// Decodes a command sequence and dispatches its components to a handler.
    ///
    /// # Description
    ///
    /// A command sequence is a list of conditions and directives that form a procedure.
    /// The SUIT specification (Section 8.4.6) defines several command sequences with specific purposes:
    ///
    /// | Sequence | Purpose | Reference |
    /// |----------|---------|-----------|
    /// | suit-payload-fetch | Obtain resources | Section 8.4.6 |
    /// | suit-install | Install/stage payloads | Section 8.4.6 |
    /// | suit-validate | Verify installation success | Section 8.4.6 |
    /// | suit-load | Prepare for execution | Section 8.4.6 |
    /// | suit-invoke | Transfer execution control | Section 8.4.6 |
    ///
    /// This method parses the flat sequence structure and invokes handler callbacks for:
    /// - **Conditions**: Prerequisite checks that must pass (Section 8.4.9)
    /// - **Directives**: Actions to execute (Section 8.4.10)
    /// - **Custom Commands**: Application-defined extensions (Section 8.4.11)
    ///
    /// # Parameters
    ///
    /// * `self` - The decoded command sequence
    /// * `handler` - Implementation of [`SuitCommandHandler`] to process sequence components
    ///
    /// # Returns
    ///
    /// * `Ok(())` - Successfully processed all components
    /// * `Err(SuitError)` - If:
    ///   - The sequence exceeds `SUIT_MAX_FLAT_PAIR` (20) pairs
    ///   - An unknown condition, directive, or command is encountered
    ///   - The handler rejects processing
    ///
    /// # Handler Callbacks
    ///
    /// The handler is invoked (in order) with:
    /// - `on_conditions()`: Iterator over [`SuitCondition`] items with their reporting policies
    /// - `on_directives()`: Iterator over [`SuitDirective`] items with their arguments
    /// - `on_customs()`: Iterator over [`CommandCustomValue`] custom command arguments
    ///
    /// # Execution Order
    ///
    /// For each update procedure, command sequences are executed in the following order:
    /// 1. Common command sequence (shared preparation)
    /// 2. Payload Fetch (if specified)
    /// 3. Install (if specified)
    /// 4. Validate (always executed)
    /// 5. Load (if invocation is needed)
    /// 6. Invoke (if invocation is needed)
    ///
    /// # Code Example
    ///
    /// ```no_run
    /// # use suit_validator::handler::*;
    /// # use suit_validator::suit_manifest::SuitCommandSequence;
    /// struct ValidateHandler;
    /// impl SuitCommandHandler for ValidateHandler {
    ///     fn on_conditions<'a>(
    ///         &mut self,
    ///         conds: impl Iterator<Item = PairView<'a, SuitCondition>>,
    ///     ) -> Result<(), suit_validator::SuitError> {
    ///         for cond in conds {
    ///             println!("Condition: {:?}", cond.get()?);
    ///         }
    ///         Ok(())
    ///     }
    ///     fn on_directives<'a>(
    ///         &mut self,
    ///         dirs: impl Iterator<Item = PairView<'a, SuitDirective<'a>>>,
    ///     ) -> Result<(), suit_validator::SuitError> {
    ///         Ok(())
    ///     }
    ///     fn on_customs<'a>(
    ///         &mut self,
    ///         _custom: impl Iterator<Item = PairView<'a, CommandCustomValue<'a>>>,
    ///     ) -> Result<(), suit_validator::SuitError> {
    ///         Ok(())
    ///     }
    /// }
    /// ```
    ///
    /// # References
    ///
    /// - [SUIT Spec: Command Sequences (Section 8.4.6)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.4.6)
    /// - [SUIT Spec: Conditions (Section 8.4.9)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.4.9)
    /// - [SUIT Spec: Directives (Section 8.4.10)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.4.10)
    /// - [SUIT Spec: Abstract Machine (Section 6.4)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-6.4)
    pub fn decode_and_dispatch<H>(&self, handler: &mut H) -> Result<(), SuitError>
    where
        H: SuitCommandHandler,
    {
        let pairs = self.0.collect_pairs::<SUIT_MAX_FLAT_PAIR>()?;
        let cond_iter = iter_conditions(&pairs);
        let direct_iter = iter_directives(&pairs);
        let custom_iter = iter_custom(&pairs);
        handler.on_conditions(cond_iter)?;
        handler.on_directives(direct_iter)?;
        handler.on_customs(custom_iter)?;
        Ok(())
    }
}

/// Decodes a SUIT manifest or envelope and dispatches to the appropriate handler.
///
/// # Description
///
/// This is the main entry point for decoding SUIT structures. It handles both:
///
/// - **SUIT_Envelope** (Tag 107): Complete manifest with authentication wrapper and severable elements
/// - **SUIT_Manifest** (Tag 1070): Bare manifest without authentication
///
/// The function implements Section 6 security requirements from the SUIT specification:
/// 1. Verifies the signature of the manifest
/// 2. Verifies the digest prior to cryptographic computation (prevents TOCTOU attacks)
/// 3. Dispatches to handler for further processing
///
/// # Parameters
///
/// * `buf` - Raw CBOR-encoded bytes containing a SUIT structure
/// * `handler` - Implementation of [`SuitStartHandler`] to process the decoded structure
/// * `keys` - Buffer containing trusted keys for signature verification
///
/// # Returns
///
/// * `Ok(())` - Successfully decoded and verified the structure
/// * `Err(SuitError)` - If:
///   - The CBOR tag is neither 107 (Envelope) nor 1070 (Manifest)
///   - Digest verification fails (corrupted or tampered manifest)
///   - COSE signature verification fails (unauthenticated or invalid signature)
///   - The handler rejects processing
///
/// # Tag Handling
///
/// | Tag | Type | Usage |
/// |-----|------|-------|
/// | 107 | SUIT_Envelope | Complete manifest with authentication and optional severable elements |
/// | 1070 | SUIT_Manifest | Bare manifest without authentication; used for testing/dev only |
///
/// # Security Considerations
///
/// This function implements critical security checks as required by RFC 9124:
///
/// - **Signature Verification**: Validates COSE authentication using provided keys
/// - **Digest Verification** (TOCTOU Protection): Verifies manifest digest before cryptographic operations
/// - **Strict Ordering**: Digest check always precedes COSE verification
///
/// All these checks are **required** before processing any other part of the manifest.
///
/// # Parameters vs Envelope Elements
///
/// - `keys`: External key material for COSE signature verification
/// - `wrapper.authentication`: COSE signature block within the envelope containing wrapped digest
/// - `envelope.manifest`: The actual manifest subject to signature verification
///
/// # Authentication Block Structure (Section 8.3)
///
/// The authentication wrapper contains:
/// ```text
/// SUIT_Authentication = [
///     bstr .cbor SUIT_Digest,           // Digest of manifest bytes
///     * bstr .cbor SUIT_Authentication_Block  // COSE_Sign, COSE_Mac, etc.
/// ]
/// ```
///
/// # Example
///
/// ```no_run
/// # use suit_validator::handler::SuitStartHandler;
/// # use suit_validator::SuitError;
/// struct MyHandler;
/// impl SuitStartHandler for MyHandler {
///     fn on_envelope<'a>(&mut self, _envelope: suit_validator::suit_manifest::SuitEnvelope<'a>)
///         -> Result<(), SuitError>
///     {
///         println!("Received envelope");
///         Ok(())
///     }
///     fn on_manifest<'a>(&mut self, _manifest: suit_validator::suit_manifest::SuitManifest<'a>)
///         -> Result<(), SuitError>
///     {
///         println!("Received manifest");
///         Ok(())
///     }
/// }
/// let manifest_bytes = vec![/* CBOR data */];
/// let keys = vec![/* key material */];
/// let mut handler = MyHandler;
/// suit_validator::suit_decode(&manifest_bytes, &mut handler, &keys)?;
/// # Ok::<(), SuitError>(())
/// ```
///
/// # References
///
/// - [SUIT Spec: Envelope (Section 8.2)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.2)
/// - [SUIT Spec: Authentication (Section 8.3)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.3)
/// - [SUIT Spec: Digest Verification (Section 8.3, TOCTOU)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-8.3)
/// - [SUIT Spec: Manifest Setup (Section 6.1)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-6.1)
/// - [SUIT Spec: Required Checks (Section 6.2)](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#section-6.2)
/// - [RFC 9124: SUIT Requirements](https://www.rfc-editor.org/rfc/rfc9124)
pub(crate) fn decode_and_dispatch<H>(
    buf: &[u8],
    handler: &mut H,
    keys: &[u8],
) -> Result<(), SuitError>
where
    H: SuitStartHandler,
{
    let mut d = Decoder::new(buf);
    let tag = d.tag()?;
    let ctx = &mut ();
    match tag.as_u64() {
        107 => {
            let envelope: SuitEnvelope<'_> = d.decode_with(ctx)?;
            let authentication = envelope.wrapper.get()?;

            // 8.3 ietf suit manifest
            // MUST verify the SUIT_Digest prior to performing the cryptographic computation to avoid "Time-of-check to time-of-use"
            // The SUIT_DIGEST is computed over the bstr-wrapped SUIT_Manifest bytes
            authentication.suit_verify_digest(envelope.manifest.raw_bytes())?;

            authentication.suit_verify_cose(keys)?;
            handler.on_envelope(envelope)
        }
        1070 => {
            let manifest = d.decode_with(ctx)?;
            handler.on_manifest(manifest)
        }
        _ => Err(DecodeError::tag_mismatch(tag)
            .with_message("SuitStart: unexpected tag (expected 107:envelope or 1070:manifest)")
            .into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[allow(unused_imports)]
    use crate::flat_seq::*;

    #[allow(dead_code)]
    struct TestHandler;

    impl SuitSharedSequenceHandler for TestHandler {
        fn on_conditions<'a>(
            &mut self,
            conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
        ) -> Result<(), SuitError> {
            for cond in conditions {
                assert!(matches!(
                    cond.get().unwrap(),
                    SuitCondition::VendorIdentifier(_)
                        | SuitCondition::ClassIdentifier(_)
                        | SuitCondition::ImageMatch(_)
                        | SuitCondition::ComponentSlot(_)
                        | SuitCondition::CheckContent(_)
                        | SuitCondition::Abort(_)
                        | SuitCondition::DeviceIdentifier(_)
                ));
            }
            Ok(())
        }

        fn on_commands<'a>(
            &mut self,
            commands: impl Iterator<Item = PairView<'a, SuitSharedCommand<'a>>>,
        ) -> Result<(), SuitError> {
            for cmd in commands {
                assert!(matches!(
                    cmd.get().unwrap(),
                    SuitSharedCommand::SetComponentIndex(_)
                        | SuitSharedCommand::RunSequence(_)
                        | SuitSharedCommand::TryEach(_)
                        | SuitSharedCommand::OverrideParameters(_)
                ));
            }
            Ok(())
        }
    }

    impl SuitCommandHandler for TestHandler {
        fn on_conditions<'a>(
            &mut self,
            conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
        ) -> Result<(), SuitError> {
            for cond in conditions {
                assert!(matches!(
                    cond.get().unwrap(),
                    SuitCondition::VendorIdentifier(_)
                        | SuitCondition::ClassIdentifier(_)
                        | SuitCondition::ImageMatch(_)
                        | SuitCondition::ComponentSlot(_)
                        | SuitCondition::CheckContent(_)
                        | SuitCondition::Abort(_)
                        | SuitCondition::DeviceIdentifier(_)
                ));
            }
            Ok(())
        }

        fn on_directives<'a>(
            &mut self,
            directives: impl Iterator<Item = PairView<'a, SuitDirective<'a>>>,
        ) -> Result<(), SuitError> {
            for dir in directives {
                assert!(matches!(
                    dir.get().unwrap(),
                    SuitDirective::Write(_)
                        | SuitDirective::SetComponentIndex(_)
                        | SuitDirective::RunSequence(_)
                        | SuitDirective::TryEach(_)
                        | SuitDirective::OverrideParameters(_)
                        | SuitDirective::Fetch(_)
                        | SuitDirective::Copy(_)
                        | SuitDirective::Swap(_)
                        | SuitDirective::Invoke(_)
                ));
            }
            Ok(())
        }
        fn on_customs<'a>(
            &mut self,
            customs: impl Iterator<Item = PairView<'a, CommandCustomValue<'a>>>,
        ) -> Result<(), SuitError> {
            for cust in customs {
                assert!(matches!(
                    cust.get().unwrap(),
                    CommandCustomValue::Bytes(_)
                        | CommandCustomValue::Text(_)
                        | CommandCustomValue::Integer(_)
                        | CommandCustomValue::Nil
                ))
            }
            Ok(())
        }
    }

    #[test]
    fn test_suit_shared_sequence_decode() {
        // Flat Shared sequence of B.6.Example 5 from ietf suit spec
        const SUIT_SHARED_SEQUENCE: cboritem::CborItem<'static> = cbor_macro::cbo!(
            r#"[
                    / directive-set-component-index / 12,0,
                    / directive-override-parameters / 20,{
                        / vendor-id /
1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-
be9d-e663e4d41ffe /,
                        / class-id /
2:h'1492af1425695e48bf429b2d51f2ab45' /
1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3:<< [
                            / algorithm-id / -16 / "sha256" /,
                            / digest-bytes /
h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ] >>,
                        / image-size / 14:34768
                    },
                    / condition-vendor-identifier / 1,15,
                    / condition-class-identifier / 2,15,
                    / directive-set-component-index / 12,1,
                    / directive-override-parameters / 20,{
                        / image-digest / 3:<< [
                            / algorithm-id / -16 / "sha256" /,
                            / digest-bytes /
h'0123456789abcdeffedcba987654321000112233445566778899aabbccddeeff'
                        ] >>,
                        / image-size / 14:76834
                    }
                ]"#
        );
        let seq = SuitCommandSequence(
            FlatSequence::decode(&mut Decoder::new(&SUIT_SHARED_SEQUENCE), &mut ()).unwrap(),
        );
        let mut handler = TestHandler;
        seq.decode_and_dispatch(&mut handler).unwrap();
        assert!(seq.decode_and_dispatch(&mut handler).is_ok());
    }

    #[test]
    fn test_suit_command_sequence() {
        // Flat command sequence from validate of B.6 Example 5 from ietf suit spec
        const SUIT_VALIDATE_COMMAND_SEQUENCE: cboritem::CborItem<'static> = cbor_macro::cbo!(
            r#"[
                / directive-set-component-index / 12,0,
                / condition-image-match / 3,15,
                / directive-set-component-index / 12,1,
                / condition-image-match / 3,15
            ] "#
        );
        let seq = SuitCommandSequence(
            FlatSequence::decode(&mut Decoder::new(&SUIT_VALIDATE_COMMAND_SEQUENCE), &mut ())
                .unwrap(),
        );
        let mut handler = TestHandler;
        seq.decode_and_dispatch(&mut handler).unwrap();
    }
}
