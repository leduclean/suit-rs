//! Cryptographic helpers for COSE key exchange and key wrapping.
//!
//! This module provides low-level primitives used in COSE message encryption,
//! specifically for performing Elliptic Curve Diffie–Hellman Ephemeral-Static (ECDH-ES)
//! key agreement and AES Key Wrap (AES-KW) unwrapping.
//!
//! ## Functions
//!
//! - perform_ecdh_es Computes a shared secret using ECDH-ES on P-256 or P-521 curves,
//!   supporting both compressed (`x` + `y_is_odd`) and uncompressed (`x`, `y`) public key formats.
//! - unwrap_aes_kw Unwraps a CEK (Content Encryption Key) using AES Key Wrap
//!   with either 128-bit or 256-bit KEK lengths.
//!
//! These functions are intended for internal use inside the COSE implementation and
//! assume all inputs (curve parameters, keys, and buffers) have already been validated.

#[cfg(feature = "ecdh_es")]
use crate::cose_keys::Curve;
#[cfg(any(feature = "ecdh_es", feature = "a128kw", feature = "a256kw"))]
use crate::errors::{CoseError, ErrorImpl};
#[cfg(feature = "ecdh_es")]
use crate::multitype::BytesBool;
#[cfg(any(feature = "ecdh_p256", feature = "ecdh_p521"))]
/// Performs an Elliptic Curve Diffie–Hellman Ephemeral-Static (ECDH-ES) key exchange.
///
/// Computes a shared secret `Z` from the recipient’s static private key and the sender’s
/// ephemeral public key. Supports both uncompressed (`x`, `y`) and compressed (`x`, `y_is_odd`)
/// representations of the public key, depending on the COSE key encoding.
///
/// ## Supported curves
///
/// - P-256 (`Curve::P256`)
/// - P-521 (`Curve::P521`)
///
/// ## Notes
///
/// The output `Z` is the raw ECDH shared secret and **must be passed through
/// a KDF (e.g. HKDF)** before being used as a symmetric key.
pub(crate) fn perform_ecdh_es(
    private_bytes: &[u8],
    pub_x: &[u8],
    pub_y: BytesBool,
    pub_crv: Curve,
    z_out: &mut [u8],
) -> Result<(), CoseError> {
    use p256::elliptic_curve::point::DecompressPoint;

    match pub_crv {
        #[cfg(feature = "ecdh_p256")]
        Curve::P256 => {
            let ephemeral_pub_key = match pub_y {
                BytesBool::Bool(y_is_odd) => p256::PublicKey::from_affine(
                    p256::AffinePoint::decompress(pub_x.into(), (y_is_odd as u8).into())
                        .into_option()
                        .ok_or(ErrorImpl::InconsistentDetails)?,
                )
                .map_err(|_| ErrorImpl::InconsistentDetails)?,
                BytesBool::Bytes(y_bytes) => p256::PublicKey::from_sec1_bytes(
                    p256::EncodedPoint::from_affine_coordinates(
                        pub_x.into(),
                        y_bytes.into(),
                        false,
                    )
                    .as_ref(),
                )
                .map_err(|_| ErrorImpl::InconsistentDetails)?,
            };
            let secret_key = p256::SecretKey::from_bytes(private_bytes.into())
                .map_err(|_| ErrorImpl::InconsistentDetails)?;

            // Shared Secret obtain from the ECDH ES process.
            let z = p256::ecdh::diffie_hellman(
                secret_key.to_nonzero_scalar(),
                ephemeral_pub_key.as_ref(),
            );
            let raw = z.raw_secret_bytes();
            if z_out.len() < raw.len() {
                return Err(ErrorImpl::OutOfSpace(z_out.len()).into());
            }
            z_out[..raw.len()].copy_from_slice(raw);
            Ok(())
        }
        #[cfg(feature = "ecdh_p521")]
        Curve::P521 => {
            let ephemeral_pub_key = match pub_y {
                BytesBool::Bool(y_is_odd) => p521::PublicKey::from_affine(
                    p521::AffinePoint::decompress(pub_x.into(), (y_is_odd as u8).into())
                        .into_option()
                        .ok_or(ErrorImpl::InconsistentDetails)?,
                )
                .map_err(|_| ErrorImpl::InconsistentDetails)?,
                BytesBool::Bytes(y_bytes) => p521::PublicKey::from_sec1_bytes(
                    p521::EncodedPoint::from_affine_coordinates(
                        pub_x.into(),
                        y_bytes.into(),
                        false,
                    )
                    .as_ref(),
                )
                .map_err(|_| ErrorImpl::InconsistentDetails)?,
            };

            let secret_key = p521::SecretKey::from_bytes(private_bytes.into())
                .map_err(|_| ErrorImpl::InconsistentDetails)?;

            // Shared Secret obtain from the ECDH ES process.
            let z = p521::ecdh::diffie_hellman(
                secret_key.to_nonzero_scalar(),
                ephemeral_pub_key.as_affine(),
            );
            let raw = z.raw_secret_bytes();
            if z_out.len() < raw.len() {
                return Err(ErrorImpl::OutOfSpace(z_out.len()).into());
            }
            z_out[..raw.len()].copy_from_slice(raw);
            Ok(())
        }
        _ => Err(ErrorImpl::UnexpectedCurve.into()),
    }
}

#[cfg(any(feature = "ecdh_es", feature = "a128kw", feature = "a256kw"))]
/// Unwraps an AES-wrapped key using AES Key Wrap [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394).
///
/// Decrypts a wrapped CEK (Content Encryption Key) using the provided KEK
/// (Key Encryption Key) into the output buffer. Supports AES-128 and AES-256 key lengths.
pub(crate) fn unwrap_aes_kw(kek: &[u8], wrapped: &[u8], out: &mut [u8]) -> Result<(), CoseError> {
    match kek.len() {
        16 => {
            let kek_impl = aes_kw::KekAes128::new(kek.into());
            kek_impl
                .unwrap(wrapped, out)
                .map_err(|_| ErrorImpl::InconsistentDetails)?;
            Ok(())
        }
        32 => {
            let kek_impl = aes_kw::KekAes256::new(kek.into());
            kek_impl
                .unwrap(wrapped, out)
                .map_err(|_| ErrorImpl::InconsistentDetails)?;
            Ok(())
        }
        _ => Err(ErrorImpl::InvalidKeyLength.into()),
    }
}
