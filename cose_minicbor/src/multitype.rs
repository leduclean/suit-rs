//! Multi-type CBOR field adapters.
//!
//! This module defines helper enums and minicbor `Encode`/`Decode` implementations
//! for CBOR structures where a single field may legally have multiple types,
//! as defined by COSE and SUIT specifications.
//!
//! These adapters make it possible to deserialize CBOR keys or parameters
//! that can be represented in more than one way (e.g. a `bool` or a byte string),
//! while keeping a strongly typed internal representation.
use crate::cose_keys::Curve;
use minicbor::{
    Decode, Decoder, Encode, bytes::EncodeBytes, data::Type, decode::Error as DecodeError,
};

/// Enum for field that needs to be either bool or Bytes.
///
/// Example: [`crate::keys::CoseKey::y`].
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
#[cfg_attr(test, derive(PartialEq))]
pub enum BytesBool<'a> {
    Bytes(&'a [u8]),
    Bool(bool),
}

impl<'a, C> Encode<C> for BytesBool<'a> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            BytesBool::Bool(b) => b.encode(e, ctx),
            BytesBool::Bytes(bytes) => bytes.encode_bytes(e, ctx),
        }
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for BytesBool<'a> {
    fn decode(d: &mut Decoder<'a>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let ty = d.datatype()?;
        match ty {
            Type::Bytes => Ok(BytesBool::Bytes(minicbor::bytes::decode(d, ctx)?)),
            Type::Bool => Ok(BytesBool::Bool(bool::decode(d, ctx)?)),
            _ => Err(DecodeError::type_mismatch(ty).with_message("expected integer op  id")),
        }
    }
}

impl<'a> From<&'a [u8]> for BytesBool<'a> {
    fn from(bytes: &'a [u8]) -> Self {
        BytesBool::Bytes(bytes)
    }
}

impl From<bool> for BytesBool<'_> {
    fn from(b: bool) -> Self {
        BytesBool::Bool(b)
    }
}

impl<'a, const N: usize> From<&'a [u8; N]> for BytesBool<'a> {
    fn from(bytes: &'a [u8; N]) -> Self {
        BytesBool::Bytes(bytes)
    }
}

/// Enum to support both crv and symmetric key (k) COSE Key Type Parameters for label b(-1).
///
/// It allows to keep a single Key supporting sym and asymmetric keys ([COSE Key Type Parameters](https://www.iana.org/assignments/cose/cose.xhtml))
/// in [`crate::keys::CoseKey::crv_or_k`]
#[derive(Debug, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq))]
pub(crate) enum CrvOrK<'a> {
    Crv(Curve),
    K(&'a [u8]),
}

impl<'a, C> Encode<C> for CrvOrK<'a> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            CrvOrK::Crv(crv_id) => crv_id.encode(e, ctx),
            CrvOrK::K(bytes) => bytes.encode_bytes(e, ctx),
        }
    }
}

impl<'a, Ctx> Decode<'a, Ctx> for CrvOrK<'a> {
    fn decode(d: &mut Decoder<'a>, ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let ty = d.datatype()?;
        match ty {
            // A Symmetric Key is encoded as bstr whereas the crv id should be String or U8.
            // We use the type information to match the correct variant.
            Type::Bytes => Ok(CrvOrK::K(minicbor::bytes::decode(d, ctx)?)),
            Type::String | Type::U8 => Ok(CrvOrK::Crv(Curve::decode(d, ctx)?)),
            _ => Err(DecodeError::type_mismatch(ty).with_message("expected integer op  id")),
        }
    }
}

/// To support fields that can be either a text string or an integer label.
///
/// Example: [`crate::keys::CoseKey::key_ops`].
#[derive(Debug, Encode)]
#[allow(dead_code)]
pub(crate) enum TstrOrInt<'a> {
    #[n(0)]
    Int(#[n(0)] i32),
    #[n(1)]
    Tstr(#[n(0)] &'a str),
}
impl<'a, Ctx> Decode<'a, Ctx> for TstrOrInt<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let ty = d.datatype()?;
        match ty {
            Type::String => Ok(TstrOrInt::Tstr(
                str::from_utf8(d.bytes()?)
                    .map_err(|_e| DecodeError::message("Utf8 parsing error for TstrOrInt"))?,
            )),

            Type::I32 => Ok(TstrOrInt::Int(i32::decode(d, _ctx)?)),
            _ => Err(minicbor::decode::Error::message(
                "unexpected type for SuitAuthenticationBlock",
            )),
        }
    }
}

/// For fields that may contain `null` or a byte string.
///
/// We can't use `Option<T>` from minicbor because the value is skipped if None.
/// Here we clearly want to encode Nul if not present
#[allow(dead_code)]
pub(crate) enum NulOrBytes<'a> {
    Nul,
    #[allow(dead_code)]
    Bytes(&'a [u8]),
}

impl<C> Encode<C> for NulOrBytes<'_> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut minicbor::Encoder<W>,
        ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        match self {
            NulOrBytes::Bytes(bytes) => bytes.encode_bytes(e, ctx),
            NulOrBytes::Nul => {
                e.null()?;
                Ok(())
            }
        }
    }
}
