use crate::suit_manifest::CborVec;
use core::str;
use minicbor::{
    Decode, Decoder, Encode, bytes::ByteSlice, data::Type, decode::Error as DecodeError,
};

// ! arbitrary for now, should explore how much it should be
const MAX_COSE_SIGN: usize = 10;
const MAX_COSE_RECIPIENT: usize = 10;
const MAX_KEY_OPS: usize = 10;

#[derive(Decode, Encode, Debug)]
#[cbor(map)]
#[non_exhaustive]
pub struct HeaderMap<'a> {
    #[n(1)]
    // Might be extended as more exotic algorithms are supported
    pub alg: Option<i32>,
    #[cbor(b(5), with = "minicbor::bytes")]
    pub(crate) iv: Option<&'a ByteSlice>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(tag(18))]
#[cbor(array)]
pub struct CoseSign1<'a> {
    #[cbor(b(0), with = "minicbor::bytes")]
    protected: &'a [u8],
    #[b(1)]
    unprotected: HeaderMap<'a>,
    #[cbor(b(2), with = "minicbor::bytes")]
    payload: Option<&'a [u8]>,
    #[cbor(b(3), with = "minicbor::bytes")]
    signature: &'a [u8],
}

// This structure will be used for Encrypting process
#[allow(dead_code)]
#[derive(minicbor::Encode)]
struct SigStructureForSignature1<'a> {
    #[n(0)]
    context: &'static str,
    #[cbor(b(1), with = "minicbor::bytes")]
    body_protected: &'a [u8],
    #[cbor(b(2), with = "minicbor::bytes")]
    external_aad: &'a [u8],
    #[cbor(b(3), with = "minicbor::bytes")]
    payload: &'a [u8],
}

#[derive(Debug, Encode, Decode)]
#[cbor(tag(98))]
#[cbor(array)]
pub struct CoseSign<'a> {
    #[cbor(b(0), with = "minicbor::bytes")]
    protected: &'a [u8],
    #[b(1)]
    unprotected: HeaderMap<'a>,
    // Payload could also be nil, but we don't support detached signatures here right now.
    #[cbor(b(2), with = "minicbor::bytes")]
    payload: &'a [u8],
    #[b(3)]
    signature: CborVec<CoseSignature<'a>, MAX_COSE_SIGN>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
struct CoseSignature<'a> {
    #[cbor(b(0), with = "minicbor::bytes")]
    protected: &'a [u8],
    #[b(1)]
    unprotected: HeaderMap<'a>,
    #[cbor(b(3), with = "minicbor::bytes")]
    signature: &'a [u8],
}

#[derive(Debug, Encode, Decode)]
#[cbor(tag(97))]
#[cbor(array)]
pub struct CoseMac<'a> {
    #[cbor(b(0), with = "minicbor::bytes")]
    protected: &'a [u8],

    #[b(1)]
    unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    payload: &'a [u8],

    #[cbor(b(3), with = "minicbor::bytes")]
    tag: &'a [u8],

    #[n(4)]
    pub recipients: CborVec<CoseRecipient<'a>, MAX_COSE_RECIPIENT>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(tag(17))]
#[cbor(array)]
pub struct CoseMac0<'a> {
    #[cbor(b(0), with = "minicbor::bytes")]
    protected: &'a [u8],

    #[b(1)]
    unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    payload: &'a [u8],

    #[cbor(b(3), with = "minicbor::bytes")]
    tag: &'a [u8],
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseRecipient<'a> {
    #[cbor(b(0), with = "minicbor::bytes")]
    protected: &'a [u8],

    #[b(1)]
    unprotected: HeaderMap<'a>,

    #[cbor(b(2), with = "minicbor::bytes")]
    pub ciphertext: Option<&'a [u8]>,
}

#[allow(dead_code)]
#[derive(minicbor::Encode)]
struct MacStructure<'a> {
    #[n(0)]
    context: &'static str,
    #[cbor(b(1), with = "minicbor::bytes")]
    body_protected: &'a [u8],
    #[cbor(b(2), with = "minicbor::bytes")]
    external_aad: &'a [u8],
    #[cbor(b(3), with = "minicbor::bytes")]
    payload: &'a [u8],
}

#[allow(dead_code)]
#[derive(minicbor::Decode, Debug)]
#[cbor(map)]
#[non_exhaustive]
pub(crate) struct CoseKey<'a> {
    #[n(1)]
    pub(crate) kty: TstrOrInt<'a>,
    #[cbor(b(2), with = "minicbor::bytes")]
    pub(crate) kid: Option<&'a [u8]>,
    #[n(3)]
    pub(crate) alg: Option<TstrOrInt<'a>>,
    #[n(4)]
    pub(crate) key_ops: CborVec<TstrOrInt<'a>, MAX_KEY_OPS>,
}
#[derive(Debug, Encode)]
pub enum TstrOrInt<'a> {
    #[n(0)]
    Int(#[n(0)] i32),
    #[n(1)]
    Tstr(#[n(0)] &'a str),
}
impl<'a, Ctx> Decode<'a, Ctx> for TstrOrInt<'a> {
    fn decode(d: &mut Decoder<'a>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let ty = d.datatype()?;
        match ty {
            Type::String => Ok(TstrOrInt::Tstr(str::from_utf8(d.bytes()?).map_err(
                |_e| {
                    #[cfg(any(feature = "defmt", feature = "std"))]
                    error!(
                        "Utf8 error for CoseKey TstrOrInt at: {:?}",
                        _e.valid_up_to()
                    );
                    DecodeError::message("Utf8 parsing error for TstrOrInt")
                },
            )?)),

            Type::I32 => Ok(TstrOrInt::Int(i32::decode(d, _ctx)?)),
            _ => {
                #[cfg(any(feature = "defmt", feature = "std"))]
                error!(
                    "SuitAuthenticationBlock: unexpected type: {:?}",
                    defmt::Display2Format(&ty)
                );
                Err(minicbor::decode::Error::message(
                    "unexpected type for SuitAuthenticationBlock",
                ))
            }
        }
    }
}
