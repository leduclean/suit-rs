use minicbor::{Decode, Encode, bytes::ByteVec};
use std::collections::HashMap;

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseSign1 {
    #[n(0)]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>, // detached mode => None

    #[n(3)]
    pub signature: ByteVec,
}

/// Pour COSE_Sign (similaire mais avec plusieurs signatures)
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseSign {
    #[n(0)]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>,

    #[n(3)]
    pub signatures: Vec<CoseSignature>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseSignature {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    #[cbor(with = "minicbor::bytes")]
    pub signature: ByteVec,
}

/// Pour COSE_Mac
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseMac {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>,

    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub tag: ByteVec,

    #[n(4)]
    pub recipients: Vec<CoseRecipient>,
}

#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseRecipient {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub ciphertext: Option<ByteVec>,
}

/// Pour COSE_Mac0
#[derive(Debug, Encode, Decode)]
#[cbor(array)]
pub struct CoseMac0 {
    #[n(0)]
    #[cbor(with = "minicbor::bytes")]
    pub protected: ByteVec,

    #[n(1)]
    pub unprotected: HashMap<String, String>,

    #[n(2)]
    pub payload: Option<ByteVec>,

    #[n(3)]
    #[cbor(with = "minicbor::bytes")]
    pub tag: ByteVec,
}
