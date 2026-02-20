pub use crate::cose::CoseAlg;
use crate::errors::{CoseError, ErrorImpl};
use crate::multitype::{BytesBool, CrvOrK};
use minicbor::{Decode, Encode};

/// A `COSE_Key` as described in Section 7 of RFC9052.
///
/// This combines [COSE Key Common
/// Parameters](https://www.iana.org/assignments/cose/cose.xhtml#key-common-parameters) with [COSE
/// Key Type Parameters](https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters)
/// under the assumption that the key type is 1 (Okp) or 2 (Ec2) or 4 (Symmetrical), which so far have non-conflicting
/// using the CrvOrK struct to accept both symmetrical key and EC id.
#[derive(Decode, Debug, Encode, Clone, Copy)]
#[cfg_attr(test, derive(PartialEq))]
#[cbor(map)]
#[non_exhaustive]
pub struct CoseKey<'a> {
    #[n(1)]
    pub(crate) kty: KeyType, // or tstr (unsupported here so far)

    #[cbor(b(2), with = "minicbor::bytes")]
    pub(crate) kid: Option<&'a [u8]>,

    #[n(3)]
    pub(crate) alg: Option<CoseAlg>,

    #[b(4)]
    pub(crate) key_ops: Option<KeyOp>, // multiple unsupported here so far

    /// Curv Id for Okp/Ec2 or k (key value) for symmetric keys (used in MAC).
    #[b(-1)]
    pub(crate) crv_or_k: Option<CrvOrK<'a>>,

    /// Public Key X parameter for Okp/Ec2 Keys.
    #[cbor(b(-2), with = "minicbor::bytes")]
    pub(crate) x: Option<&'a [u8]>,

    /// Public Key Y parameter for Ec2 Keys.
    #[cbor(b(-3))]
    pub(crate) y: Option<BytesBool<'a>>, // or bool (unsupported here so far)

    /// Private Key parameter for Ec2 Keys and Okp keys.
    #[cbor(b(-4), with = "minicbor::bytes")]
    pub(crate) d: Option<&'a [u8]>,
}

impl<'a> CoseKey<'a> {
    /// Creates an empty [`CoseKey`] of a specific [`KeyType`].
    pub fn new(kty: KeyType) -> Self {
        CoseKey {
            kty,
            kid: None,
            alg: None,
            key_ops: None,
            crv_or_k: None,
            x: None,
            y: None,
            d: None,
        }
    }

    /// Adds Key ID to [`CoseKey`].
    pub fn kid(&mut self, kid: &'a [u8]) {
        self.kid = Some(kid);
    }

    /// Adds Algorithm to [`CoseKey`].
    pub fn alg(&mut self, alg: CoseAlg) {
        self.alg = Some(alg);
    }

    /// Validate that the key has the required parameters to accept the current
    /// [`CoseAlg`] if present.
    pub fn verify_alg(&self) -> Result<(), CoseError> {
        if let Some(alg) = self.alg {
            let valid = match self.kty {
                KeyType::Symmetric | KeyType::HssLms => matches!(
                    alg,
                    CoseAlg::A128KW
                        | CoseAlg::A256KW
                        | CoseAlg::HMAC256256
                        | CoseAlg::HMAC25664
                        | CoseAlg::HSSLMS
                ),
                KeyType::Ec2 => matches!(
                    alg,
                    CoseAlg::ES256 | CoseAlg::ES256P256 | CoseAlg::ECDHESA128KW
                ),
                KeyType::Okp => matches!(alg, CoseAlg::ED25519 | CoseAlg::ECDHESA128KW),
            };
            if !valid {
                return Err(ErrorImpl::UnexpectedAlg.into());
            }
        }
        Ok(())
    }

    /// Adds symmetrical Key to [`CoseKey`]
    /// Raises error if this key is not of type [`KeyType::Symmetric`].
    pub fn k(&mut self, k: &'a [u8]) -> Result<(), CoseError> {
        if !matches!(self.kty, KeyType::Symmetric | KeyType::HssLms) {
            return Err(ErrorImpl::UncompatibleKeyField.into());
        }
        self.crv_or_k = Some(CrvOrK::K(k));
        Ok(())
    }

    /// Adds curve to [`CoseKey`].
    /// Raises error if this key is not of type [`KeyType::Ec2`] or [`KeyType::Okp`].
    pub fn crv(&mut self, crv: Curve) -> Result<(), CoseError> {
        if !matches!(self.kty, KeyType::Ec2 | KeyType::Okp) {
            return Err(ErrorImpl::UncompatibleKeyField.into());
        }
        self.crv_or_k = Some(CrvOrK::Crv(crv));
        Ok(())
    }

    /// Try to get the curve from [`CoseKey`] assuming it should be present.
    #[inline]
    pub(crate) fn try_crv(&self) -> Result<Curve, CoseError> {
        match self.crv_or_k {
            Some(CrvOrK::Crv(crv)) => Ok(crv),
            _ => Err(ErrorImpl::MissingCurve.into()),
        }
    }

    /// Validate that the key has the required parameters to accept the current
    /// [`Curve`] if present.
    pub fn verify_curve(&self) -> Result<(), CoseError> {
        if matches!(self.kty, KeyType::Symmetric | KeyType::HssLms) {
            return Ok(());
        }

        let crv = self.try_crv()?;

        if (self.kty == KeyType::Okp && crv == Curve::Ed25519)
            || (self.kty == KeyType::Ec2 && crv == Curve::P256)
            || (self.alg == Some(CoseAlg::ECDHESA128KW)
                && [Curve::P256, Curve::P384, Curve::P521].contains(&crv))
        {
            Ok(())
        } else {
            Err(ErrorImpl::UnexpectedCurve.into())
        }
    }

    /// Adds public key or x-coordinate to [`CoseKey`].
    /// Raises error if this key is not of type [`KeyType::Ec2`] or [`KeyType::Okp`].
    pub fn x(&mut self, x: &'a [u8]) -> Result<(), CoseError> {
        if !matches!(self.kty, KeyType::Ec2 | KeyType::Okp) {
            return Err(ErrorImpl::UncompatibleKeyField.into());
        }
        self.x = Some(x);
        Ok(())
    }

    /// Sets the y-coordinate (or its compressed parity flag) for an EC2 key.
    /// Raises error if this key is not of type [`KeyType::Ec2`].
    pub fn y<T>(&mut self, y: T) -> Result<(), CoseError>
    where
        T: Into<BytesBool<'a>>,
    {
        if !matches!(self.kty, KeyType::Ec2) {
            return Err(ErrorImpl::UncompatibleKeyField.into());
        }

        self.y = Some(y.into());
        Ok(())
    }

    /// Adds secret key d to [`CoseKey`].
    /// Raises error if this key is not of type [`KeyType::Ec2`] or [`KeyType::Okp`].
    pub fn d(&mut self, d: &'a [u8]) -> Result<(), CoseError> {
        if !matches!(self.kty, KeyType::Ec2 | KeyType::Okp) {
            return Err(ErrorImpl::UncompatibleKeyField.into());
        }
        self.d = Some(d);
        Ok(())
    }

    /// Adds key_op depending on KeyOp to [`CoseKey`]
    /// Only one key op is supported so if you aim for a generic key
    /// don't use this field assignment used to filter on keys.
    pub fn key_op(&mut self, use_for: KeyOp) {
        self.key_ops = Some(use_for)
    }

    /// Verify that keys field are not empty when needed.
    pub fn verify_key_present(&self) -> Result<(), CoseError> {
        match self.kty {
            KeyType::Symmetric | KeyType::HssLms => {
                // For symmetric and HSSLMS keys crv_or_k MUST be Some(CrvOrK::K(_))
                match &self.crv_or_k {
                    Some(CrvOrK::K(_)) => Ok(()),
                    _ => Err(ErrorImpl::MissingKeyValue.into()),
                }
            }
            KeyType::Ec2 => {
                // Ec2 requires x and y
                if self.x.is_some() && self.y.is_some() {
                    Ok(())
                } else {
                    Err(ErrorImpl::MissingKeyValue.into())
                }
            }
            KeyType::Okp => {
                // OKP requires x
                if self.x.is_some() {
                    Ok(())
                } else {
                    Err(ErrorImpl::MissingKeyValue.into())
                }
            }
        }
    }

    /// Validate that the key has the required parameters to be encoded/used,
    /// according to kty.
    pub fn validate_for_encoding(&self) -> Result<(), CoseError> {
        self.verify_curve()?;
        self.verify_alg()?;
        self.verify_key_present()
    }
}

/// Key Types supported by Suit [`CoseKey`].
#[derive(Decode, Debug, Encode, PartialEq, Copy, Clone)]
#[cbor(index_only)]
#[non_exhaustive]
pub enum KeyType {
    #[n(1)]
    Okp,
    #[n(2)]
    Ec2,
    #[n(4)]
    Symmetric,
    #[n(5)]
    HssLms,
}
/// Key Operation values as depicted in the table 5 of RFC 9052.
#[derive(Decode, Debug, Encode, PartialEq, Copy, Clone)]
#[cbor(index_only)]
#[non_exhaustive]
pub enum KeyOp {
    #[n(1)]
    Verify,
    #[n(6)]
    UnwrapKey,
    #[n(8)]
    DeriveBits,
    #[n(10)]
    MACVerify,
}

// Cose Elliptic Curves values as decrypted in IANA spec [COSE
/// Key Type Parameters](<https://www.iana.org/assignments/cose/cose.xhtml#key-type-parameters>).
#[derive(Decode, Debug, Encode, PartialEq, Copy, Clone)]
#[cbor(index_only)]
#[non_exhaustive]
pub enum Curve {
    #[n(1)]
    P256,
    #[n(2)]
    P384,
    #[n(3)]
    P521,
    #[n(6)]
    Ed25519,
}
impl Curve {
    /// Little helper to compare a curve with the expected.
    ///
    /// * `expected`: Expected curve.
    /// * `actual`: Actual curve.
    pub fn check_curve(self, expected: Curve) -> Result<(), CoseError> {
        if expected != self {
            return Err(ErrorImpl::UnexpectedCurve.into());
        }
        Ok(())
    }
}

suit_cbor::iter_wrapper!(IterCoseKey, CoseKey<'a>);

/// An iterable [`CoseKey`] set to decode CoseKeySet buffer bytes as described in Appendix C.7 of RFC9052.
#[derive(Decode)]
#[cbor(transparent)]
pub(crate) struct CoseKeySet<'a>(#[b(0)] IterCoseKey<'a>);

impl<'a> CoseKeySet<'a> {
    /// Iter on [`CoseKeySet`] and filters on a key set to retrieve a key.
    /// Filter layers are: kid -> kty -> alg -> key_op.
    /// The correspondance is strict (reject if not provided) for all field,
    /// expect key_ops, on which we allow key if not provided.
    pub(crate) fn match_and_get_key(
        &self,
        kty: KeyType,
        alg: Option<CoseAlg>,
        key_op: KeyOp,
        kid: Option<&[u8]>,
    ) -> Result<KeyMaterial<'a>, CoseError> {
        let mut iter = self.0.get()?;

        let found = iter.find_map(|key| {
            key.ok().filter(|key| {
                // Used to filter, MUST be present and the same if requested.
                if let Some(required_kid) = kid
                    && (key.kid.is_none() || key.kid != Some(required_kid))
                {
                    return false;
                }

                // Security Checks

                // MUST be the same
                if key.kty != kty {
                    return false;
                }

                // If the algorithms do not match (or is not present), then this key
                // object MUST NOT be used to perform the cryptographic operation.
                if let Some(required_alg) = alg
                    && (key.alg.is_none() || key.alg != Some(required_alg))
                {
                    return false;
                }

                // If present MUST be the same.
                if key.key_ops.is_some() && key.key_ops.as_ref() != Some(&key_op) {
                    return false;
                }

                true
            })
        });
        if let Some(key) = found {
            key.try_into()
        } else {
            Err(ErrorImpl::UnvalidKeySet.into())
        }
    }
}

/// A **building** struct to create an encoded `CoseKeySet`.
pub struct CoseKeySetBuilder<const N: usize> {
    inner: heapless::Vec<u8, N>,
}

impl<const N: usize> CoseKeySetBuilder<N> {
    /// Create an empty [`CoseKeySetBuilder`].
    ///
    /// We begin an array with [`Encode`] so it can raise [`CoseError`].
    pub fn try_new() -> Result<Self, CoseError> {
        let mut inner = heapless::Vec::new();
        let mut enc = minicbor::Encoder::new(minicbor_adapters::WriteToHeapless(&mut inner));
        enc.begin_array().map_err(|_| ErrorImpl::OutOfSpace(N))?;
        Ok(Self { inner })
    }

    /// Add a [`CoseKey`] in the [`CoseKeySetBuilder`].
    pub fn push_key(&mut self, key: CoseKey) -> Result<(), CoseError> {
        key.validate_for_encoding()?;
        minicbor::encode(key, minicbor_adapters::WriteToHeapless(&mut self.inner))
            .map_err(|_| ErrorImpl::OutOfSpace(N))?;

        Ok(())
    }

    /// Closes the [`CoseKeySetBuilder`] and give the encoded corresponding bytes.
    ///
    /// Since it **closes** the builder, you won't be able to use the builder after.
    pub fn into_bytes(mut self) -> Result<heapless::Vec<u8, N>, CoseError> {
        let mut enc = minicbor::Encoder::new(minicbor_adapters::WriteToHeapless(&mut self.inner));
        enc.end().map_err(|_| ErrorImpl::OutOfSpace(N))?;
        Ok(self.inner)
    }

    /// Give the owned [`OwnedCoseKeySet`] wrapper around the encoded inner bytes.
    pub fn into_owned(self) -> Result<OwnedCoseKeySet<N>, CoseError> {
        let buf = self.into_bytes()?;
        Ok(OwnedCoseKeySet { buf })
    }
}

/// Wrapper around the encoded bytes of an encoded `CoseKeySet`.
pub struct OwnedCoseKeySet<const N: usize> {
    pub buf: heapless::Vec<u8, N>,
}

/// Enum to return different type of keys when using [`CoseKeySet::match_and_get_key`].
pub(crate) enum KeyMaterial<'a> {
    Ec2 {
        x: &'a [u8],
        y: BytesBool<'a>,
        crv: Curve,
    },
    Okp {
        x: &'a [u8],
        crv: Curve,
    },
    Symmetric(&'a [u8]),
    HssLms(&'a [u8]),
    Private {
        d: &'a [u8],
        crv: Curve,
    },
}

impl<'a> TryFrom<CoseKey<'a>> for KeyMaterial<'a> {
    type Error = CoseError;
    fn try_from(key: CoseKey<'a>) -> Result<Self, Self::Error> {
        match key.kty {
            KeyType::Ec2 => {
                let crv = key.try_crv()?;
                if let Some(d) = key.d {
                    Ok(KeyMaterial::Private { d, crv })
                } else if let (Some(x), Some(y)) = (key.x, key.y) {
                    Ok(KeyMaterial::Ec2 { x, y, crv })
                } else {
                    Err(ErrorImpl::MissingKeyValue.into())
                }
            }
            KeyType::Okp => {
                let crv = key.try_crv()?;
                let Some(x) = key.x else {
                    return Err(ErrorImpl::MissingKeyValue.into());
                };
                Ok(KeyMaterial::Okp { x, crv })
            }
            KeyType::Symmetric => {
                let Some(CrvOrK::K(k)) = key.crv_or_k else {
                    return Err(ErrorImpl::MissingKeyValue.into());
                };
                Ok(KeyMaterial::Symmetric(k))
            }
            KeyType::HssLms => {
                let Some(CrvOrK::K(k)) = key.crv_or_k else {
                    return Err(ErrorImpl::MissingKeyValue.into());
                };
                Ok(KeyMaterial::HssLms(k))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use minicbor::decode::Decoder;
    use std::vec::Vec;
    const KEY_SET_SIZE_TEST: usize = 1000;

    #[test]
    fn test_cose_key_set_builder() {
        let key_set: cboritem::CborItem = cbor_macro::cbo!(
            r#"[
  {
    -1:1,
    -2:h'65eda5a12577c2bae829437fe338701a10aaa375e1bb5b5de108de439c0
8551d',
    -3:h'1e52ed75701163f7f9e40ddf9f341b3dc9ba860af7e0ca7ca7e9eecd008
4d19c',
    1:2,
    2:'meriadoc.brandybuck@buckland.example'
  },
  {
    -1:1,
    -2:h'bac5b11cad8f99f9c72b05cf4b9e26d244dc189f745228255a219a86d6a
09eff',
    -3:h'20138bf82dc1b6d562be0fa54ab7804a3a64b6d72ccfed6b6fb6ed28bbf
c117e',
    1:2,
    2:'11',
  },
  {
    -1:1,
    -2:h'98f50a4ff6c05861c8860d13a638ea56c3f5ad7590bbfbf054e1c7b4d91
d6280',
    -3:h'f01400b089867804b8e9fc96c3932161f1934f4223069170d924b7e03bf
822bb',
    1:2,
    2:'peregrin.took@tuckborough.example'
  }
]"#
        );
        let mut builder: CoseKeySetBuilder<KEY_SET_SIZE_TEST> =
            CoseKeySetBuilder::try_new().expect("Begin array shouldn't fail");
        let mut decoder = Decoder::new(&key_set);
        let iterable_cose_set = decoder
            .array_iter::<CoseKey>()
            .expect("array iteration should be possible");
        iterable_cose_set.for_each(|key| {
            builder
                .push_key(key.expect("Couldn't decode into key"))
                .expect("buffer too small")
        });

        let mut decoder2 = Decoder::new(&key_set);
        let iterable_cose_set2 = decoder2
            .array_iter::<CoseKey>()
            .expect("array iteration should be possible");

        let key_set_bytes = builder.into_bytes().expect("too much bytes");
        let key_set: CoseKeySet =
            minicbor::decode(&key_set_bytes).expect("Cose Key Set decoding failed");

        let actual: Result<Vec<_>, _> = key_set.0.get().expect("get_iterable failed").collect();

        let expected: Result<Vec<_>, _> = iterable_cose_set2.collect();

        let actual = actual.expect("actual iterator had an error");
        let expected = expected.expect("expected iterator had an error");

        assert_eq!(actual, expected);
    }

    #[test]
    fn test_match_and_get_key() {
        let mut builder: CoseKeySetBuilder<KEY_SET_SIZE_TEST> =
            CoseKeySetBuilder::try_new().unwrap();
        let mut key1 = CoseKey::new(KeyType::Ec2);
        key1.x(b"first").unwrap();
        key1.y(b"first").unwrap();
        key1.crv(Curve::P256).unwrap();

        let mut key2 = CoseKey::new(KeyType::Ec2);
        key2.alg(CoseAlg::ES256);
        key2.x(b"second").unwrap();
        key2.y(b"second").unwrap();
        key2.crv(Curve::P256).unwrap();

        let mut key3 = CoseKey::new(KeyType::Ec2);
        key3.x(b"third").unwrap();
        key3.y(b"third").unwrap();
        key3.kid(b"key3");
        key3.crv(Curve::P256).unwrap();

        builder.push_key(key1).unwrap();
        builder.push_key(key2).unwrap();
        builder.push_key(key3).unwrap();

        let bytes = builder.into_bytes().unwrap();
        let key_set: CoseKeySet = minicbor::decode(&bytes).unwrap();

        let is_a_match = key_set
            .match_and_get_key(KeyType::Ec2, None, KeyOp::Verify, None)
            .expect("Should match a key");
        if let KeyMaterial::Ec2 { x, y, crv } = is_a_match {
            assert_eq!(x, b"first");
            assert_eq!(y, BytesBool::Bytes(b"first"));
            assert_eq!(crv, Curve::P256);
        } else {
            panic!("First match should be an Ec2 key")
        };

        let is_a_match_with_alg = key_set
            .match_and_get_key(KeyType::Ec2, Some(CoseAlg::ES256), KeyOp::Verify, None)
            .expect("Should match a key");
        if let KeyMaterial::Ec2 { x, y, crv } = is_a_match_with_alg {
            // We assert it's curve coordinate of the second key
            assert_eq!(x, b"second");
            assert_eq!(y, BytesBool::Bytes(b"second"));
            assert_eq!(crv, Curve::P256);
        } else {
            panic!("Second match should be an Ec2 key")
        };

        let is_a_match_with_kid = key_set
            .match_and_get_key(KeyType::Ec2, None, KeyOp::MACVerify, Some(b"key3"))
            .expect("Should match a key");
        if let KeyMaterial::Ec2 { x, y, crv } = is_a_match_with_kid {
            // We assert it's curve coordinate of the third key
            assert_eq!(x, b"third");
            assert_eq!(y, BytesBool::Bytes(b"third"));
            assert_eq!(crv, Curve::P256);
        } else {
            panic!("Second match should be an Ec2 key")
        };
        let is_not_a_match =
            key_set.match_and_get_key(KeyType::Symmetric, None, KeyOp::Verify, None);
        assert!(is_not_a_match.is_err_and(|e| matches!(e.source, ErrorImpl::UnvalidKeySet)));
    }

    #[test]
    fn test_k_on_non_symmetric_error() {
        let mut non_sym = CoseKey::new(KeyType::Ec2);
        assert!(
            non_sym
                .k(b"secret")
                .is_err_and(|e| matches!(e.source, ErrorImpl::UncompatibleKeyField))
        );
    }

    #[test]
    fn test_crv_on_non_ec_error() {
        let mut non_ec = CoseKey::new(KeyType::Symmetric);
        assert!(
            non_ec
                .crv(Curve::P256)
                .is_err_and(|e| matches!(e.source, ErrorImpl::UncompatibleKeyField))
        );
    }

    #[test]
    fn test_roundtrip_symmetric() {
        let mut key = CoseKey::new(KeyType::Symmetric);
        key.kid(b"kid");
        key.alg(CoseAlg::HSSLMS);
        key.k(b"secret").expect("should accept k on symmetric");
        let mut builder: CoseKeySetBuilder<KEY_SET_SIZE_TEST> =
            CoseKeySetBuilder::try_new().unwrap();
        builder.push_key(key).unwrap();
        let bytes = builder.into_bytes().unwrap();
        let key_set: CoseKeySet = minicbor::decode(&bytes).expect("decode key set");
        if let KeyMaterial::Symmetric(k) = key_set
            .match_and_get_key(KeyType::Symmetric, None, KeyOp::MACVerify, None)
            .unwrap()
        {
            assert_eq!(k, b"secret");
        } else {
            panic!("expected symmetric key");
        }
    }

    #[test]
    fn test_key_ops_exists_but_unvalid() {
        let mut key = CoseKey::new(KeyType::Symmetric);
        key.k(b"my secret").unwrap();
        key.key_op(KeyOp::Verify);

        let mut builder: CoseKeySetBuilder<KEY_SET_SIZE_TEST> =
            CoseKeySetBuilder::try_new().unwrap();
        builder.push_key(key).unwrap();
        let bytes = builder.into_bytes().unwrap();
        let key_set: CoseKeySet = minicbor::decode(&bytes).expect("decode key set");
        assert!(
            key_set
                .match_and_get_key(KeyType::Symmetric, None, KeyOp::MACVerify, None)
                .is_err_and(|e| matches!(e.source, ErrorImpl::UnvalidKeySet))
        )
    }

    #[test]
    fn test_out_of_space() {
        let mut constrained: CoseKeySetBuilder<2> = CoseKeySetBuilder::try_new().unwrap();
        let mut key1 = CoseKey::new(KeyType::Symmetric);
        key1.k(b"1").unwrap();
        assert!(
            constrained
                .push_key(key1)
                .is_err_and(|e| matches!(e.source, ErrorImpl::OutOfSpace(2)))
        )
    }

    #[test]
    fn test_verify_alg_symmetric_ok() {
        let mut key = CoseKey::new(KeyType::Symmetric);
        key.alg(CoseAlg::A128KW);
        assert!(key.verify_alg().is_ok());

        key.alg(CoseAlg::HMAC256256);
        assert!(key.verify_alg().is_ok());

        key.alg(CoseAlg::HSSLMS);
        assert!(key.verify_alg().is_ok());
    }

    #[test]
    fn test_verify_alg_symmetric_fail() {
        let mut key = CoseKey::new(KeyType::Symmetric);
        key.alg(CoseAlg::ES256);
        assert!(key.verify_alg().is_err());
    }

    #[test]
    fn test_verify_alg_ec2_ok() {
        let mut key = CoseKey::new(KeyType::Ec2);
        key.alg(CoseAlg::ES256);
        assert!(key.verify_alg().is_ok());

        key.alg(CoseAlg::ES256P256);
        assert!(key.verify_alg().is_ok());

        key.alg(CoseAlg::ECDHESA128KW);
        assert!(key.verify_alg().is_ok());
    }

    #[test]
    fn test_verify_alg_ec2_fail() {
        let mut key = CoseKey::new(KeyType::Ec2);
        key.alg(CoseAlg::A128KW);
        assert!(key.verify_alg().is_err());
    }

    #[test]
    fn test_verify_alg_okp_ok() {
        let mut key = CoseKey::new(KeyType::Okp);
        key.alg(CoseAlg::ED25519);
        assert!(key.verify_alg().is_ok());

        key.alg(CoseAlg::ECDHESA128KW);
        assert!(key.verify_alg().is_ok());
    }

    #[test]
    fn test_verify_alg_okp_fail() {
        let mut key = CoseKey::new(KeyType::Okp);
        key.alg(CoseAlg::ES256);
        assert!(key.verify_alg().is_err());
    }

    #[test]
    fn test_verify_curve_ok() {
        let mut key = CoseKey::new(KeyType::Okp);
        key.crv(Curve::Ed25519).unwrap();
        assert!(key.verify_curve().is_ok());

        let mut key2 = CoseKey::new(KeyType::Ec2);
        key2.crv(Curve::P256).unwrap();
        assert!(key2.verify_curve().is_ok());
    }

    #[test]
    fn test_verify_curve_fail() {
        let mut key = CoseKey::new(KeyType::Okp);
        key.crv(Curve::P256).unwrap();
        assert!(key.verify_curve().is_err());

        let mut key2 = CoseKey::new(KeyType::Ec2);
        key2.crv(Curve::Ed25519).unwrap();
        assert!(key2.verify_curve().is_err());
    }

    #[test]
    fn test_verify_curve_symmetric_ignored() {
        let key = CoseKey::new(KeyType::Symmetric);
        // Should not error even if crv_or_k is None
        assert!(key.verify_curve().is_ok());
    }

    #[test]
    fn test_verify_key_present() {
        let key = CoseKey::new(KeyType::Ec2);
        assert!(
            key.verify_key_present()
                .is_err_and(|e| matches!(e.source, ErrorImpl::MissingKeyValue))
        )
    }
}
