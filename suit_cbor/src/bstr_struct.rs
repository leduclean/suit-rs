use minicbor::{
    Decode, Decoder, Encode, Encoder, decode::Error as DecodeError, encode::Error as EncodeError,
};

use crate::errors::CborError;

/// A lazily decoded CBOR `.bstr` wrapper.
///
/// `BstrStruct<T>` stores the raw CBOR-encoded bytes of an inner value `T`
/// without decoding it immediately.
///
/// This is useful for:
/// - deferred validation
/// - signature verification workflows
/// - minimizing allocations in `no_std` environments
///
/// Call [`BstrStruct::get()`] to decode the inner value when needed.
#[derive(Debug)]
pub struct BstrStruct<'a, T: 'a> {
    bytes: &'a [u8],
    _ty: core::marker::PhantomData<&'a T>,
}

impl<'a, 'bytes: 'a, T, Ctx> Decode<'bytes, Ctx> for BstrStruct<'a, T>
where
    T: Decode<'a, Ctx>,
{
    fn decode(d: &mut Decoder<'bytes>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let start = d.position();
        let input = d.input();
        // We advance the main decoder to the next element
        d.skip()?;

        let end = d.position();
        let bytes = &input[start..end];
        Ok(BstrStruct {
            bytes,
            _ty: core::marker::PhantomData,
        })
    }
}

impl<'a, T, Ctx> Encode<Ctx> for BstrStruct<'a, T>
where
    T: Encode<Ctx>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _ctx: &mut Ctx,
    ) -> Result<(), EncodeError<W::Error>> {
        e.bytes(self.bytes)?;
        Ok(())
    }
}

impl<'a, T> BstrStruct<'a, T> {
    /// Getter to decode inner T and to get it when needed.
    pub fn get(&self) -> Result<T, CborError>
    where
        T: Decode<'a, ()>,
    {
        let inner = self.inner_bytes()?;
        minicbor::decode(inner).map_err(|err| err.into())
    }

    #[allow(dead_code)]
    /// Get the raw bytes of the struct.
    pub fn raw_bytes(&self) -> &'a [u8] {
        self.bytes
    }

    /// Get the inner bytes of the struct.
    pub fn inner_bytes(&self) -> Result<&'a [u8], CborError> {
        let mut d = Decoder::new(self.bytes);
        d.bytes().map_err(|e| e.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Decode, PartialEq, Debug)]
    struct Test<'a> {
        #[b(0)]
        label: &'a str,
        #[b(1)]
        value: u8,
    }

    #[test]
    fn test_lazy_cbor_decode_and_get_on_command_seq() {
        // We use `<< >>`  diagnostic notation to create bstr wrapped struct
        const LAZY_CBOR_COMMAND_SEQ: cboritem::CborItem<'_> =
            cbor_macro::cbo!(r#"<< ["test", 1] >>"#);
        const COMMAND_SEQ: cboritem::CborItem<'static> = cbor_macro::cbo!(r#"["test", 1]"#);
        let lazy: BstrStruct<Test> = minicbor::decode(&LAZY_CBOR_COMMAND_SEQ).unwrap();
        let seq = lazy.get().unwrap();
        assert_eq!(seq, minicbor::decode(&COMMAND_SEQ).unwrap())
    }

    #[test]
    fn test_invalid_data() {
        let invalid_bytes = b"\xFF\xFF";
        let bstr: BstrStruct<u8> = minicbor::decode(invalid_bytes).unwrap();
        let result = bstr.get();
        assert!(result.is_err());
    }
}
