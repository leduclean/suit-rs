use core::marker::PhantomData;
use minicbor::{
    Decode, Decoder, Encode, Encoder, decode::Error as DecodeError, encode::Error as EncodeError,
};

/// Lazy wrapper: on decode, for .bstr cbor T, we store the bytes slice but do NOT decode inner T.
/// Call `.get()` to decode T later if you need acces to data.
// We borrow a bstr below so we need #[b()] instead of #[n()] of each struct using LazyCbor
#[derive(Debug)]
pub struct LazyCbor<'a, T: 'a> {
    bytes: &'a [u8],
    _ty: PhantomData<&'a T>,
}

impl<'a, 'bytes: 'a, T, Ctx> Decode<'bytes, Ctx> for LazyCbor<'a, T>
where
    T: Decode<'a, Ctx>,
{
    fn decode(d: &mut Decoder<'bytes>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let bytes: &'bytes [u8] = d.bytes()?;
        Ok(LazyCbor {
            bytes,
            _ty: PhantomData,
        })
    }
}

impl<'a, T, Ctx> Encode<Ctx> for LazyCbor<'a, T>
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

/// Getter to decode inner T and to get it when needed
impl<'a, T> LazyCbor<'a, T> {
    pub fn get(&self) -> Result<T, DecodeError>
    where
        T: Decode<'a, ()>,
    {
        let mut decoder = Decoder::new(self.bytes);
        T::decode(&mut decoder, &mut ())
    }
}

mod tests {
    #[test]
    fn test_lazy_cbor_decode_and_get_on_command_seq() {
        use super::*;
        use crate::suit_manifest::SuitCommandSequence;
        // We use `<< >>`  diagnostic notation to create bstr wrapped struct
        const LAZY_CBOR_COMMAND_SEQ: cboritem::CborItem<'_> = cbor_macro::cbo!(
            r#"<< [
                / condition-image-match / 3,15] >>
             "#
        );
        const COMMAND_SEQ: cboritem::CborItem<'static> = cbor_macro::cbo!(
            r#"[
                / condition-image-match / 3,15
            ]"#
        );
        let mut d1 = Decoder::new(&LAZY_CBOR_COMMAND_SEQ);
        let mut d2 = Decoder::new(&COMMAND_SEQ);

        let lazy = LazyCbor::<SuitCommandSequence>::decode(&mut d1, &mut ()).unwrap();
        let seq = lazy.get().unwrap();

        assert_eq!(
            seq.get(),
            SuitCommandSequence::decode(&mut d2, &mut ()).unwrap().get()
        )
    }
}
