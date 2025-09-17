use core::marker::PhantomData;
use minicbor::{
    Decode, Decoder, Encode, Encoder, decode::Error as DecodeError, encode::Error as EncodeError,
};

/// Lazy wrapper: on decode, for .bstr cbor T, we store the bytes slice but do NOT decode inner T.
/// Call `.decode_inner(ctx)` to decode T later if you need acces to data.
// we borrow a bstr so we need #[b()] instead of #[n()] of each struct using this
#[derive(Debug)]
pub struct LazyCbor<'b, T: 'b> {
    pub bytes: &'b [u8],
    _ty: PhantomData<&'b T>, // We use phantom data that any reference in T are valid for 'b (the bstr entry)
}

impl<'b, T, Ctx> Decode<'b, Ctx> for LazyCbor<'b, T>
where
    // T must itself implement decoding so we can decode on demand
    T: Decode<'b, Ctx>,
{
    fn decode(d: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let bytes = d.bytes()?; // returns &'b [u8] (handles definite/indefinite)
        Ok(LazyCbor {
            bytes,
            _ty: PhantomData,
        })
    }
}
impl<'b, T, Ctx> Encode<Ctx> for LazyCbor<'b, T>
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

// helper to decode when needed:
impl<'b, T> LazyCbor<'b, T> {
    pub fn decode_inner<C>(&self, ctx: &mut C) -> Result<T, DecodeError>
    where
        T: Decode<'b, C>,
    {
        let mut sub = Decoder::new(self.bytes);
        T::decode(&mut sub, ctx)
    }
}
