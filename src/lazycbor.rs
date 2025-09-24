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
        // Using OnceCell allows us to init the cache
        // without a &mut self reference (unsafe)
        let mut decoder = Decoder::new(self.bytes);
        T::decode(&mut decoder, &mut ())
    }
}
