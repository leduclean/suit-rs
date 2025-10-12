use crate::SuitError;
use core::marker::PhantomData;
use minicbor::decode::Error as DecodeError;
use minicbor::{Decode, Decoder};

#[derive(Debug)]
pub(crate) struct CborIter<'b, T> {
    bytes: &'b [u8],
    _marker: PhantomData<&'b T>,
}

impl<'b, T, Ctx> Decode<'b, Ctx> for CborIter<'b, T> {
    fn decode(d: &mut Decoder<'b>, _ctx: &mut Ctx) -> Result<Self, DecodeError> {
        let start = d.position();
        let input = d.input();
        // We advance the main decoder to the next element
        d.skip()?;

        let end = d.position();
        let inner = &input[start..end];
        Ok(CborIter {
            bytes: inner,
            _marker: PhantomData,
        })
    }
}

impl<'b, T> CborIter<'b, T>
where
    T: Decode<'b, ()>,
{
    pub(crate) fn get(&self) -> Result<impl Iterator<Item = Result<T, SuitError>>, SuitError> {
        let mut d = Decoder::new(self.bytes);
        if let Some(len) = d.array()? {
            Ok(ArrayIter {
                decoder: d,
                remaining: len,
                _mark: core::marker::PhantomData,
            })
        } else {
            Err(SuitError::indefinite_length())
        }
    }
}

struct ArrayIter<'b, T> {
    decoder: Decoder<'b>,
    remaining: u64,
    _mark: core::marker::PhantomData<&'b T>,
}

impl<'b, T: Decode<'b, ()>> Iterator for ArrayIter<'b, T> {
    type Item = Result<T, SuitError>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.remaining {
            0 => None,
            n => {
                self.remaining = n - 1;
                Some(T::decode(&mut self.decoder, &mut ()).map_err(|e| e.into()))
            }
        }
    }
}
