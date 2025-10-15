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

mod tests {

    #[test]
    fn test_get_iter() {
        use super::*;
        use crate::suit_manifest::SuitComponentIdentifier;

        let components: cboritem::CborItem = cbor_macro::cbo!(
            r#"[[h'00'],
                    [h'02']
                    ]"#
        );
        let cbor_iter: CborIter<'_, SuitComponentIdentifier> = CborIter {
            bytes: &components,
            _marker: core::marker::PhantomData,
        };
        let mut compo_iter = cbor_iter.get().expect("Top level array");

        let first_id = compo_iter
            .next()
            .expect("Expected first component")
            .expect("Component decoding failed");
        let mut iter_first_id_slice = first_id.get().expect("Expected top-level array");
        let first_id_slice = iter_first_id_slice
            .next()
            .expect("Expected first identifier slice")
            .expect("Identifier slice decoding failed");

        let id1_bytes = cbor_macro::cbo!(r#"h'00'"#);
        let mut d1 = Decoder::new(&id1_bytes);

        assert_eq!(first_id_slice.as_ref(), d1.bytes().unwrap(),);
        assert!(iter_first_id_slice.next().is_none());

        let second_id = compo_iter
            .next()
            .expect("Expected second component")
            .expect("Component decoding failed");
        let mut iter_second_id_slice = second_id.get().expect("Expected top-level array");
        let second_id_slice = iter_second_id_slice
            .next()
            .expect("Expected first identifier slice")
            .expect("Identifier slice decoding failed");

        let id2_bytes = cbor_macro::cbo!(r#"h'02'"#);
        let mut d2 = Decoder::new(&id2_bytes);

        assert_eq!(second_id_slice.as_ref(), d2.bytes().unwrap());
        assert!(iter_second_id_slice.next().is_none());
        assert!(compo_iter.next().is_none());
    }
}
