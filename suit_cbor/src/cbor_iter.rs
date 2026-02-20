use crate::errors::CborError;
use core::marker::PhantomData;
use minicbor::data::Type;
use minicbor::decode::Error as DecodeError;
use minicbor::{Decode, Decoder, Encode};

/// A lazily decoded CBOR array wrapper.
///
/// `CborIter<T>` stores the raw CBOR bytes of an array without decoding
/// its elements immediately.
///
/// Instead of eagerly decoding the full array, it allows deferred,
/// element-by-element decoding via [`CborIter::get()`].
///
///
/// # Behavior
///
/// - The outer CBOR array is not decoded at construction time.
/// - The raw encoded bytes are preserved.
/// - Calling [`CborIter::get()`] returns an iterator that lazily decodes each element.
/// - Both definite and indefinite-length arrays are supported.
///
/// # Example
///
/// ```rust
/// use minicbor::Decode;
/// use suit_cbor::CborIter;
/// use suit_cbor::errors::CborError;
///
/// #[derive(Decode)]
/// struct Item {
///     #[n(0)]
///     value: u8,
/// }
///
/// # fn example(data: &[u8]) -> Result<(), CborError> {
/// let iter: CborIter<Item> = minicbor::decode(data)?;
///
/// for element in iter.get()? {
///     let item = element?;
///     // process item
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct CborIter<'b, T> {
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
    /// Returns a lazy iterator over the decoded array elements.
    ///
    /// The iterator:
    /// - Decodes elements one by one.
    /// - Stops automatically at the end of the array.
    /// - Handles both definite and indefinite-length CBOR arrays.
    ///
    /// Each iteration yields `Result<T, CborError>`.
    ///
    /// Decoding errors are propagated per element.
    pub fn get(&self) -> Result<impl Iterator<Item = Result<T, CborError>>, CborError> {
        let mut d = Decoder::new(self.bytes);
        match d.array()? {
            Some(len) => Ok(ArrayIter {
                decoder: d,
                remaining: Some(len),
                _mark: core::marker::PhantomData,
            }),
            None => {
                // indefinite: keep decoder and mark remaining = None
                Ok(ArrayIter {
                    decoder: d,
                    remaining: None,
                    _mark: core::marker::PhantomData,
                })
            }
        }
    }
}

/// Internal iterator implementation for [`CborIter`].
///
/// Handles:
/// - Definite-length arrays (tracked via `remaining`)
/// - Indefinite-length arrays (detected via CBOR break marker)
///
/// This type is not exposed publicly.
struct ArrayIter<'b, T> {
    decoder: Decoder<'b>,
    remaining: Option<u64>,
    _mark: core::marker::PhantomData<&'b T>,
}

impl<'b, T: Decode<'b, ()>> Iterator for ArrayIter<'b, T> {
    type Item = Result<T, CborError>;

    fn next(&mut self) -> Option<Self::Item> {
        // definite
        if let Some(ref mut n) = self.remaining {
            if *n == 0 {
                return None;
            }
            *n -= 1;
            return Some(T::decode(&mut self.decoder, &mut ()).map_err(|e| e.into()));
        }

        // indefinite: need to check for break
        match self.decoder.datatype() {
            Ok(Type::Break) => {
                // consume the break and end iteration
                if let Err(e) = self.decoder.skip() {
                    Some(Err(e.into()))
                } else {
                    None
                }
            }
            Ok(_) => Some(T::decode(&mut self.decoder, &mut ()).map_err(|e| e.into())),
            Err(e) => Some(Err(e.into())),
        }
    }
}

impl<'a, C, T> Encode<C> for CborIter<'a, T> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        _e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        // TODO
        Ok(())
    }
}

mod tests {
    use super::CborIter;
    use minicbor::Decode;
    use minicbor::bytes::ByteSlice;

    #[derive(Decode, Debug)]
    #[cbor(transparent)]
    #[allow(unused)]
    pub struct Test<'a>(#[cbor(borrow)] CborIter<'a, &'a ByteSlice>);

    #[test]
    fn test_get_iter() {
        let test_bytes: cboritem::CborItem = cbor_macro::cbo!(
            r#"[[h'00'],
                    [h'02']
                    ]"#
        );
        let cbor_iter: CborIter<'_, Test> = minicbor::decode(&test_bytes).unwrap();
        let mut test_iter = cbor_iter.get().expect("Top level array");

        let test1 = test_iter
            .next()
            .expect("Expected first component")
            .expect("Component decoding failed");
        let mut iter_test1_slice = test1.0.get().expect("Expected top-level array");
        let test1_slice = iter_test1_slice
            .next()
            .expect("Expected first identifier slice")
            .expect("Identifier slice decoding failed");

        let test1_bytes = cbor_macro::cbo!(r#"h'00'"#);
        let mut d1 = minicbor::decode::Decoder::new(&test1_bytes);

        assert_eq!(test1_slice.as_ref(), d1.bytes().unwrap(),);
        assert!(iter_test1_slice.next().is_none());

        let test2 = test_iter
            .next()
            .expect("Expected second component")
            .expect("Component decoding failed");
        let mut iter_test2_slice = test2.0.get().expect("Expected top-level array");
        let test2_slice = iter_test2_slice
            .next()
            .expect("Expected first identifier slice")
            .expect("Identifier slice decoding failed");

        let test2_bytes = cbor_macro::cbo!(r#"h'02'"#);
        let mut d2 = minicbor::decode::Decoder::new(&test2_bytes);

        assert_eq!(test2_slice.as_ref(), d2.bytes().unwrap());
        assert!(iter_test2_slice.next().is_none());
        assert!(test_iter.next().is_none());
    }

    #[test]
    fn test_indefinite_array() {
        // 0x9F = indefinite array start, 0x01,0x02,0x03 elements, 0xFF break
        let data: &[u8] = &[0x9F, 0x01, 0x02, 0x03, 0xFF];
        let iter: CborIter<'_, u8> = minicbor::decode(&data).unwrap();
        let mut iter = iter.get().unwrap();
        let mut expected = [1, 2, 3];
        for exp in expected.iter_mut() {
            let val = iter.next().unwrap().unwrap();
            assert_eq!(val, *exp);
        }
        assert!(iter.next().is_none());
    }

    #[test]
    fn test_empty_array() {
        let data = cbor_macro::cbo!(r#"[]"#);
        let iter: CborIter<'_, &'_ ByteSlice> = minicbor::decode(&data).unwrap();
        let mut it = iter.get().unwrap();
        assert!(it.next().is_none());
    }
}
