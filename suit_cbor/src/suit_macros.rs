#[macro_export]
/// Generate a lazy wrapper struct for CBOR arrays.
macro_rules! iter_wrapper {
    ($name:ident, $inner:ty) => {
        #[doc = concat!(
            "A lazy bytes wrapper over `",
            stringify!($inner),
            "`\n\n",
            "Use [`",stringify!($name),"::get()`] when you want to iterate over the array elements. ",
            "This wrapper keeps bytes borrowed and decodes elements lazily."
        )]
        #[derive(Debug, Encode, Decode)]
        #[cbor(transparent)]
        pub struct $name<'a>(#[cbor(borrow)] pub(crate) $crate::CborIter<'a, $inner>);

        impl<'a> $name<'a> {
            /// Give an Iterator over all array elements.
            ///
            /// This supports definite length arrays and uses the
            /// [`Decode`] trait to decode each element. *Only finite length array are supported*
            #[inline]
            #[allow(dead_code)]
            pub fn get(
                &self,
            ) -> Result<
                impl Iterator<Item = Result<$inner, $crate::errors::CborError>>,
                $crate::errors::CborError,
            > {
                self.0.get()
            }
        }
    };
}

#[macro_export]
/// Generate a bstr wrapper struct for `.bstr` CBOR struct
macro_rules! bstr_wrapper {
    ($name:ident, $inner:ty) => {
        #[doc = concat!(
            "A lazy wrapper for *bstr .cbor* `",
            stringify!($inner),
            "` encoded structure \n\n",
            "Use [`", stringify!($name), "::get()`] when you want to acces to the inner structure.",
        )]
        #[derive(Debug, Encode, Decode)]
        #[cbor(transparent)]
        pub struct $name<'a>(#[cbor(borrow)] pub(crate) $crate::BstrStruct<'a, $inner>);

        impl<'a> $name<'a> {
            /// Give the *bstr .cbor* inner structure
            ///
            /// It uses the [`Decode`] trait to *decode* the inner type and raises [`crate::errors::SuitError`]
            /// if failing to.
            #[inline]
            pub fn get(&self) -> Result<$inner, $crate::errors::CborError> {
                self.0.get()
            }

            /// Get the inner bytes of the bstr wrapper struct (without the bstr wrapper).
            #[inline]
            pub fn inner_bytes(&self) -> Result<&'a [u8], $crate::errors::CborError> {
                self.0.inner_bytes()
            }


            /// Get the raw bytes of bstr wrapped struct.
            #[inline]
            pub fn raw_bytes(&self) -> &'a [u8] {
                self.0.raw_bytes()

            }


        }


    };
}
