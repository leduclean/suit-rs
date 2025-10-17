macro_rules! iter_wrapper {
    // Optionnal validator
    ($name:ident, $inner:ty $(, $validator:path)? ) => {
        iter_wrapper!(@impl $name, $inner $(, $validator)? );
    };

    // internal: case without validator
    (@impl $name:ident, $inner:ty) => {
        #[doc = concat!(
            "A lazy bytes wrapper over `",
            stringify!($inner),
            "`\n\n",
            "Use [`",stringify!($name),"::get()`] when you want to iterate over the array elements. ",
            "This wrapper keeps bytes borrowed and decodes elements lazily."
        )]
        #[derive(Debug, Encode, Decode)]
        #[cbor(transparent)]
        pub struct $name<'a>(#[cbor(borrow)] pub(crate) crate::cbor_iter::CborIter<'a, $inner>);

        impl<'a> $name<'a> {
            #[inline]
            pub fn get(
                &self,
            ) -> Result<impl Iterator<Item = Result<$inner, crate::errors::SuitError>>, crate::errors::SuitError> {
                self.0.get()
            }
        }
    };

    (@impl $name:ident, $inner:ty, $validator:path) => {
        #[doc = concat!(
            "A lazy bytes wrapper over `",
            stringify!($inner),
            "`\n\n",
            "Use [`",stringify!($name),"::get()`] when you want to iterate over the array elements. ",
            "This wrapper keeps bytes borrowed and decodes elements lazily."
        )]
        #[derive(Debug, Encode)]
        #[cbor(transparent)]
        pub struct $name<'a>(#[cbor(borrow)] pub(crate) crate::cbor_iter::CborIter<'a, $inner>);

        impl<'a> $name<'a> {
            #[inline]
            pub fn get(
                &self,
            ) -> Result<impl Iterator<Item = Result<$inner, crate::errors::SuitError>>, crate::errors::SuitError> {
                self.0.get()
            }
        }

        impl<'a, 'bytes: 'a, Ctx> minicbor::Decode<'bytes, Ctx> for $name<'a> {
            fn decode(d: &mut minicbor::Decoder<'bytes>, ctx: &mut Ctx) -> Result<Self, minicbor::decode::Error> {
                // We call the validator on a probe which is basically a view of the current decoder bytes
                $validator(&mut d.probe())?;
                Ok($name(minicbor::Decode::decode(d, ctx)?))
            }
        }
    };
}

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
        pub struct $name<'a>(#[cbor(borrow)] pub(crate) BstrStruct<'a, $inner>);

        impl<'a> $name<'a> {
            /// Give the *bstr .cbor* inner structure
            ///
            /// It uses the [`Decode`] trait to *decode* the inner type and raises [`crate::errors::SuitError`]
            /// if failing to.
            #[inline]
            pub fn get(&self) -> Result<$inner, SuitError> {
                self.0.get()
            }
        }
    };
}
