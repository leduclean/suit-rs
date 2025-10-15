macro_rules! iter_wrapper {
    ($name:ident, $inner:ty) => {
        #[derive(Debug, Encode, Decode)]
        #[cbor(transparent)]
        pub struct $name<'a>(#[cbor(borrow)] pub(crate) crate::cbor_iter::CborIter<'a, $inner>);

        impl<'a> $name<'a> {
            #[inline]
            pub fn get(
                &self,
            ) -> Result<
                impl Iterator<Item = Result<$inner, crate::errors::SuitError>>,
                crate::errors::SuitError,
            > {
                self.0.get()
            }
        }
    };
}

macro_rules! bstr_wrapper {
    ($name:ident, $inner:ty) => {
        #[derive(Debug, Encode, Decode)]
        #[cbor(transparent)]
        pub struct $name<'a>(#[cbor(borrow)] pub(crate) BstrStruct<'a, $inner>);

        impl<'a> $name<'a> {
            #[inline]
            pub fn get(&self) -> Result<$inner, SuitError> {
                self.0.get()
            }
        }
    };
}
