use crate::flat_seq::FlatSequence;
use crate::suit_manifest::*;
use minicbor::{Encode, Encoder, encode::Error as EncodeError};

impl<Ctx> Encode<Ctx> for SuitReportingBits {
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        _: &mut Ctx,
    ) -> Result<(), EncodeError<W::Error>> {
        e.u8(self.bits())?;
        Ok(())
    }
}

impl<T, Ctx, const N: usize> Encode<Ctx> for CborVec<T, N>
where
    T: Encode<Ctx>,
{
    fn encode<W: minicbor::encode::Write>(
        &self,
        e: &mut Encoder<W>,
        ctx: &mut Ctx,
    ) -> Result<(), EncodeError<W::Error>> {
        e.array(self.0.len() as u64)?;
        for item in &self.0 {
            item.encode(e, ctx)?;
        }
        Ok(())
    }
}

impl<'a, C> Encode<C> for FlatSequence<'a> {
    fn encode<W: minicbor::encode::Write>(
        &self,
        _e: &mut minicbor::Encoder<W>,
        _ctx: &mut C,
    ) -> Result<(), minicbor::encode::Error<W::Error>> {
        // TODO
        Ok(())
    }
}
