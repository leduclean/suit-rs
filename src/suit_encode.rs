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
