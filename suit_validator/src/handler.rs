use crate::SuitError;
pub use crate::flat_seq::PairView;
use crate::suit_manifest::*;

pub trait SuitStartHandler {
    fn on_envelope<'a>(&mut self, envelope: SuitEnvelope<'a>) -> Result<(), SuitError>;
    fn on_manifest<'a>(&mut self, manifest: SuitManifest<'a>) -> Result<(), SuitError>;
}

pub trait SuitCommandHandler {
    fn on_conditions<'a>(
        &mut self,
        conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
    ) -> Result<(), SuitError>;
    fn on_directives<'a>(
        &mut self,
        directives: impl Iterator<Item = PairView<'a, SuitDirective<'a>>>,
    ) -> Result<(), SuitError>;
    fn on_customs<'a>(
        &mut self,
        customs: impl Iterator<Item = PairView<'a, CommandCustomValue<'a>>>,
    ) -> Result<(), SuitError>;
}

pub trait SuitSharedSequenceHandler {
    fn on_conditions<'a>(
        &mut self,
        conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
    ) -> Result<(), SuitError>;
    fn on_commands<'a>(
        &mut self,
        commands: impl Iterator<Item = PairView<'a, SuitSharedCommand<'a>>>,
    ) -> Result<(), SuitError>;
}
