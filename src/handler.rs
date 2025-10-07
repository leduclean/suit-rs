use crate::SuitError;
use crate::suit_manifest::*;

pub trait SuitStartHandler {
    fn on_envelope<'a>(&mut self, envelope: SuitEnvelope<'a>) -> Result<(), SuitError>;
    fn on_manifest<'a>(&mut self, manifest: SuitManifest<'a>) -> Result<(), SuitError>;
}

pub trait SuitCommandHandler {
    fn on_conditions(
        &mut self,
        conditions: impl Iterator<Item = Result<SuitCondition, SuitError>>,
    ) -> Result<(), SuitError>;
    fn on_directives<'a>(
        &mut self,
        directives: impl Iterator<Item = Result<SuitDirective<'a>, SuitError>>,
    ) -> Result<(), SuitError>;
    fn on_customs<'a>(
        &mut self,
        customs: impl Iterator<Item = Result<CommandCustomValue<'a>, SuitError>>,
    ) -> Result<(), SuitError>;
}

pub trait SuitSharedSequenceHandler {
    fn on_conditions(
        &mut self,
        conditions: impl Iterator<Item = Result<SuitCondition, SuitError>>,
    ) -> Result<(), SuitError>;
    fn on_commands<'a>(
        &mut self,
        commands: impl Iterator<Item = Result<SuitSharedCommand<'a>, SuitError>>,
    ) -> Result<(), SuitError>;
}
