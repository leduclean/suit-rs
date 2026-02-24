use crate::SuitError;
pub use crate::flat_seq::PairView;
use crate::suit_manifest::*;

/// Handler trait to treat the Starting structure ([SuitEnvelope] or [SuitManifest]).
///
/// It's easier and quicker to directly use the [GenericStartHandler].
pub trait SuitStartHandler {
    fn on_envelope<'a>(&mut self, envelope: SuitEnvelope<'a>) -> Result<(), SuitError>;
    fn on_manifest<'a>(&mut self, manifest: SuitManifest<'a>) -> Result<(), SuitError>;
}

/// Handler trait to treat a SuitCommand Sequence.
/// You can specify the comportement for each
/// [SuitCommandSequence] type ([SuitCondition], [SuitDirective], [CommandCustomValue]).
///
/// This handler will be lazy applicated to the corresponding variant.
/// If you wanna customize the behaviour with [PairView] inspection
/// before decoding it you can implement this trait by yourself.
///
/// Else if you wnat a generic handler you can directly use the [GenericCommandHandler].
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

/// Handler trait to treat a SuitShareCommand Sequence.
/// You can specify the comportement for each
/// [SuitCommandSequence] type ([SuitCondition], [SuitDirective]).
///
/// This handler will be lazy applicated to the corresponding variant.
/// If you wanna customize the behaviour with [PairView] inspection
/// before decoding it you can implement this trait by yourself.
///
/// Else if you wnat a generic handler you can directly use the [GenericSharedSequenceHandler].
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

/// Generic Handler to handle the starting structure ([SuitManifest] or [SuitEnvelope]).
///
/// * `on_envelope`: Handling function to apply on the envelope.
/// * `on_manifest`: Handling function to apply on the manifest.
pub struct GenericStartHandler<FEnv, FManif>
where
    FEnv: Fn(&SuitEnvelope),
    FManif: Fn(&SuitManifest),
{
    pub on_envelope: FEnv,
    pub on_manifest: FManif,
}

impl<FEnv, FManif> SuitStartHandler for GenericStartHandler<FEnv, FManif>
where
    FEnv: Fn(&SuitEnvelope),
    FManif: Fn(&SuitManifest),
{
    fn on_envelope<'a>(&mut self, envelope: SuitEnvelope<'a>) -> Result<(), SuitError> {
        (self.on_envelope)(&envelope);
        Ok(())
    }

    fn on_manifest<'a>(&mut self, manifest: SuitManifest<'a>) -> Result<(), SuitError> {
        (self.on_manifest)(&manifest);
        Ok(())
    }
}

/// Generic handler for the [SuitCommandSequence] structure.
///
/// NOTE: If you want a more customizable behaviour, you should use the
/// [SuitCommandHandler] trait directly and speciey behaviour with inspection.
///
/// * `on_cond`: Handling function applied to each of the [SuitCondition].
/// * `on_dir`: Handling function applied to each of the [SuitDirective].
/// * `on_custom`: Handling function applied to each of the [CommandCustomValue].
pub struct GenericCommandHandler<FCond, FDir, FCustom>
where
    FCond: Fn(&SuitCondition),
    FDir: Fn(&SuitDirective),
    FCustom: Fn(&CommandCustomValue),
{
    on_cond: FCond,
    on_dir: FDir,
    on_custom: FCustom,
}

impl<FCond, FDir, FCustom> SuitCommandHandler for GenericCommandHandler<FCond, FDir, FCustom>
where
    FCond: Fn(&SuitCondition),
    FDir: Fn(&SuitDirective),
    FCustom: Fn(&CommandCustomValue),
{
    fn on_conditions<'a>(
        &mut self,
        conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
    ) -> Result<(), SuitError> {
        for cond in conditions {
            (self.on_cond)(&cond.get()?);
        }
        Ok(())
    }

    fn on_directives<'a>(
        &mut self,
        directives: impl Iterator<Item = PairView<'a, SuitDirective<'a>>>,
    ) -> Result<(), SuitError> {
        for dir in directives {
            (self.on_dir)(&dir.get()?);
        }
        Ok(())
    }

    fn on_customs<'a>(
        &mut self,
        customs: impl Iterator<Item = PairView<'a, CommandCustomValue<'a>>>,
    ) -> Result<(), SuitError> {
        for c in customs {
            (self.on_custom)(&c.get()?);
        }
        Ok(())
    }
}

/// Generic handler for the [SuitSharedSequence] structure.
///
/// NOTE: If you want a more customizable behaviour, you should implement your own
/// [SuitSharedSequenceHandler] trait directly and specify behaviour with inspection.
///
/// * `on_cond`: Handling function applied to each of the [SuitCondition].
/// * `on_com`: Handling function applied to each of the [SuitSharedCommand].
pub struct GenericSharedSequenceHandler<FCond, FCom>
where
    FCond: Fn(&SuitCondition),
    FCom: Fn(&SuitSharedCommand),
{
    on_cond: FCond,
    on_com: FCom,
}

impl<FCond, FCom> SuitSharedSequenceHandler for GenericSharedSequenceHandler<FCond, FCom>
where
    FCond: Fn(&SuitCondition),
    FCom: Fn(&SuitSharedCommand),
{
    fn on_conditions<'a>(
        &mut self,
        conditions: impl Iterator<Item = PairView<'a, SuitCondition>>,
    ) -> Result<(), SuitError> {
        for cond in conditions {
            (self.on_cond)(&cond.get()?);
        }
        Ok(())
    }

    fn on_commands<'a>(
        &mut self,
        customs: impl Iterator<Item = PairView<'a, SuitSharedCommand<'a>>>,
    ) -> Result<(), SuitError> {
        for c in customs {
            (self.on_com)(&c.get()?);
        }
        Ok(())
    }
}
