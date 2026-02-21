#![no_std]
use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, KeyType};
use suit_validator::handler::*;
use suit_validator::{SuitError, suit_decode, suit_manifest::*};
struct DemoHandler;

impl SuitStartHandler for DemoHandler {
    fn on_envelope<'a>(&mut self, envelope: SuitEnvelope<'a>) -> Result<(), SuitError> {
        let manifest: SuitManifest = envelope.manifest.get()?;
        let common = manifest.common.get()?;
        let _shared_sequence = common.shared_seq.unwrap().get()?;
        let _validate_sequence = manifest.validate.unwrap().get()?;
        // Do something with shared sequence
        // Do something with validate_sequence
        Ok(())
    }
    fn on_manifest<'a>(&mut self, _manifest: SuitManifest<'a>) -> Result<(), SuitError> {
        // Do something with the manifest
        Ok(())
    }
}

fn main() -> Result<(), SuitError> {
    // raw byte of examples from ietf suit manifest
    let example1 = cbor_macro::cbo!(
        r#"107({
        / authentication-wrapper / 2:<< [
            / digest: / << [
                / algorithm-id / -16 / "sha256" /,
                / digest-bytes /
h'6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af'
            ] >>,
            / signature: / << 18([
                / protected / << {
                    / alg / 1:-7 / "ES256" /
                } >>,
                / unprotected / {
                },
                / payload / null / nil /,
                / signature / h'408d0816f9b510749bf6a51b066951e08a4438
f849eb092a1ac768eed9de696c1b1dd35d82ef149e6a73a61976ad2cfe78444b806429
3350a122f332cb49f0da'
            ]) >>
        ] >>,
        / manifest / 3:<< {
            / manifest-version / 1:1,
            / manifest-sequence-number / 2:0,
            / common / 3:<< {
                / components / 2:[
                    [h'00']
                ],
                / shared-sequence / 4:<< [
                    / directive-override-parameters / 20,{
                        / vendor-id /
1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-
be9d-e663e4d41ffe /,
                        / class-id /
2:h'1492af1425695e48bf429b2d51f2ab45' /
1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3:<< [
                            / algorithm-id / -16 / "sha256" /,
                            / digest-bytes /
h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ] >>,
                        / image-size / 14:34768
                    },
                    / condition-vendor-identifier / 1,15,
                    / condition-class-identifier / 2,15
                ] >>
            } >>,
            / validate / 7:<< [
                / condition-image-match / 3,15
            ] >>,
            / invoke / 9:<< [
                / directive-invoke / 23,2
            ] >>
        } >>
    })"#
    );

    let mut handler = DemoHandler;
    let mut key_set_builder: CoseKeySetBuilder<100> = CoseKeySetBuilder::try_new()?;
    let mut key = CoseKey::new(KeyType::Ec2);
    key.alg(CoseAlg::ES256P256);
    key.x(b"x coordinate")?;
    key.y(b"y coordinate")?;
    key_set_builder.push_key(key)?;
    let key_set_bytes = key_set_builder.into_bytes()?;

    suit_decode(&example1, &mut handler, &key_set_bytes)?;
    Ok(())
}
