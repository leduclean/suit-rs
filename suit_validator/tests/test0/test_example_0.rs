use cbor_diag::parse_diag;
use suit_validator::SuitError;
use suit_validator::handler::*;
use suit_validator::suit_manifest;

use crate::setup;

const VENDOR_ID_BYTES: &[u8] = &[
    0xfa, 0x6b, 0x4a, 0x53, 0xd5, 0xad, 0x5f, 0xdf, 0xbe, 0x9d, 0xe6, 0x63, 0xe4, 0xd4, 0x1f, 0xfe,
];

const CLASS_ID_BYTES: &[u8] = &[
    0x14, 0x92, 0xaf, 0x14, 0x25, 0x69, 0x5e, 0x48, 0xbf, 0x42, 0x9b, 0x2d, 0x51, 0xf2, 0xab, 0x45,
];

const DIGEST_BYTES: &[u8] = &[
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
];

const IMAGE_SIZE: u64 = 34768;

#[cfg(test)]
pub struct SharedSequenceHandler;
impl SuitSharedSequenceHandler for SharedSequenceHandler {
    fn on_commands<'a>(
        &mut self,
        commands: impl Iterator<Item = PairView<'a, suit_manifest::SuitSharedCommand<'a>>>,
    ) -> Result<(), SuitError> {
        let mut cmd_iter = commands;
        let first_cmd = cmd_iter.next().expect("First command missing");

        match first_cmd.get().expect("Unvalid Format for first_cmd") {
            suit_manifest::SuitSharedCommand::OverrideParameters(params) => {
                assert_eq!(
                    params.vendor_identifier.expect("Vendor identifier missing"),
                    VENDOR_ID_BYTES
                );
                assert_eq!(
                    params.class_identifier.expect("Class identifier missing"),
                    CLASS_ID_BYTES
                );
                assert_eq!(params.image_size.expect("Image size missing"), IMAGE_SIZE);

                // Check image digest
                let digest = params
                    .image_digest
                    .as_ref()
                    .expect("Image digest missing")
                    .get()
                    .expect("Failed to get image digest");
                assert!(matches!(digest.hash_alg, suit_manifest::HashAlg::Sha256));
                assert_eq!(digest.bytes, DIGEST_BYTES);
            }
            _ => panic!("Expected first command to be OverrideParameters"),
        }

        Ok(())
    }

    fn on_conditions<'a>(
        &mut self,
        conditions: impl Iterator<Item = PairView<'a, suit_manifest::SuitCondition>>,
    ) -> Result<(), SuitError> {
        let mut cond_iter = conditions;
        let first_cond = cond_iter
            .next()
            .expect("First condition missing")
            .get()
            .expect("Unvalid First Condition format");
        assert_eq!(first_cond.policy().bits(), 15);

        let second_cond = cond_iter
            .next()
            .expect("Second condition missing")
            .get()
            .expect("Unvalid Second Condition format");
        assert_eq!(second_cond.policy().bits(), 15);

        Ok(())
    }
}
#[cfg(test)]
pub struct ValidateHandler;

impl SuitCommandHandler for ValidateHandler {
    fn on_conditions<'a>(
        &mut self,
        conditions: impl Iterator<Item = PairView<'a, suit_manifest::SuitCondition>>,
    ) -> Result<(), SuitError> {
        let mut cond_iter = conditions;
        let first_condition = cond_iter
            .next()
            .expect("Expected at least one condition in validate command")
            .get()
            .unwrap();

        let policy = first_condition.policy();

        assert_eq!(
            policy.bits(),
            15,
            "Condition policy does not match expected validate policy"
        );

        Ok(())
    }

    fn on_directives<'a>(
        &mut self,
        directives: impl Iterator<Item = PairView<'a, suit_manifest::SuitDirective<'a>>>,
    ) -> Result<(), SuitError> {
        assert!(directives.peekable().peek().is_none());
        Ok(())
    }

    fn on_customs<'a>(
        &mut self,
        customs: impl Iterator<Item = PairView<'a, suit_manifest::CommandCustomValue<'a>>>,
    ) -> Result<(), SuitError> {
        assert!(customs.peekable().peek().is_none());
        Ok(())
    }
}

#[cfg(test)]
pub struct StartHandler;
impl SuitStartHandler for StartHandler {
    fn on_envelope<'a>(
        &mut self,
        envelope: suit_manifest::SuitEnvelope<'a>,
    ) -> Result<(), SuitError> {
        assert!(
            envelope.payload.is_none(),
            "Envelope payload should be None"
        );

        let manifest = envelope
            .manifest
            .get()
            .expect("Failed to get manifest from envelope");

        assert_eq!(manifest.version, 1, "Manifest version mismatch");
        assert_eq!(
            manifest.sequence_number, 0,
            "Manifest sequence number mismatch"
        );

        let common = manifest.common.get().expect("Failed to get common fields");
        let component = common
            .components
            .get()
            .expect("Valid Format")
            .next()
            .expect("Expected at least one component")
            .expect("Expected valid first component");
        assert_eq!(
            component
                .get()
                .expect("Valid Format")
                .next()
                .expect("Expected at least first slice")
                .expect("Expected valid first slice")
                .as_ref(),
            &[0]
        );

        // Dispatch the shared sequence handler
        let shared_seq = common
            .shared_seq
            .expect("Shared sequence missing")
            .get()
            .expect("Failed to get shared sequence");
        shared_seq.decode_and_dispatch(&mut SharedSequenceHandler)?;

        // Dispatch the validate handler
        let validate = manifest
            .validate
            .expect("Validate section missing")
            .get()
            .expect("Failed to get validate section");
        validate.decode_and_dispatch(&mut ValidateHandler)?;

        Ok(())
    }

    fn on_manifest<'a>(
        &mut self,
        _manifest: suit_manifest::SuitManifest<'a>,
    ) -> Result<(), SuitError> {
        panic!("Expected envelope, got manifest");
    }
}

#[test]
fn test_decode_example_0() {
    // Read CBOR test file
    let cbor_item = parse_diag(include_str!("example_0.edn")).unwrap();

    // Initialize key set
    let key_bytes = setup::get_keys();
    // Decode the SUIT manifest
    suit_validator::suit_decode(
        cbor_item.to_bytes().as_slice(),
        &mut StartHandler,
        key_bytes.as_ref(),
    )
    .expect("Decoding failed");
}
