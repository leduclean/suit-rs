//! This file ensure the IETF failure spec is
//! respected on different corner case.
//!
//! We use this example [example1](https://datatracker.ietf.org/doc/html/draft-ietf-suit-manifest#name-example-1-simultaneous-down)
//! as an initial valid manifest and then we inject some problems to check if the parser return the right errors.

use cbor_diag::parse_diag;
use suit_validator::suit_decode;

const MANIFEST_TEMPLATE: &str = r#"
107({
        / authentication-wrapper / 2:<< [
            / digest: / << [
                / algorithm-id / __AUTH_ALG__ / "sha256" /,
                / digest-bytes /
h'__DIGEST__'
            ] >>,
            / signature: / << 18([
                / protected / << {
                    / alg / 1:-7 / "ES256" /
                } >>,
                / unprotected / {
                },
                / payload / null / nil /,
                / signature / h'__SIGNATURE__'
            ]) >>
        ] >>,
        / manifest / 3:<< {
            / manifest-version / 1:__VERSION__,
            / manifest-sequence-number / 2:1,
            / common / 3:<< {
                / components / 2:[
                    __COMPONENTS__
                ],
                / shared-sequence / 4:<< [
                    __SHARED_SEQ_BODY__
                ] >>
            } >>,
            / validate / 7:<< [
                / condition-image-match / 3,__POLICY_VALIDATE__
            ] >>,
            / install / 20:<< [
                / directive-override-parameters / 20,{
                    / uri / 21:"__INSTALL_URI__"
                },
                / directive-fetch / 21,__FETCH_PARAM__,
                / condition-image-match / 3,__POLICY_INSTALL__
            ] >>
        } >>
    })"#;

const DEFAULT_AUTH_ALG: i32 = -16;
const DEFAULT_DIGEST: &str = "1f2e7acca0dc2786f2fe4eb947f50873a6a3cfaa98866c5b02e621f42074daf2";
const DEFAULT_SIGNATURE: &str = "27a3d7986eddcc1bee04e1436746408c308ed3c15ac590a1ca0cf96f85671ccac216cb9a1497fc59e21c15f33c95cf75203e25c287b31a57d6cd2ef950b27a7a";
const DEFAULT_VERSION: u64 = 1;
const DEFAULT_COMPONENTS: &str = "[ [h'00'] ]"; // placed inside the components array
const DEFAULT_SHARED_SEQ_BODY: &str = r#"
                    / directive-override-parameters / 20,{
                        / vendor-id /
1:h'fa6b4a53d5ad5fdfbe9de663e4d41ffe' / fa6b4a53-d5ad-5fdf-be9d-e663e4d41ffe /,
                        / class-id /
2:h'1492af1425695e48bf429b2d51f2ab45' / 1492af14-2569-5e48-bf42-9b2d51f2ab45 /,
                        / image-digest / 3:<< [
                            / algorithm-id / -16 / "sha256" /,
                            / digest-bytes /
h'00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210'
                        ] >>,
                        / image-size / 14:34768
                    },
                    / condition-vendor-identifier / 1,15,
                    / condition-class-identifier / 2,15
                "#;
const DEFAULT_IMAGE_DIGEST: &str =
    "00112233445566778899aabbccddeeff0123456789abcdeffedcba9876543210";
const DEFAULT_IMAGE_SIZE: u64 = 34768;
const DEFAULT_POLICY_VALIDATE: u8 = 15;
const DEFAULT_INSTALL_URI: &str = "http://example.com/file.bin";
const DEFAULT_FETCH_PARAM: u64 = 2;
const DEFAULT_POLICY_INSTALL: u8 = 15;

/// ManifestChange : modifications que tu peux appliquer **
#[derive(Clone, Debug)]
pub enum ManifestChange {
    Version(u64),
    AuthAlg(i32),
    Digest(&'static str),
    // Shared seq / components
    EmptySharedSequence,
    EmptyComponents,
    // image
    RemoveImageSize,
    // vendor/class
    VendorIdTooLong(&'static str),
    // policies
    PolicyValidate(u8),
    PolicyInstall(u8),
    // install
    RemoveInstallUri,
    // signature
    BadSignature,
}

/// Builder to apply the changes.
///
/// * `changes`: changes to make.
pub fn build_manifest_bytes_with_changes(changes: &[ManifestChange]) -> Vec<u8> {
    // defaults
    let mut auth_alg = DEFAULT_AUTH_ALG;
    let mut digest = DEFAULT_DIGEST.to_string();
    let mut signature = DEFAULT_SIGNATURE.to_string();
    let mut version = DEFAULT_VERSION;
    let mut components = DEFAULT_COMPONENTS.to_string();
    let mut shared_seq_body = DEFAULT_SHARED_SEQ_BODY.to_string();
    let image_digest = DEFAULT_IMAGE_DIGEST.to_string();
    let image_size = DEFAULT_IMAGE_SIZE;
    let mut policy_validate = DEFAULT_POLICY_VALIDATE;
    let install_uri = DEFAULT_INSTALL_URI.to_string();
    let fetch_param = DEFAULT_FETCH_PARAM;
    let mut policy_install = DEFAULT_POLICY_INSTALL;

    // vendor/class default inside shared_seq body: we'll replace by simple string replacement
    let mut vendor_id = "fa6b4a53d5ad5fdfbe9de663e4d41ffe".to_string();
    let class_id = "1492af1425695e48bf429b2d51f2ab45".to_string();

    // flags
    let mut should_remove_image_size = false;
    let mut should_remove_install_uri = false;

    // apply changes
    for c in changes {
        match c {
            ManifestChange::Version(v) => version = *v,
            ManifestChange::AuthAlg(a) => auth_alg = *a,
            ManifestChange::Digest(d) => digest = d.to_string(),
            ManifestChange::EmptySharedSequence => shared_seq_body = String::new(),
            ManifestChange::EmptyComponents => components = String::from(""),
            ManifestChange::RemoveImageSize => should_remove_image_size = true,
            ManifestChange::VendorIdTooLong(v) => vendor_id = v.to_string(),
            ManifestChange::PolicyValidate(p) => policy_validate = *p,
            ManifestChange::PolicyInstall(p) => policy_install = *p,
            ManifestChange::RemoveInstallUri => should_remove_install_uri = true,
            ManifestChange::BadSignature => signature = "00".to_string(),
        }
    }

    // prepare shared_seq_body by injecting vendor/class/image_digest/image_size placeholders
    // we replace the default tokens inside DEFAULT_SHARED_SEQ_BODY when present; but because DEFAULT_SHARED_SEQ_BODY
    // is a big string we've assigned above, we'll craft the actual shared_seq_body string:
    if shared_seq_body.is_empty() {
        // produce exactly an empty shared sequence content (so template becomes 4:<< [  ] >>)
        shared_seq_body = String::new();
    } else {
        // construct the standard inner block using (possibly modified) vendor_id/class_id/image_digest/image_size
        // keep the same formatting as the sample
        shared_seq_body = format!(
            r#"
                    / directive-override-parameters / 20,{{
                        / vendor-id /
1:h'{vendor_id}' / {vendor_id} /,
                        / class-id /
2:h'{class_id}' / {class_id} /,
                        / image-digest / 3:<< [
                            / algorithm-id / -16 / "sha256" /,
                            / digest-bytes /
h'{image_digest}'
                        ] >>,
                        / image-size / 14:{image_size}
                    }},
                    / condition-vendor-identifier / 1,15,
                    / condition-class-identifier / 2,15
                "#
        );
    }

    // components string
    let components_str = if components.is_empty() {
        // empty components -> produce an empty list
        String::from("")
    } else {
        components
    };

    // Build diag and apply simple replacements
    let mut diag = MANIFEST_TEMPLATE
        .replace("__AUTH_ALG__", &auth_alg.to_string())
        .replace("__DIGEST__", &digest)
        .replace("__SIGNATURE__", &signature)
        .replace("__VERSION__", &version.to_string())
        .replace("__COMPONENTS__", &components_str)
        .replace("__SHARED_SEQ_BODY__", &shared_seq_body)
        .replace("__IMAGE_DIGEST__", &image_digest)
        .replace("__IMAGE_SIZE__", &image_size.to_string())
        .replace("__POLICY_VALIDATE__", &policy_validate.to_string())
        .replace("__INSTALL_URI__", &install_uri)
        .replace("__FETCH_PARAM__", &fetch_param.to_string())
        .replace("__POLICY_INSTALL__", &policy_install.to_string());

    if should_remove_image_size {
        diag = diag.replace(
            "/ image-size / 14:__IMAGE_SIZE__",
            "/ image-size / null / nil /",
        );
    }
    if should_remove_install_uri {
        diag = diag.replace("/ uri / 21:\"__INSTALL_URI__\"", "/ uri / null / nil /");
    }

    // parse diag -> bytes (panic on parse error to surface template mistakes quickly)
    parse_diag(&diag)
        .unwrap_or_else(|_| panic!("template diag must parse\n---diag---\n{diag}"))
        .to_bytes()
}

pub fn build_manifest_bytes_with_change(change: ManifestChange) -> Vec<u8> {
    build_manifest_bytes_with_changes(&[change])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::setup::MockCrypto;
    use suit_validator::handler::GenericStartHandler;

    // 1. version != 1
    #[test]
    fn manifest_bad_version_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::Version(2));
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for bad version"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 2. digest algorithm unsupported (auth digest alg -> shake128 = -18)
    #[test]
    fn manifest_unsupported_digest_alg_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::AuthAlg(-18)); // Shake128
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for unsupported digest alg"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 3. digest incorrect (different bytes)
    #[test]
    fn manifest_bad_digest_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::Digest("deadbeef"));
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for bad digest"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 4. signature invalid
    #[test]
    fn manifest_bad_signature_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::BadSignature);
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for bad signature"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 5. empty shared-sequence (no commands/conditions)
    #[test]
    fn manifest_empty_shared_sequence_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::EmptySharedSequence);
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for empty shared sequence"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        // decode should fail because shared sequence must have at least one pair
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 6. components empty -> invalid (components must have at least one)
    #[test]
    fn manifest_empty_components_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::EmptyComponents);
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for empty components"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 7. remove image-size while image-digest present -> spec requires image-size when image-digest present
    #[test]
    fn manifest_missing_image_size_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::RemoveImageSize);
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for missing image size"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 8. vendor id too long ( > 16 bytes ) -> decoding of UUID should fail
    #[test]
    fn manifest_vendor_id_too_long_should_fail() {
        // 17 bytes hex (34 hex chars)
        let long_vendor = "00112233445566778899aabbccddeeff00";
        let bytes = build_manifest_bytes_with_change(ManifestChange::VendorIdTooLong(long_vendor));
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for long vendor id"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 9. policy invalid (use 255)
    #[test]
    fn manifest_policy_invalid_should_fail() {
        let bytes = build_manifest_bytes_with_changes(&[
            ManifestChange::PolicyValidate(255),
            ManifestChange::PolicyInstall(255),
        ]);
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for invalid policy"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 10. install without URI
    #[test]
    fn manifest_install_without_uri_should_fail() {
        let bytes = build_manifest_bytes_with_change(ManifestChange::RemoveInstallUri);
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for install without uri"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }

    // 11. combined case: bad digest + bad signature
    #[test]
    fn manifest_bad_digest_and_signature_should_fail() {
        let bytes = build_manifest_bytes_with_changes(&[
            ManifestChange::Digest("deadbeef"),
            ManifestChange::BadSignature,
        ]);
        let mut handler = GenericStartHandler {
            on_envelope: |_env| panic!("Should not reach handler for bad manifest"),
            on_manifest: |_manif| panic!("Should not happend since we are decoding an envelop"),
        };
        assert!(suit_decode(&bytes, &mut handler, &mut MockCrypto).is_err());
    }
}
