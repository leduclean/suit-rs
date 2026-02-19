use cose_minicbor::cose::CoseSign1;
use cose_minicbor::keys::{CoseAlg, CoseKey, CoseKeySetBuilder, Curve, KeyType};

#[test]
fn test_suit_verify_sign1_es256_detached() {
    let mut cose_key_builder: CoseKeySetBuilder<100> =
        CoseKeySetBuilder::try_new().expect("valid builder");
    let mut key = CoseKey::new(KeyType::Ec2);
    key.alg(CoseAlg::ES256);
    key.crv(Curve::P256).unwrap();
    key.x(&hex_literal::hex!(
        "8496811aae0baaabd26157189eecda26beaa8bf11b6f3fe6e2b5659c85dbc0ad"
    ))
    .expect("X unvalid");
    key.y(&hex_literal::hex!(
        "3b1f2a4b6c098131c0a36dacd1d78bd381dcdfb09c052db33991db7338b4a896"
    ))
    .expect("Y unvalid");
    cose_key_builder.push_key(key).expect("Key Set is full");
    let key_bytes = cose_key_builder.into_bytes().expect("Bytes should be okay");

    let sign1_bytes = cbor_diag::parse_diag(include_str!("diags/sign1_es256.edn"))
        .unwrap()
        .to_bytes();
    let detached_payload_bytes = cbor_macro::cbo!(
        r#"[
                    / algorithm-id / -16 / "sha256" /,
                    / digest-bytes /
    h'6658ea560262696dd1f13b782239a064da7c6c5cbaf52fded428a6fc83c7e5af'
                ]"#
    );

    let sign1: CoseSign1 = minicbor::decode(&sign1_bytes).expect("Unvalid format for CoseSign1");
    sign1
        .suit_verify_cose_sign1(Some(&detached_payload_bytes), &key_bytes)
        .expect("Signature verification error");
}
