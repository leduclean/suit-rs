use cose_minicbor::cose::CoseSign;
use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, Curve, KeyType};

#[test]
fn test_suit_verify_sign_ed25519() {
    let mut builder: CoseKeySetBuilder<100> = CoseKeySetBuilder::try_new().unwrap();
    let mut key = CoseKey::new(KeyType::Okp);
    key.alg(CoseAlg::ED25519);
    key.crv(Curve::Ed25519).unwrap();
    // pub key from https://github.com/cose-wg/Examples/blob/53c9d634333bb4f529d78f5980fffa2667ee2c12/eddsa-examples/eddsa-01.json
    key.x(&hex_literal::hex!(
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    ))
    .unwrap();
    key.kid(b"11");
    builder.push_key(key).unwrap();
    let key_set_bytes = builder.into_bytes().unwrap();
    let sign_bytes = cbor_diag::parse_diag(include_str!("diags/sign_ed25519.edn"))
        .unwrap()
        .to_bytes();
    let sign1: CoseSign = minicbor::decode(&sign_bytes).expect("Unvalid format for CoseSign1");
    sign1
        .suit_verify_cose_sign(None, &key_set_bytes)
        .expect("Signature verification error");
}
