use cose_minicbor::cose::CoseMac0;
use cose_minicbor::keys::{CoseAlg, CoseKey, CoseKeySetBuilder, KeyType};

#[test]
fn test_suit_verify_mac0() {
    let mut builder: CoseKeySetBuilder<200> = CoseKeySetBuilder::try_new().unwrap();
    let mut key = CoseKey::new(KeyType::Symmetric);
    key.alg(CoseAlg::HMAC256256);

    // sym key from https://github.com/cose-wg/Examples/blob/53c9d634333bb4f529d78f5980fffa2667ee2c12/hmac-examples/HMac-enc-01.json
    key.k(&hex_literal::hex!(
        "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"
    ))
    .unwrap();
    key.kid(b"our-secret");
    builder.push_key(key).unwrap();

    let key_set_bytes = builder.into_bytes().unwrap();
    let mac1_bytes = cbor_diag::parse_diag(include_str!("diags/mac0_hs256.edn"))
        .unwrap()
        .to_bytes();
    let mac: CoseMac0 = minicbor::decode(&mac1_bytes).expect("Unvalid format for CoseSign1");
    mac.suit_verify_mac0(None, &key_set_bytes)
        .expect("Signature verification error");
}
