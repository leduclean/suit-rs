use cose_minicbor::cose::CoseMac;
use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, KeyOp, KeyType};

#[test]
fn test_suit_verify_hmac_a256kw() {
    let mut builder: CoseKeySetBuilder<200> = CoseKeySetBuilder::try_new().unwrap();

    // KEK key for A256 KW
    let mut key = CoseKey::new(KeyType::Symmetric);
    key.alg(CoseAlg::A256KW);
    key.k(&hex_literal::hex!(
        "849b57219dae48de646d07dbb533566e976686457c1491be3a76dcea6c427188"
    ))
    .unwrap();
    key.kid(b"018c0ae5-4d9b-471b-bfd6-eef314bc7037");
    key.key_op(KeyOp::UnwrapKey);

    builder.push_key(key).unwrap();
    let key_set_bytes = builder.into_bytes().unwrap();
    let mac_bytes = cbor_diag::parse_diag(include_str!("diags/mac_hs256_a256kw.edn"))
        .unwrap()
        .to_bytes();
    let mac: CoseMac = minicbor::decode(&mac_bytes).expect("Unvalid format for CoseSign1");
    mac.suit_verify_mac(None, &key_set_bytes)
        .expect("Signature verification error");
}
