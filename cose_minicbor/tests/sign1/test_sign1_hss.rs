use cose_minicbor::cose::CoseSign1;
use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, KeyType};

#[test]
fn test_suit_verify_sign1_hss_lms_attached() {
    let mut builder: CoseKeySetBuilder<100> = CoseKeySetBuilder::try_new().unwrap();
    let mut key = CoseKey::new(KeyType::HssLms);
    key.alg(CoseAlg::HSSLMS);

    // pub key from https://github.com/cose-wg/Examples/blob/53c9d634333bb4f529d78f5980fffa2667ee2c12/hashsig/hashsig-01.json
    key.k(&hex_literal::hex!("000000010000000600000003d08fabd4a2091ff0a8cb4ed834e7453432a58885cd9ba0431235466bff9651c6c92124404d45fa53cf161c28f1ad5a8e")).unwrap();
    key.kid(b"ItsBig");
    builder.push_key(key).unwrap();
    let key_set_bytes = builder.into_bytes().unwrap();
    let sign1_bytes = cbor_diag::parse_diag(include_str!("diags/sign1_hss_lms.edn"))
        .unwrap()
        .to_bytes();
    let sign1: CoseSign1 = minicbor::decode(&sign1_bytes).expect("Unvalid format for CoseSign1");
    sign1
        .suit_verify_cose_sign1(None, &key_set_bytes)
        .expect("Signature verification error");
}
