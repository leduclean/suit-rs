use cose_minicbor::cose::CoseMac;
use cose_minicbor::cose_keys::{CoseAlg, CoseKey, CoseKeySetBuilder, KeyOp, KeyType};

#[test]
fn test_suit_verify_hmac_a128kw() {
    let mut builder: CoseKeySetBuilder<200> = CoseKeySetBuilder::try_new().unwrap();

    // KEK key for A128 KW (it uses the key from previous example as CEK)
    let mut key = CoseKey::new(KeyType::Symmetric);
    key.alg(CoseAlg::A128KW);
    key.k(&hex_literal::hex!("c1e60d0db5c6cbdac37e8473b412f6b0"))
        .unwrap();
    key.kid(b"our-secret");
    key.key_op(KeyOp::UnwrapKey);

    builder.push_key(key).unwrap();
    let key_set_bytes = builder.into_bytes().unwrap();
    let mac_bytes = cbor_diag::parse_diag(include_str!("diags/mac_hs256_a128kw.edn"))
        .unwrap()
        .to_bytes();
    let mac: CoseMac = minicbor::decode(&mac_bytes).expect("Unvalid format for CoseSign1");
    mac.suit_verify_mac(None, &key_set_bytes)
        .expect("Signature verification error");
}
