use cose_minicbor::cose::CoseMac;
use cose_minicbor::keys::{CoseAlg, CoseKey, CoseKeySetBuilder, Curve, KeyOp, KeyType};

#[test]
fn test_suit_verify_hmac_ecdh_es_a256kw() {
    let mut builder: CoseKeySetBuilder<800> = CoseKeySetBuilder::try_new().unwrap();
    let mut key: CoseKey<'_> = CoseKey::new(KeyType::Ec2);
    key.kid(b"bilbo.baggins@hobbiton.example");
    key.key_op(KeyOp::DeriveBits);
    key.x(&hex_literal::hex!(
        "0072992cb3ac08ecf3e5c63dedec0d51a8c1f79ef2f82f94f3c737bf5de
   7986671eac625fe8257bbd0394644caaa3aaf8f27a4585fbbcad0f2457620085e5c8
   f42ad"
    ))
    .unwrap();
    key.y(&hex_literal::hex!(
        "01dca6947bce88bc5790485ac97427342bc35f887d86d65a089377e247e
   60baa55e4e8501e2ada5724ac51d6909008033ebc10ac999b9d7f5cc2519f3fe1ea1
   d9475"
    ))
    .unwrap();
    key.alg(CoseAlg::ECDHESA128KW);
    key.crv(Curve::P521).unwrap();
    // Private key
    key.d(&hex_literal::hex!("00085138ddabf5ca975f5860f91a08e91d6d5f9a76ad4018766a476680b55cd339e8ab6c72b5facdb2a2a50ac25bd086647dd3e2e6e99e84ca2c3609fdf177feb26d")).unwrap();
    builder.push_key(key).unwrap();
    let key_set_bytes = builder.into_bytes().unwrap();
    let mac_bytes = cbor_diag::parse_diag(include_str!("diags/mac_hs256_a256kw.edn"))
        .unwrap()
        .to_bytes();
    let mac: CoseMac = minicbor::decode(&mac_bytes).expect("Unvalid format for CoseSign1");
    mac.suit_verify_mac(None, &key_set_bytes)
        .expect("Signature verification error");
}
