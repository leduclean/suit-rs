use cose_minicbor::cose_keys::{CoseAlg, Curve};
use cose_minicbor::cose_keys::{CoseKey, CoseKeySetBuilder, KeyType};

pub fn get_keys() -> impl AsRef<[u8]> {
    // Initialize key set
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
    cose_key_builder.into_bytes().expect("Bytes should be okay")
}
