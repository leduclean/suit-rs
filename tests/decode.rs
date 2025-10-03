use std::fs;
use std::path::Path;

#[test]
fn test_decode_cbor_file() {
    let path = Path::new("tests/cbor/suit_manifest_expU_fixed.cbor");
    let _ = fs::read(path).expect("Error while reading CBOR file");

    // Call decode function
    // let res = suit_decode(&data);
    // assert!(res.is_ok(), "Decoding failed: {:?}", res.err());

    // // Verify the decoded content
    // let suit_start = res.unwrap();

    // if let SuitStart::EnvelopeTagged(envelope) = suit_start {
    //     // Check envelope content
    //     let manifest = envelope.manifest.get().expect("Failed to get manifest");
    //     assert_eq!(manifest.version, 1);
    //     assert_eq!(manifest.sequence_number, 3);
    // } else {
    //     panic!("Expected SuitStart::EnvelopeTagged variant");
    // }
}
