use minicbor::{decode};
use std::fs::File;
use std::io::Read;
use suit_rs::manifest::{SuitStart};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut file = File::open("testfiles/suit_manifest_expID.cbor")?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer)?;
    let value: SuitStart = decode(&buffer)?;
    println!("struct: {:?}", value);
    Ok(())
}
