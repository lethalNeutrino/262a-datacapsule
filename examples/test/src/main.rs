extern crate pretty_env_logger;
#[macro_use]
extern crate log;
use anyhow::bail;
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, path::Path};

use capsulelib::Capsule;

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    let data_path = ".fjall_data";
    let metadata: BTreeMap<String, Vec<u8>> =
        BTreeMap::from([(String::from("verify_key"), (0..16).collect::<Vec<u8>>())]);

    let signing_key_seed = [0u8; 32];
    let signing_key = SigningKey::from_bytes(&signing_key_seed);

    let encryption_key = (0..16).collect::<Vec<u8>>();

    let mut capsule = Capsule::create(data_path, metadata, signing_key, encryption_key)?;
    info!("Capsule created successfully");

    let data = vec!["Hello", "World!"];
    let mut header_hashes: Vec<Vec<u8>> = Vec::new();

    for _ in 0..10000 {
        header_hashes.push(capsule.append(vec![], data[0].as_bytes().to_vec())?);
    }

    let record = capsule.peek()?;
    info!("Read data (decrypted): {}", str::from_utf8(&record.body)?);
    Ok(())
}
