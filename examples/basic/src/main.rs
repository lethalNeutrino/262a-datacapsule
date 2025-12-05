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

    let header_hash = capsule.append(vec![], "Hello, world!".as_bytes().to_vec())?;
    info!(
        "Header Hash: {}",
        header_hash
            .iter()
            .map(|c| format!("{:02x}", c))
            .collect::<String>()
    );

    let record = capsule.read(header_hash)?;
    info!("Read data (decrypted): {:?}", str::from_utf8(&record.body)?);

    Ok(())
}
