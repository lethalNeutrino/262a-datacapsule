extern crate pretty_env_logger;
#[macro_use]
extern crate log;
use anyhow::bail;
use capsulelib::capsule::structs::{Capsule, Metadata};
use ed25519_dalek::SigningKey;
use std::{collections::BTreeMap, path::Path};

fn main() -> anyhow::Result<()> {
    pretty_env_logger::init();
    let data_path = ".fjall_data";

    let signing_key_seed = [0u8; 32];
    let generated_signing_key = SigningKey::from_bytes(&signing_key_seed);
    let generated_verify_key = generated_signing_key.verifying_key();
    let generated_verify_key_bytes = generated_verify_key.to_bytes();

    info!(
        "Generated signing key seed: {}",
        signing_key_seed
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    info!(
        "Generated verify key: {}",
        generated_verify_key_bytes
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<String>()
    );
    let metadata: BTreeMap<String, Vec<u8>> = BTreeMap::from([(
        String::from("verify_key"),
        generated_verify_key_bytes.to_vec(),
    )]);

    let encryption_key = (0..16).collect::<Vec<u8>>();

    let mut capsule = Capsule::create(
        data_path,
        Metadata(metadata),
        generated_signing_key,
        encryption_key,
    )?;
    info!("Capsule created successfully");

    let data = "Hello, world!";
    let header_hash = capsule.append(vec![], data.as_bytes().to_vec())?;
    info!(
        "Header Hash: {}",
        header_hash
            .iter()
            .map(|c| format!("{:02x}", c))
            .collect::<String>()
    );

    let record_container = capsule.read(header_hash)?;
    let record = record_container
        .head()
        .cloned()
        .expect("record should be present");
    info!("Read data (decrypted): {:?}", str::from_utf8(&record.body)?);
    Ok(())
}
