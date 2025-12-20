use std::collections::BTreeMap;

use capsuleclient::Connection;
use capsulelib::capsule::structs::{Metadata, SHA256Hashable};
use capsulelib::requests::DataCapsuleRequest;
use ed25519_dalek::SigningKey;
use futures::{executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use log::{debug, info};
use r2r::QosProfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    let mut connection = Connection::new()?;

    let metadata_map: BTreeMap<String, Vec<u8>> = BTreeMap::from([(
        String::from("verify_key"),
        generated_verify_key_bytes.to_vec(),
    )]);

    let metadata = Metadata(metadata_map);

    let mut capsule_writer = connection.create(
        data_path,
        metadata,
        generated_signing_key,
        encryption_key.clone(),
    )?;

    let mut header_hashes: Vec<Vec<u8>> = Vec::new();
    for i in 1..=1000 {
        header_hashes.push(
            capsule_writer.append(vec![], format!("Hello, World{}!", i).as_bytes().to_vec())?,
        );
    }

    let mut capsule_reader =
        connection.get(capsule_writer.local_capsule.gdp_name(), encryption_key)?;

    for hash in header_hashes {
        // Capsule::read now returns a RecordContainer; extract the head record.
        let container = capsule_reader.read(hash)?;
        let r = container.head().cloned().expect("record");
        println!("retrieved record {:?}", r);
    }

    // connection.pool.spawner().spawn_local(async move {
    //     capsule_writer
    //         .topic
    //         .subscriber
    //         .for_each(|msg| {
    //             println!("{}", &msg.data);
    //             future::ready(())
    //         })
    //         .await
    // })?;

    // let mut capsule_reader =
    //     connection.get(capsule_writer.local_capsule.gdp_name(), encryption_key)?;

    // let rec = capsule_reader.read(header_hash)?;

    // // Main loop spins ros.
    loop {
        connection
            .node
            .borrow_mut()
            .spin_once(std::time::Duration::from_millis(100));
        connection.pool.run_until_stalled();
    }
}
