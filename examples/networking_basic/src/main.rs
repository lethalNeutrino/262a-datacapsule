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
    let capsule_topic =
        connection.create(data_path, metadata, generated_signing_key, encryption_key)?;

    connection.pool.spawner().spawn_local(async move {
        capsule_topic
            .subscriber
            .for_each(|msg| {
                // Parse the incoming request and call the appropriate handler.
                match serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
                    Ok(DataCapsuleRequest::Ack) => {
                        println!("got ack back from create");
                    }
                    Err(e) => {
                        println!("It's bwoken: {}", e);
                    }
                    _ => {
                        println!("not yet implemented");
                    }
                };
                future::ready(())
            })
            .await
    })?;

    // // Main loop spins ros.
    loop {
        connection
            .node
            .spin_once(std::time::Duration::from_millis(100));
        connection.pool.run_until_stalled();
    }
}
