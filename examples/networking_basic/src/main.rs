use std::collections::BTreeMap;

use capsuleclient::{Connection, DataCapsuleRequest};
use capsulelib::{Metadata, SHA256Hashable};
use futures::{executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::QosProfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::new()?;
    let metadata_map: BTreeMap<String, Vec<u8>> =
        BTreeMap::from([(String::from("verify_key"), (0..16).collect::<Vec<u8>>())]);
    let metadata = Metadata(metadata_map);
    let capsule_topic = connection.create(metadata)?;

    // // Main loop spins ros.
    loop {
        connection
            .node
            .spin_once(std::time::Duration::from_millis(100));
        connection.pool.run_until_stalled();
    }
}
