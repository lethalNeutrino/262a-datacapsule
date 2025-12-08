use std::collections::BTreeMap;

use capsuleclient::Connection;
use capsulelib::{Metadata, SHA256Hashable};
use futures::{executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::QosProfile;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut connection = Connection::new()?;
    let metadata_map: BTreeMap<String, Vec<u8>> =
        BTreeMap::from([(String::from("verify_key"), (0..16).collect::<Vec<u8>>())]);
    let metadata = Metadata(metadata_map);
    let capsule_topic = connection.create(metadata)?;
    // // Set up a simple task executor.
    // let mut pool = LocalPool::new();
    // let spawner = pool.spawner();

    // // Run the publisher in another task
    // spawner.spawn_local(async move {
    //     let mut counter = 0;
    //     loop {
    //         let _elapsed = timer.tick().await.unwrap();
    //         let msg = r2r::std_msgs::msg::String {
    //             data: format!("Hello, world! ({})", counter),
    //         };
    //         publisher.publish(&msg).unwrap();
    //         counter += 1;
    //     }
    // })?;

    // // Main loop spins ros.
    loop {
        connection
            .node
            .spin_once(std::time::Duration::from_millis(100));
        connection.pool.run_until_stalled();
    }
}
