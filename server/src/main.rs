use anyhow::Result;
use capsulelib::capsule::{
    Capsule, Metadata, Record, RecordHeader, RecordHeartbeat, SHA256Hashable,
};
use capsulelib::requests::DataCapsuleRequest;
use futures::{executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::Context;
use r2r::QosProfile;

fn handle_create(
    metadata: Metadata,
    heartbeat: RecordHeartbeat,
    header: RecordHeader,
) -> Result<Capsule> {
    println!("creating capsule!");
    todo!()
}

fn handle_append(capsule_name: String, record: Record) -> Result<()> {
    println!("appending data to capsule!");
    todo!()
}

fn handle_read(capsule_name: String, header: Vec<u8>) -> Result<Vec<u8>> {
    println!("reading data from capsule!");
    todo!()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = r2r::Context::create()?;
    let mut node = r2r::Node::create(ctx, "node", "namespace")?;
    let subscriber =
        node.subscribe::<r2r::std_msgs::msg::String>("/chatter", QosProfile::default())?;
    let publisher =
        node.create_publisher::<r2r::std_msgs::msg::String>("/chatter", QosProfile::default())?;
    let mut timer = node.create_wall_timer(std::time::Duration::from_millis(1000))?;

    // Set up a simple task executor.
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    // Run the subscriber in one task, printing the messages
    spawner.spawn_local(async move {
        subscriber
            .for_each(|msg| {
                match serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
                    Ok(DataCapsuleRequest::Create {
                        metadata,
                        heartbeat,
                        header,
                    }) => {
                        handle_create(metadata, heartbeat, header).expect("creation failed!");
                        println!("Capsule created!");
                    }
                    Ok(DataCapsuleRequest::Append {
                        capsule_name,
                        record,
                    }) => {
                        handle_append(capsule_name, record).expect("append failed!");
                        println!("Record appended!");
                    }
                    Ok(DataCapsuleRequest::Read {
                        capsule_name,
                        header_hash,
                    }) => {
                        handle_read(capsule_name, header_hash).expect("read failed!");
                        println!("Capsule read!");
                    }
                    Err(e) => {
                        println!("It's bwoken: {}", e);
                    }
                    _ => {
                        println!("got new msg: {:?}", msg.data);
                    }
                };
                future::ready(())
            })
            .await
    })?;

    // Main loop spins ros.
    loop {
        node.spin_once(std::time::Duration::from_millis(100));
        pool.run_until_stalled();
    }
}
