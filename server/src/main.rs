use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::Result;
use capsulelib::capsule::structs::{
    Capsule, Metadata, Record, RecordHeader, RecordHeartbeat, SHA256Hashable,
};
use capsulelib::requests::DataCapsuleRequest;
use futures::{Stream, executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use log::{debug, info};
use r2r::{Context, Node};
use r2r::{Publisher, QosProfile};

/// TODO: REFACTOR THIS INTO NETWORK LIB
pub struct Connection {
    pub ctx: r2r::Context,
    pub node: r2r::Node,
    pub pool: LocalPool,
    pub chatter: Topic,
}

pub struct Topic {
    pub name: String,
    pub subscriber: Box<dyn Stream<Item = r2r::std_msgs::msg::String> + Unpin>,
    pub publisher: Publisher<r2r::std_msgs::msg::String>,
}

struct NetworkCapsuleWriter {
    connection: Topic,
    local_capsule: Capsule,
}

struct NetworkCapsuleReader {
    connection: Topic,
    local_capsule: Capsule,
}

/// Updated to take a shared, mutable reference to the `Node` so it can be
/// called from both the main loop and the spawned task.
fn handle_create(
    node_rc: &Rc<RefCell<Node>>,
    metadata: Metadata,
    heartbeat: RecordHeartbeat,
    header: RecordHeader,
) -> Result<Capsule> {
    info!("creating capsule!");
    let gdp_name = metadata.hash_string();
    let key_var = format!("{}_key", gdp_name);
    let key_str = match std::env::var(&key_var) {
        Ok(v) => v,
        Err(_) => return Err(anyhow::anyhow!("environment variable {} not set", key_var)),
    };

    // For now use a dummy symmetric key for testing.
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    // Borrow the node mutably only for the duration of creating the subscriber/publisher.
    let mut node = node_rc.borrow_mut();

    let capsule_topic = Topic {
        name: gdp_name.clone(),
        subscriber: Box::new(node.subscribe::<r2r::std_msgs::msg::String>(
            &format!("/capsule_{}/server", metadata.hash_string()),
            QosProfile::default(),
        )?),
        publisher: node.create_publisher::<r2r::std_msgs::msg::String>(
            &format!("/capsule_{}/client", metadata.hash_string()),
            QosProfile::default(),
        )?,
    };

    // At this point `node` mutable borrow is dropped when `node` goes out of scope.

    info!("capsule created!");
    Capsule::open(gdp_name.clone(), metadata, header, heartbeat, symmetric_key)
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
    // Create the ROS2 context and node as before.
    let ctx = r2r::Context::create()?;
    let node = r2r::Node::create(ctx, "node", "namespace")?;

    // Wrap the node in an Rc<RefCell<_>> so it can be shared between the main
    // loop and the spawned local task.
    let node_rc = Rc::new(RefCell::new(node));

    // Create the initial subscriber, publisher and timer using a temporary mutable borrow.
    let subscriber = {
        let mut node_borrow = node_rc.borrow_mut();
        node_borrow
            .subscribe::<r2r::std_msgs::msg::String>("/chatter/server", QosProfile::default())?
    };
    let publisher = {
        let mut node_borrow = node_rc.borrow_mut();
        node_borrow.create_publisher::<r2r::std_msgs::msg::String>(
            "/chatter/client",
            QosProfile::default(),
        )?
    };
    let mut timer = {
        let mut node_borrow = node_rc.borrow_mut();
        node_borrow.create_wall_timer(std::time::Duration::from_millis(1000))?
    };

    // Set up a simple task executor.
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();

    // Clone the Rc so the spawned task has access to the same Node.
    let node_for_task = Rc::clone(&node_rc);

    // Run the subscriber in one task, printing the messages.
    spawner.spawn_local(async move {
        subscriber
            .for_each(|msg| {
                // Parse the incoming request and call the appropriate handler.
                match serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
                    Ok(DataCapsuleRequest::Create {
                        metadata,
                        heartbeat,
                        header,
                    }) => {
                        // Pass the shared node reference to `handle_create`.
                        match handle_create(&node_for_task, metadata, heartbeat, header) {
                            Ok(_) => {
                                println!("Capsule created!");
                            }
                            Err(e) => {
                                eprintln!("creation failed: {}", e);
                            }
                        }
                    }
                    // Ok(DataCapsuleRequest::Append {
                    //     capsule_name,
                    //     record,
                    // }) => {
                    //     if let Err(e) = handle_append(capsule_name, record) {
                    //         eprintln!("append failed: {}", e);
                    //     } else {
                    //         println!("Record appended!");
                    //     }
                    // }
                    // Ok(DataCapsuleRequest::Read {
                    //     capsule_name,
                    //     header_hash,
                    // }) => {
                    //     match handle_read(capsule_name, header_hash) {
                    //         Ok(_) => println!("Capsule read!"),
                    //         Err(e) => eprintln!("read failed: {}", e),
                    //     };
                    // }
                    Err(e) => {
                        println!("It's bwoken: {}", e);
                    }
                    _ => {
                        println!("chatter should only be used for create requests; ignoring");
                    }
                };
                future::ready(())
            })
            .await
    })?;

    // Main loop spins ros and runs the local task pool.
    loop {
        // Borrow the node mutably for spinning once. The borrow must be short-lived
        // so spawned tasks can also borrow it when they run.
        {
            let mut node_borrow = node_rc.borrow_mut();
            node_borrow.spin_once(std::time::Duration::from_millis(100));
        }

        // Run any pending futures until they stall.
        pool.run_until_stalled();
    }
}
