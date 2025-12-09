use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use capsulelib::capsule::structs::{
    Capsule, Metadata, Record, RecordHeader, RecordHeartbeat, SHA256Hashable,
};
use capsulelib::requests::DataCapsuleRequest;
use futures::executor::LocalSpawner;
use futures::{
    Stream, executor::LocalPool, future, stream, stream::StreamExt, task::LocalSpawnExt,
};
use log::{debug, error, info, warn};
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

fn handle_capsule_subscriber(
    local_topics: Rc<RefCell<HashMap<String, Topic>>>,
    local_capsules: Rc<RefCell<HashMap<String, Capsule>>>,
    gdp_name: String,
    request: String,
) {
    // temporary bc i dont want to deal with communicating keys.
    let encryption_key = (0..16).collect::<Vec<u8>>();
    match serde_json::from_str::<DataCapsuleRequest>(&request) {
        Ok(DataCapsuleRequest::Append {
            reply_to, record, ..
        }) => {
            info!("[{}] got capsule append request: {}", &gdp_name, request);
            let publisher = local_topics
                .borrow()
                .get(&reply_to)
                .unwrap()
                .publisher
                .clone();

            handle_append(gdp_name, publisher, record, local_capsules)
                .expect("Failed to append capsule");
        }
        Ok(DataCapsuleRequest::Read {
            reply_to,
            header_hash,
            ..
        }) => {
            info!("[{}] got capsule append request: {}", &gdp_name, request);
            let publisher = local_topics
                .borrow()
                .get(&reply_to)
                .unwrap()
                .publisher
                .clone();

            handle_read(gdp_name, publisher, header_hash, local_capsules)
                .expect("Failed to append capsule");
        }
        Ok(_) => {
            warn!(
                "[UNSUPPORTED] [{}] got capsule message: {}",
                gdp_name, request
            );
        }
        Err(_) => {
            error!("[{}] got invalid capsule message: {}", gdp_name, request);
        }
    }
}

fn handle_machine_subscriber(
    local_topics: Rc<RefCell<HashMap<String, Topic>>>,
    local_capsules: Rc<RefCell<HashMap<String, Capsule>>>,
    uuid: String,
    request: String,
) {
    // let publisher = local_topics
    //     .borrow()
    //     .get(&gdp_name)
    //     .unwrap()
    //     .publisher
    //     .clone();
    info!("[{}] got machine message: {}", uuid, request);
    // The local_capsules map is available here for future logic.
}

fn handle_new_connection<'a>(
    node_rc: &Rc<RefCell<Node>>,
    spawner_rc: Rc<RefCell<futures::executor::LocalSpawner>>,
    local_topics: Rc<RefCell<HashMap<String, Topic>>>,
    local_capsules: Rc<RefCell<HashMap<String, Capsule>>>,
    reply_to: String,
    gdp_name: String,
    request: &'a str,
) -> Result<()> {
    let (capsule_sub, capsule_pub): (
        Box<dyn Stream<Item = r2r::std_msgs::msg::String>>,
        Publisher<r2r::std_msgs::msg::String>,
    ) = if local_topics.borrow().contains_key(&gdp_name) {
        //Pub/Sub is already handled for this topic
        let subscriber = Box::new(futures::stream::empty::<r2r::std_msgs::msg::String>());
        let publisher = local_topics
            .borrow()
            .get(&gdp_name)
            .unwrap()
            .publisher
            .clone();

        (subscriber, publisher)
    } else {
        let subscriber = {
            let mut node = node_rc.borrow_mut();
            node.subscribe::<r2r::std_msgs::msg::String>(
                &format!("/capsule_{}/server", gdp_name),
                QosProfile::default(),
            )?
        };

        // Handle subscriber
        let inner_gdp_name = gdp_name.clone();
        let capsule_inner_topics = Rc::clone(&local_topics);
        let capsule_inner_capsules = Rc::clone(&local_capsules);
        spawner_rc.borrow_mut().spawn_local(async move {
            subscriber
                .for_each(move |msg| {
                    handle_capsule_subscriber(
                        capsule_inner_topics.clone(),
                        capsule_inner_capsules.clone(),
                        inner_gdp_name.clone(),
                        msg.data,
                    );
                    future::ready(())
                })
                .await;
        })?;

        let publisher = {
            let mut node = node_rc.borrow_mut();
            node.create_publisher::<r2r::std_msgs::msg::String>(
                &format!("/capsule_{}/client", gdp_name),
                QosProfile::default(),
            )?
        };

        // We can't store the actual live subscriber (it will be moved into its own task),
        // so to satisfy the `Topic` type we store an empty stream as the placeholder for subscriber.
        let topic_entry = Topic {
            name: gdp_name.clone(),
            subscriber: Box::new(stream::empty::<r2r::std_msgs::msg::String>()),
            publisher: publisher.clone(),
        };

        local_topics
            .borrow_mut()
            .insert(gdp_name.clone(), topic_entry);

        (
            Box::new(stream::empty::<r2r::std_msgs::msg::String>()),
            publisher,
        )
    };

    let (machine_sub, machine_pub): (
        Box<dyn Stream<Item = r2r::std_msgs::msg::String>>,
        Publisher<r2r::std_msgs::msg::String>,
    ) = if local_topics.borrow().contains_key(&reply_to) {
        //Pub/Sub is already handled for this topic
        let subscriber = Box::new(futures::stream::empty::<r2r::std_msgs::msg::String>());
        let publisher = local_topics
            .borrow()
            .get(&reply_to)
            .unwrap()
            .publisher
            .clone();

        (subscriber, publisher)
    } else {
        let subscriber = {
            let mut node = node_rc.borrow_mut();
            node.subscribe::<r2r::std_msgs::msg::String>(
                &format!("/machine_{}/server", reply_to),
                QosProfile::default(),
            )?
        };

        // Handle subscriber
        let inner_reply_to = reply_to.clone();
        let machine_inner_topics = Rc::clone(&local_topics);
        let machine_inner_capsules = Rc::clone(&local_capsules);
        spawner_rc.borrow_mut().spawn_local(async move {
            subscriber
                .for_each(move |msg| {
                    handle_machine_subscriber(
                        machine_inner_topics.clone(),
                        machine_inner_capsules.clone(),
                        inner_reply_to.clone(),
                        msg.data,
                    );
                    future::ready(())
                })
                .await;
        })?;

        let publisher = {
            let mut node = node_rc.borrow_mut();
            node.create_publisher::<r2r::std_msgs::msg::String>(
                &format!("/machine_{}/client", reply_to.clone()),
                QosProfile::default(),
            )?
        };

        // We can't store the actual live subscriber (it will be moved into its own task),
        // so to satisfy the `Topic` type we store an empty stream as the placeholder for subscriber.
        let topic_entry = Topic {
            name: reply_to.clone(),
            subscriber: Box::new(stream::empty::<r2r::std_msgs::msg::String>()),
            publisher: publisher.clone(),
        };

        local_topics
            .borrow_mut()
            .insert(reply_to.clone(), topic_entry);

        (
            Box::new(stream::empty::<r2r::std_msgs::msg::String>()),
            publisher,
        )
    };
    let req = serde_json::from_str::<DataCapsuleRequest>(request)?;
    info!("got connection request: {:?}", req);

    match req {
        DataCapsuleRequest::Create {
            request_id,
            header,
            heartbeat,
            metadata,
            ..
        } => {
            handle_create(
                machine_pub,
                request_id,
                metadata,
                heartbeat,
                header,
                Rc::clone(&local_capsules),
            )?;
        }
        DataCapsuleRequest::Get { capsule_name, .. } => {
            handle_get(machine_pub, capsule_name, Rc::clone(&local_capsules))?;
        }
        _ => warn!("Chatter topic should only be used for create and get requests, ignoring"),
    }

    Ok(())
}

/// Create a capsule/topic and arrange for the subscriber to be processed on the local spawner.
/// - `node_rc`: shared single-threaded Node handle (Rc<RefCell<Node>>)
/// - `spawner_rc`: shared LocalSpawner (Rc<RefCell<LocalSpawner>>) so handlers can spawn local tasks
/// - `local_topics`: local, main-thread map keeping publishers (and optionally lightweight placeholders)
/// - `shared_index`: thread-safe (Arc<Mutex<...>>) lightweight index with capsule -> endpoint info
fn handle_create(
    reply_to: Publisher<r2r::std_msgs::msg::String>,
    request_id: String,
    metadata: Metadata,
    heartbeat: RecordHeartbeat,
    header: RecordHeader,
    local_capsules: Rc<RefCell<HashMap<String, Capsule>>>,
) -> Result<()> {
    info!("creating capsule!");
    let gdp_name = metadata.hash_string();

    // Temporary symmetric key for testing
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    // Send initial ack (if that variant exists)
    let _ = reply_to.publish(&r2r::std_msgs::msg::String {
        data: serde_json::to_string(&DataCapsuleRequest::CreateAck { request_id })?,
    });

    info!("capsule created!");
    let local_capsule = Capsule::open(
        ".fjall_data".to_string(),
        metadata.clone(),
        header,
        heartbeat,
        symmetric_key,
    )?;

    local_capsules
        .borrow_mut()
        .insert(metadata.hash_string(), local_capsule);

    Ok(())
}

fn handle_get(
    reply_to: Publisher<r2r::std_msgs::msg::String>,
    capsule_name: String,
    local_capsules: Rc<RefCell<HashMap<String, Capsule>>>,
) -> Result<()> {
    info!("getting capsule!");
    // For now use a dummy symmetric key for testing.
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    let local_capsule = if local_capsules.borrow().contains_key(&capsule_name) {
        local_capsules.borrow().get(&capsule_name).unwrap().clone()
    } else {
        let local_capsule = Capsule::get(
            ".fjall_data".to_string(),
            capsule_name.clone(),
            symmetric_key,
        )?;

        local_capsules
            .borrow_mut()
            .insert(capsule_name.clone(), local_capsule.clone());

        local_capsule
    };

    // Create Header
    let metadata_header = RecordHeader {
        seqno: 0,
        gdp_name: capsule_name.clone().to_string(),
        prev_ptr: None,
        hash_ptrs: Vec::new(),
    };

    let metadata_header_hash = metadata_header.hash();
    let metadata_record = local_capsule.read(metadata_header_hash)?;

    // Send initial ack (if that variant exists)
    let _ = reply_to.publish(&r2r::std_msgs::msg::String {
        data: serde_json::to_string(&DataCapsuleRequest::GetResponse {
            metadata: local_capsule.metadata,
            heartbeat: metadata_record.heartbeat.unwrap(),
            header: metadata_record.header,
        })?,
    });

    Ok(())
}

fn handle_append(
    capsule_name: String,
    reply_to: Publisher<r2r::std_msgs::msg::String>,
    record: Record,
    local_capsules: Rc<RefCell<HashMap<String, Capsule>>>,
) -> Result<()> {
    debug!("appending data to capsule!");

    // For now use a dummy symmetric key for testing.
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    // Try to reuse a cached capsule if present, otherwise open and cache it.
    {
        let mut map = local_capsules.borrow_mut();
        if let Some(capsule) = map.get_mut(&capsule_name) {
            debug!("capsule metadata: {:?}", capsule.metadata);
            let response = DataCapsuleRequest::AppendAck {
                header_hash: record.header.hash_string(),
            };
            capsule.place(record.header, record.heartbeat.unwrap(), record.body)?;
            reply_to
                .publish(&r2r::std_msgs::msg::String {
                    data: serde_json::to_string(&response).unwrap(),
                })
                .expect("Publishing failed");
            info!("appended to cached capsule");
            return Ok(());
        }
    }

    // Not cached: open, append, and cache.
    let mut local_capsule = Capsule::get(
        ".fjall_data/".to_string(),
        capsule_name.clone(),
        symmetric_key,
    )?;
    let response = DataCapsuleRequest::AppendAck {
        header_hash: record.header.hash_string(),
    };
    local_capsule.place(record.header, record.heartbeat.unwrap(), record.body)?;
    reply_to
        .publish(&r2r::std_msgs::msg::String {
            data: serde_json::to_string(&response).unwrap(),
        })
        .expect("Publishing failed");
    info!("appended to newly opened capsule");

    local_capsules
        .borrow_mut()
        .insert(capsule_name.clone(), local_capsule);

    Ok(())
}

fn handle_read(
    capsule_name: String,
    reply_to: Publisher<r2r::std_msgs::msg::String>,
    header: Vec<u8>,
    local_capsules: Rc<RefCell<HashMap<String, Capsule>>>,
) -> Result<()> {
    debug!("reading data from capsule!");

    // For now use a dummy symmetric key for testing.
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    let header_hash = header;

    // First, try to use a cached capsule (immutable borrow is sufficient for read).
    if let Some(cached) = local_capsules.borrow().get(&capsule_name) {
        let record = cached.read(header_hash.clone())?;
        let response = DataCapsuleRequest::ReadResponse { record };
        reply_to.publish(&r2r::std_msgs::msg::String {
            data: serde_json::to_string(&response).unwrap(),
        })?;
        return Ok(());
    }

    // Not cached: open the capsule, cache it, then read.
    let local_capsule = Capsule::get(
        ".fjall_data/".to_string(),
        capsule_name.clone(),
        symmetric_key,
    )?;
    let record = local_capsule.read(header_hash)?;
    let response = DataCapsuleRequest::ReadResponse { record };
    reply_to.publish(&r2r::std_msgs::msg::String {
        data: serde_json::to_string(&response).unwrap(),
    })?;

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    pretty_env_logger::init();
    // Create the ROS2 context and node.
    let ctx = r2r::Context::create()?;
    let node = r2r::Node::create(ctx, "node", "namespace")?;

    // Shared single-threaded Node handle for main + local tasks.
    let node_rc = Rc::new(RefCell::new(node));

    // LocalPool + spawner for single-threaded async work.
    let mut pool = LocalPool::new();
    let spawner = pool.spawner();
    // Wrap the spawner so it can be cloned into handlers on the same thread.
    let spawner_rc = Rc::new(RefCell::new(spawner));

    // Local main-thread map of topics (publishers etc.)
    let local_topics: Rc<RefCell<HashMap<String, Topic>>> = Rc::new(RefCell::new(HashMap::new()));

    // Local main-thread map of in-memory Capsules (shared with handlers)
    let local_capsules: Rc<RefCell<HashMap<String, Capsule>>> =
        Rc::new(RefCell::new(HashMap::new()));

    // Create initial chatter subscriber/publisher/timer with short borrows.
    let subscriber = {
        let mut n = node_rc.borrow_mut();
        n.subscribe::<r2r::std_msgs::msg::String>("/chatter/server", QosProfile::default())?
    };
    let _publisher = {
        let mut n = node_rc.borrow_mut();
        n.create_publisher::<r2r::std_msgs::msg::String>("/chatter/client", QosProfile::default())?
    };
    let mut _timer = {
        let mut n = node_rc.borrow_mut();
        n.create_wall_timer(std::time::Duration::from_millis(1000))?
    };

    // Clone handles for the spawned subscriber task.
    let node_for_task = Rc::clone(&node_rc);
    let spawner_for_task = Rc::clone(&spawner_rc);
    let local_topics_for_task = Rc::clone(&local_topics);
    let local_capsules_for_task = Rc::clone(&local_capsules);

    // Spawn the chatter subscriber handler on the local spawner.
    {
        // Move clones into the async closure; they will be cloned per-message when needed.
        let spawner_clone_for_handle = spawner_for_task.clone();
        let local_topics_clone_for_handle = local_topics_for_task.clone();
        let local_capsules_clone_for_handle = local_capsules_for_task.clone();

        let spawner_ref = spawner_for_task.borrow_mut();
        let spawn_res =
            spawner_ref.spawn_local(async move {
                // We own the clones inside this async closure. For each incoming message
                // we will clone them again before passing to `handle_create`, which avoids
                // moving the captured values out of the FnMut closure.
                subscriber
                .for_each(move |msg| {
                    match serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
                        Ok(DataCapsuleRequest::Create {
                            reply_to, metadata, ..
                        }) => {
                            // Clone the Rc/Arc for this invocation so we don't move the owned values
                            let spawner_for_call = spawner_clone_for_handle.clone();
                            let local_topics_for_call = local_topics_clone_for_handle.clone();
                            let local_capsules_for_call = local_capsules_clone_for_handle.clone();
                            let reply_to_clone = reply_to.clone();
                            let gdp_name = metadata.clone().hash_string();

                            handle_new_connection(
                                &node_for_task,
                                spawner_for_call,
                                local_topics_for_call,
                                local_capsules_for_call,
                                reply_to_clone,
                                gdp_name,
                                &msg.data,
                            ).expect("Failed to handle new connection");
                        }
                        Ok(DataCapsuleRequest::Get {
                            reply_to,
                            capsule_name,
                        }) => {
                            let spawner_for_call = spawner_clone_for_handle.clone();
                            let local_topics_for_call = local_topics_clone_for_handle.clone();
                            let local_capsules_for_call = local_capsules_clone_for_handle.clone();
                            let capsule_name_clone = capsule_name.clone();
                            handle_new_connection(
                                &node_for_task,
                                spawner_for_call,
                                local_topics_for_call,
                                local_capsules_for_call,
                                reply_to,
                                capsule_name_clone,
                                &msg.data,
                            ).expect("Failed to handle new connection");
                        }
                        Err(e) => {
                            error!("It's bwoken: {}", e);
                        }
                        _ => {
                            warn!(
                                "chatter should only be used for create or get requests; ignoring"
                            );
                        }
                    };
                    future::ready(())
                })
                .await;
            });

        if let Err(e) = spawn_res {
            eprintln!("failed to spawn chatter handler: {:?}", e);
        }
    }

    // Main loop: spin the node and run the local task pool.
    loop {
        // Short-lived mutable borrow to call spin_once.
        {
            let mut node_borrow = node_rc.borrow_mut();
            node_borrow.spin_once(std::time::Duration::from_millis(100));
        }

        pool.run_until_stalled();
    }
}
