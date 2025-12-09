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

fn handle_capsule_subscriber(gdp_name: String, request: String) {
    println!("[{}] got capsule message: {}", gdp_name, request);
}

fn handle_machine_subscriber(uuid: String, request: String) {
    println!("[{}] got machine message: {}", uuid, request);
}

fn handle_new_connection<'a>(
    node_rc: &Rc<RefCell<Node>>,
    spawner_rc: Rc<RefCell<futures::executor::LocalSpawner>>,
    local_topics: Rc<RefCell<HashMap<String, Topic>>>,
    reply_to: String,
    gdp_name: String,
    request: &'a str,
) -> Result<()> {
    let req = serde_json::from_str::<DataCapsuleRequest>(request)?;
    println!("got connection request: {:?}", req);

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
        spawner_rc.borrow_mut().spawn_local(async move {
            subscriber
                .for_each(move |msg| {
                    handle_capsule_subscriber(inner_gdp_name.clone(), msg.data);
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
                &format!("/machine_{}/client", reply_to),
                QosProfile::default(),
            )?
        };

        // Handle subscriber
        let inner_reply_to = reply_to.clone();
        spawner_rc.borrow_mut().spawn_local(async move {
            subscriber
                .for_each(move |msg| {
                    handle_machine_subscriber(inner_reply_to.clone(), msg.data);
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
    Ok(())
}

/// Create a capsule/topic and arrange for the subscriber to be processed on the local spawner.
/// - `node_rc`: shared single-threaded Node handle (Rc<RefCell<Node>>)
/// - `spawner_rc`: shared LocalSpawner (Rc<RefCell<LocalSpawner>>) so handlers can spawn local tasks
/// - `local_topics`: local, main-thread map keeping publishers (and optionally lightweight placeholders)
/// - `shared_index`: thread-safe (Arc<Mutex<...>>) lightweight index with capsule -> endpoint info
fn handle_create(
    node_rc: &Rc<RefCell<Node>>,
    spawner_rc: Rc<RefCell<futures::executor::LocalSpawner>>,
    local_topics: Rc<RefCell<HashMap<String, Topic>>>,
    reply_to: String,
    metadata: Metadata,
    heartbeat: RecordHeartbeat,
    header: RecordHeader,
) -> Result<Capsule> {
    info!("creating capsule!");
    let gdp_name = metadata.hash_string();

    // Temporary symmetric key for testing
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    // Send initial ack (if that variant exists)
    // let _ = machine_pub.publish(&r2r::std_msgs::msg::String {
    //     data: serde_json::to_string(&DataCapsuleRequest::CreateAck)?,
    // });

    // // Store publisher in local map so main thread can publish later if needed.
    // // We can't store the actual live subscriber (it will be moved into its own task),
    // // so to satisfy the `Topic` type we store an empty stream as the placeholder for subscriber.
    // let topic_entry = Topic {
    //     name: gdp_name.clone(),
    //     subscriber: Box::new(stream::empty::<r2r::std_msgs::msg::String>()),
    //     publisher,
    // };
    // local_topics
    //     .borrow_mut()
    //     .insert(gdp_name.clone(), topic_entry);

    info!("capsule created!");
    Capsule::open(
        ".fjall_data".to_string(),
        metadata,
        header,
        heartbeat,
        symmetric_key,
    )
}

fn handle_append(capsule_name: String, record: Record) -> Result<()> {
    println!("appending data to capsule!");

    // For now use a dummy symmetric key for testing.
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    let mut local_capsule = Capsule::get(".fjall_data/".to_string(), capsule_name, symmetric_key)?;
    local_capsule.place(record.header, record.heartbeat.unwrap(), record.body)?;
    info!("capsule created!");

    Ok(())
}

fn handle_get(
    node_rc: &Rc<RefCell<Node>>,
    spawner_rc: Rc<RefCell<futures::executor::LocalSpawner>>,
    local_topics: Rc<RefCell<HashMap<String, Topic>>>,
    shared_index: Arc<Mutex<HashMap<String, String>>>,
    capsule_name: String,
) -> Result<()> {
    println!("getting capsule!");
    // For now use a dummy symmetric key for testing.
    let symmetric_key: Vec<u8> = (0..16).collect::<Vec<u8>>();

    let local_capsule = Capsule::get(
        ".fjall_data".to_string(),
        capsule_name.clone(),
        symmetric_key,
    )?;
    // Create Header
    let metadata_header = RecordHeader {
        seqno: 0,
        gdp_name: capsule_name.clone().to_string(),
        prev_ptr: None,
        hash_ptrs: Vec::new(),
    };

    let metadata_header_hash = metadata_header.hash();
    let metadata_record = local_capsule.read(metadata_header_hash)?;

    // Create subscriber/publisher with a short mutable borrow of the node
    let subscriber = {
        let mut node = node_rc.borrow_mut();
        node.subscribe::<r2r::std_msgs::msg::String>(
            &format!("/capsule_{}/server", capsule_name),
            QosProfile::default(),
        )?
    };

    let publisher = {
        let mut node = node_rc.borrow_mut();
        node.create_publisher::<r2r::std_msgs::msg::String>(
            &format!("/capsule_{}/client", capsule_name),
            QosProfile::default(),
        )?
    };

    // Send initial ack (if that variant exists)
    let _ = publisher.publish(&r2r::std_msgs::msg::String {
        data: serde_json::to_string(&DataCapsuleRequest::GetResponse {
            metadata: local_capsule.metadata,
            heartbeat: metadata_record.heartbeat.unwrap(),
            header: metadata_record.header,
        })?,
    });

    // Insert a lightweight record into the thread-safe shared index so other threads can see this capsule
    {
        let mut idx = shared_index.lock().unwrap();
        idx.insert(
            capsule_name.clone(),
            format!("/capsule_{}/client", capsule_name.clone()),
        );
    }

    // Store publisher in local map so main thread can publish later if needed.
    // We can't store the actual live subscriber (it will be moved into its own task),
    // so to satisfy the `Topic` type we store an empty stream as the placeholder for subscriber.
    let topic_entry = Topic {
        name: capsule_name.clone(),
        subscriber: Box::new(stream::empty::<r2r::std_msgs::msg::String>()),
        publisher,
    };
    local_topics
        .borrow_mut()
        .insert(capsule_name.clone(), topic_entry);

    // Spawn a task to process incoming messages on the subscriber.
    // Use the LocalSpawner wrapped in Rc<RefCell<..>> (single-threaded).
    {
        // Clone what the task needs.
        let capsule_name_for_task = capsule_name.clone();
        // Move the actual subscriber into the task so it can `.for_each`.
        let mut spawner = spawner_rc.borrow_mut();
        let spawn_result = spawner.spawn_local(async move {
            subscriber
                .for_each(move |msg| {
                    println!("[{}] capsule message: {}", capsule_name_for_task, msg.data);
                    future::ready(())
                })
                .await;
        });

        if let Err(e) = spawn_result {
            // spawn failed; log but continue. We return success for the capsule creation itself.
            eprintln!(
                "failed to spawn subscriber task for {}: {:?}",
                capsule_name, e
            );
        }
    }

    Ok(())
}

fn handle_read(capsule_name: String, header: Vec<u8>) -> Result<Vec<u8>> {
    println!("reading data from capsule!");
    todo!()
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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

    // Spawn the chatter subscriber handler on the local spawner.
    {
        // Move clones into the async closure; they will be cloned per-message when needed.
        let spawner_clone_for_handle = spawner_for_task.clone();
        let local_topics_clone_for_handle = local_topics_for_task.clone();

        let spawner_ref = spawner_for_task.borrow_mut();
        let spawn_res = spawner_ref.spawn_local(async move {
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
                            let reply_to_clone = reply_to.clone();
                            let gdp_name = metadata.clone().hash_string();

                            handle_new_connection(
                                &node_for_task,
                                spawner_for_call,
                                local_topics_for_call,
                                reply_to_clone,
                                gdp_name,
                                &msg.data,
                            );
                        }
                        Ok(DataCapsuleRequest::Get {
                            reply_to,
                            capsule_name,
                        }) => {
                            let spawner_for_call = spawner_clone_for_handle.clone();
                            let local_topics_for_call = local_topics_clone_for_handle.clone();
                            let capsule_name_clone = capsule_name.clone();
                            handle_new_connection(
                                &node_for_task,
                                spawner_for_call,
                                local_topics_for_call,
                                reply_to,
                                capsule_name_clone,
                                &msg.data,
                            );
                        }
                        Err(e) => {
                            println!("It's bwoken: {}", e);
                        }
                        _ => {
                            println!(
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
