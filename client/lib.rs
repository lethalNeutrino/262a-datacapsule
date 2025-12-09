mod capsule;

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::Path;
use std::rc::Rc;
use uuid::Uuid;

use anyhow::Result;
use capsule::{NetworkCapsuleReader, NetworkCapsuleWriter};
use capsulelib::capsule::structs::{Capsule, Metadata, SHA256Hashable};
use capsulelib::requests::DataCapsuleRequest;
use ed25519_dalek::SigningKey;
use futures::{Stream, StreamExt, executor::LocalPool, task::LocalSpawnExt};
use futures::{future, stream};
use r2r::{Publisher, QosProfile};
use serde::{Deserialize, Serialize};

// Struct representing a connection to the ROS2 network
// Responsible for creating / connecting to capsules in
// Writer / Read mode, respectively
pub struct Connection<'a> {
    // Context that spawned the node
    pub ctx: r2r::Context,
    // Node that needs to be repeatedly spun for this connection.
    // Wrapped in `Rc<RefCell<_>>` so we can share a reference to the Node
    // with returned readers without making the Node `Send`.
    pub node: Rc<RefCell<r2r::Node>>,
    // Pool to spawn tasks
    pub pool: LocalPool,
    // UUID topic
    pub topic: Topic,
    // Chatter topic to broadcast to all servers
    pub chatter: Topic,

    // HashMaps that store CapsuleName <-> Reader/Writer pairings
    writers: HashMap<String, &'a NetworkCapsuleWriter>,
    readers: HashMap<String, &'a NetworkCapsuleReader>,
}

pub struct Topic {
    pub name: String,
    pub subscriber: Box<dyn Stream<Item = r2r::std_msgs::msg::String> + Unpin>,
    pub publisher: Publisher<r2r::std_msgs::msg::String>,
}

impl<'a> Connection<'a> {
    /// Creates a new namespace with the given context and node name
    pub fn new() -> Result<Self> {
        let ctx = r2r::Context::create()?;
        let node_inner = r2r::Node::create(ctx.clone(), "node", "namespace")?;
        let node = Rc::new(RefCell::new(node_inner));

        // Use short-lived mutable borrows to call r2r APIs on the node.
        let chatter_sub = node
            .borrow_mut()
            .subscribe::<r2r::std_msgs::msg::String>("/chatter/client", QosProfile::default())?;
        let chatter_pub = node
            .borrow_mut()
            .create_publisher::<r2r::std_msgs::msg::String>(
                "/chatter/server",
                QosProfile::default(),
            )?;

        let uuid = uuid::Uuid::new_v4().simple().to_string();
        println!("uuid in new is: {}", uuid);
        // let uuid = "abcdef".to_string();
        let uuid_sub = node.borrow_mut().subscribe::<r2r::std_msgs::msg::String>(
            &format!("/machine_{}/client", uuid),
            QosProfile::default(),
        )?;

        let uuid_pub = node
            .borrow_mut()
            .create_publisher::<r2r::std_msgs::msg::String>(
                &format!("/machine_{}/server", uuid),
                QosProfile::default(),
            )?;

        uuid_pub.publish(&r2r::std_msgs::msg::String {
            data: "priming".to_string(),
        })?;

        uuid_pub.publish(&r2r::std_msgs::msg::String {
            data: "priming1".to_string(),
        })?;

        uuid_pub.publish(&r2r::std_msgs::msg::String {
            data: "priming2".to_string(),
        })?;

        let pool = LocalPool::new();

        let inner_uuid = uuid.clone();
        pool.spawner().spawn_local(async move {
            uuid_sub
                .for_each(move |msg| {
                    println!("[{}] got machine message: {}", inner_uuid, &msg.data);
                    future::ready(())
                })
                .await;
        })?;

        Ok(Connection {
            ctx,
            node,
            pool,
            topic: Topic {
                name: uuid.clone(),
                subscriber: Box::new(stream::empty::<r2r::std_msgs::msg::String>()),
                publisher: uuid_pub,
            },
            chatter: Topic {
                name: String::from("chatter"),
                subscriber: Box::new(chatter_sub),
                publisher: chatter_pub,
            },
            readers: HashMap::new(),
            writers: HashMap::new(),
        })
    }

    /// Given the same parameters that are used to create a datacapsule
    /// locally, create a datacapsule on the server, as well as an in-
    /// memory capsule that serves as the source of truth.
    pub fn create<P: AsRef<Path>>(
        &mut self,
        kv_store_path: P,
        metadata: Metadata,
        signing_key: SigningKey,
        symmetric_key: Vec<u8>,
    ) -> Result<NetworkCapsuleWriter> {
        // Open new topic to talk to the servers
        let subscriber = self
            .node
            .borrow_mut()
            .subscribe::<r2r::std_msgs::msg::String>(
                &format!("/capsule_{}/client", metadata.hash_string()),
                QosProfile::default(),
            )?;
        // Used to send a create request to the servers; a reply should be expected
        // on the topic specifically for this machine.
        let publisher = self
            .node
            .borrow_mut()
            .create_publisher::<r2r::std_msgs::msg::String>(
                &format!("/capsule_{}/server", metadata.hash_string()),
                QosProfile::default(),
            )?;

        let gdp_name = metadata.hash_string();

        let local_capsule =
            Capsule::create(kv_store_path, metadata.clone(), signing_key, symmetric_key)?;
        let metadata_record = local_capsule.peek()?;

        // Run the publisher in another task
        let request_id = uuid::Uuid::new_v4().to_string();
        let inner_msg = DataCapsuleRequest::Create {
            request_id: request_id.clone(),
            reply_to: self.topic.name.clone(),
            metadata: metadata.clone(),
            header: metadata_record.header,
            heartbeat: metadata_record.heartbeat.unwrap(),
        };

        // Serialize the create request once so it can be reused for resends and for the
        // short-lived task that publishes the initial announcement on the chatter topic.
        let payload = serde_json::to_string(&inner_msg)?;
        let inner_pub = self.chatter.publisher.clone();
        let payload_for_task = payload.clone();
        self.pool.spawner().spawn_local(async move {
            let msg = r2r::std_msgs::msg::String {
                data: payload_for_task,
            };
            inner_pub.publish(&msg).unwrap();
        })?;

        // publisher.publish();

        println!("uuid in create is: {}", self.topic.name.clone());

        // Wait for CreateAck on the machine topic, resending the create request until
        // we get an Ack. We create a short-lived subscriber to /machine_{uuid}/client
        // so we can watch for CreateAck messages. We reuse the existing pool and node
        // to keep everything single-threaded.
        use std::time::{Duration, Instant};

        let response_holder: Rc<RefCell<Option<DataCapsuleRequest>>> = Rc::new(RefCell::new(None));
        let holder_for_task = Rc::clone(&response_holder);

        // Create a short-lived machine subscriber that will write CreateAck into the holder.
        let machine_topic = format!("/machine_{}/client", self.topic.name);
        let machine_sub = self
            .node
            .borrow_mut()
            .subscribe::<r2r::std_msgs::msg::String>(&machine_topic, QosProfile::default())?;

        self.pool.spawner().spawn_local(async move {
            machine_sub
                .for_each(move |msg| {
                    if let Ok(parsed) = serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
                        match parsed {
                            DataCapsuleRequest::CreateAck {
                                request_id: ack_request_id,
                            } => {
                                if ack_request_id == request_id {
                                    *holder_for_task.borrow_mut() =
                                        Some(DataCapsuleRequest::CreateAck {
                                            request_id: ack_request_id,
                                        });
                                }
                            }
                            _ => { /* ignore other messages */ }
                        }
                    }
                    future::ready(())
                })
                .await;
        })?;

        // payload already serialized above and reused for resends

        // Resend loop: publish create on chatter until we receive CreateAck or timeout.
        let retry_interval = Duration::from_millis(500);
        let mut attempts = 0usize;
        let max_attempts = 40usize; // ~20s maximum (adjustable)

        loop {
            // send create
            println!("resending create request due to no ack recieved");
            let msg = r2r::std_msgs::msg::String {
                data: payload.clone(),
            };
            self.chatter.publisher.publish(&msg)?;

            let start = Instant::now();
            while response_holder.borrow().is_none() && start.elapsed() < retry_interval {
                // spin node and run pool briefly
                {
                    let mut nb = self.node.borrow_mut();
                    nb.spin_once(std::time::Duration::from_millis(50));
                }
                self.pool.run_until_stalled();
            }

            if response_holder.borrow().is_some() {
                break;
            }

            attempts += 1;
            if attempts >= max_attempts {
                anyhow::bail!("no CreateAck received after {} attempts", attempts);
            }

            // otherwise loop and resend
        }

        Ok(NetworkCapsuleWriter {
            uuid: self.topic.name.clone(),
            local_capsule,
            topic: Topic {
                name: metadata.hash_string(),
                subscriber: Box::new(subscriber),
                publisher,
            },
        })
    }

    pub fn get(
        &mut self,
        gdp_name: String,
        symmetric_key: Vec<u8>,
    ) -> Result<NetworkCapsuleReader> {
        // Create the subscriber and publisher for this capsule.
        // Borrow the node mutably for each r2r call (short-lived borrow).
        let subscriber = self
            .node
            .borrow_mut()
            .subscribe::<r2r::std_msgs::msg::String>(
                &format!("/capsule_{}/client", gdp_name),
                QosProfile::default(),
            )?;
        let publisher = self
            .node
            .borrow_mut()
            .create_publisher::<r2r::std_msgs::msg::String>(
                &format!("/capsule_{}/server", gdp_name),
                QosProfile::default(),
            )?;

        // Build the Get request (we will resend until we receive a GetResponse).
        let request = DataCapsuleRequest::Get {
            reply_to: self.topic.name.clone(),
            capsule_name: gdp_name.clone(),
        };

        // Holder to receive the response from the spawned task.
        // We use Rc<RefCell<Option<...>>> so the async task can set the value
        // and the synchronous caller can observe it (single-threaded LocalPool).
        let response_holder: Rc<RefCell<Option<DataCapsuleRequest>>> = Rc::new(RefCell::new(None));
        let holder_for_task = Rc::clone(&response_holder);

        // Create a short-lived machine subscriber that will write GetResponse into the holder.
        let machine_topic = format!("/machine_{}/client", self.topic.name);
        let machine_sub = self
            .node
            .borrow_mut()
            .subscribe::<r2r::std_msgs::msg::String>(&machine_topic, QosProfile::default())?;

        // Move the capsule subscriber into the spawned task which will set the holder
        // when it sees a GetResponse for this capsule.
        self.pool.spawner().spawn_local(async move {
            machine_sub
                .for_each(move |msg| {
                    match serde_json::from_str::<DataCapsuleRequest>(&msg.data) {
                        Ok(res @ DataCapsuleRequest::GetResponse { .. }) => {
                            // store the response in the shared holder
                            *holder_for_task.borrow_mut() = Some(res);
                        }
                        Ok(_) => {
                            // other messages ignored for now
                        }
                        Err(e) => {
                            println!("It's bwoken: {}", e);
                        }
                    };
                    future::ready(())
                })
                .await
        })?;

        // Prepare serialized payload for the Get request so we can resend cheaply.
        let payload = serde_json::to_string(&request)?;

        // Resend loop: publish Get on chatter until we receive GetResponse or timeout.
        use std::time::{Duration, Instant};
        let retry_interval = Duration::from_millis(500);
        let mut attempts = 0usize;
        let max_attempts = 40usize; // ~20s maximum (adjustable)

        loop {
            // publish the Get request
            let msg = r2r::std_msgs::msg::String {
                data: payload.clone(),
            };
            self.chatter.publisher.publish(&msg)?;

            let start = Instant::now();
            while response_holder.borrow().is_none() && start.elapsed() < retry_interval {
                // spin node and run pool briefly
                {
                    let mut nb = self.node.borrow_mut();
                    nb.spin_once(std::time::Duration::from_millis(50));
                }
                self.pool.run_until_stalled();
            }

            if response_holder.borrow().is_some() {
                break;
            }

            attempts += 1;
            if attempts >= max_attempts {
                anyhow::bail!("no GetResponse received after {} attempts", attempts);
            }

            // otherwise loop and resend
        }

        // Optionally extract the parsed response if you need to inspect it here.
        let parsed = response_holder.borrow_mut().take().unwrap();
        println!("got back {:?}", parsed);
        let local_capsule = if let DataCapsuleRequest::GetResponse {
            metadata,
            heartbeat,
            header,
        } = parsed
        {
            Capsule::open(
                ".fjall_data".to_string(),
                metadata,
                header,
                heartbeat,
                symmetric_key,
            )?
        } else {
            Capsule::default()
        };

        println!("uuid in get is: {}", self.topic.name.clone());
        Ok(NetworkCapsuleReader {
            uuid: self.topic.name.clone(),
            connection: Topic {
                name: gdp_name,
                // we moved the real subscriber into the spawned task; return an empty placeholder
                subscriber: Box::new(futures::stream::empty::<r2r::std_msgs::msg::String>()),
                publisher,
            },
            local_capsule,
            // Pass a clone of the shared node handle so the reader's `read`
            // implementation can spin the node while waiting for replies.
            node: Rc::clone(&self.node),
        })
    }
}
