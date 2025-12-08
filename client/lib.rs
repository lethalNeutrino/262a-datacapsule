mod capsule;

use std::path::Path;

use anyhow::Result;
use capsule::{NetworkCapsuleReader, NetworkCapsuleWriter};
use capsulelib::capsule::structs::{Capsule, Metadata, SHA256Hashable};
use capsulelib::requests::DataCapsuleRequest;
use ed25519_dalek::SigningKey;
use futures::{Stream, executor::LocalPool, task::LocalSpawnExt};
use r2r::{Publisher, QosProfile};
use serde::{Deserialize, Serialize};

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

impl Connection {
    /// Creates a new namespace with the given context and node name
    pub fn new() -> Result<Self> {
        let ctx = r2r::Context::create()?;
        let mut node = r2r::Node::create(ctx.clone(), "node", "namespace")?;
        let subscriber =
            node.subscribe::<r2r::std_msgs::msg::String>("/chatter/client", QosProfile::default())?;
        let publisher = node.create_publisher::<r2r::std_msgs::msg::String>(
            "/chatter/server",
            QosProfile::default(),
        )?;
        let pool = LocalPool::new();
        Ok(Connection {
            ctx,
            node,
            pool,
            chatter: Topic {
                name: String::from("chatter"),
                subscriber: Box::new(subscriber),
                publisher,
            },
        })
    }

    pub fn create<P: AsRef<Path>>(
        &mut self,
        kv_store_path: P,
        metadata: Metadata,
        signing_key: SigningKey,
        symmetric_key: Vec<u8>,
    ) -> Result<NetworkCapsuleWriter> {
        let subscriber = self.node.subscribe::<r2r::std_msgs::msg::String>(
            &format!("/capsule_{}/client", metadata.hash_string()),
            QosProfile::default(),
        )?;
        let publisher = self.node.create_publisher::<r2r::std_msgs::msg::String>(
            &format!("/capsule_{}/server", metadata.hash_string()),
            QosProfile::default(),
        )?;

        let gdp_name = metadata.hash_string();

        let local_capsule =
            Capsule::create(kv_store_path, metadata.clone(), signing_key, symmetric_key)?;
        let metadata_record = local_capsule.peek()?;

        // Run the publisher in another task
        let inner_msg = DataCapsuleRequest::Create {
            metadata: metadata.clone(),
            header: metadata_record.header,
            heartbeat: metadata_record.heartbeat.unwrap(),
        };

        let inner_pub = self.chatter.publisher.clone();
        self.pool.spawner().spawn_local(async move {
            let msg = r2r::std_msgs::msg::String {
                data: serde_json::to_string(&inner_msg).unwrap(),
            };
            inner_pub.publish(&msg).unwrap();
        })?;

        // publisher.publish();

        Ok(NetworkCapsuleWriter {
            local_capsule,
            connection: Topic {
                name: metadata.hash_string(),
                subscriber: Box::new(subscriber),
                publisher,
            },
        })
    }
}

// impl<S, P> Topic<S, P>
// where
//     S: WrappedTypesupport + 'static,
//     P: WrappedTypesupport + 'static,
// {
//     /// Creates a capsule in writer mode and returns a NetworkCapsuleWriter
//     pub fn create(self, metadata: Metadata) -> Result<()> {
//         let gdp_name = metadata.hash_string();
//         Ok(())
//     }

//     /// Gets a capsule that has already been created in reader mode and returns a NetworkCapsuleReader
//     pub fn get(self, metadata: Metadata) -> Result<()> {
//         Ok(())
//     }
// }
