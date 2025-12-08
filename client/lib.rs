mod capsule;

use anyhow::Result;
use capsulelib::capsule::{Metadata, SHA256Hashable};
use capsulelib::requests::DataCapsuleRequest;
use futures::{Stream, executor::LocalPool, task::LocalSpawnExt};
use r2r::{Publisher, QosProfile};
use serde::{Deserialize, Serialize};

pub struct Connection {
    pub ctx: r2r::Context,
    pub node: r2r::Node,
    pub pool: LocalPool,
    pub chatter: Topic,
}

pub struct Topic
//     S: WrappedTypesupport + 'static,
//     P: WrappedTypesupport + 'static,
{
    pub name: String,
    pub subscriber: Box<dyn Stream<Item = r2r::std_msgs::msg::ByteMultiArray> + Unpin>,
    pub publisher: Publisher<r2r::std_msgs::msg::ByteMultiArray>,
}

impl Connection {
    /// Creates a new namespace with the given context and node name
    pub fn new() -> Result<Self> {
        let ctx = r2r::Context::create()?;
        let mut node = r2r::Node::create(ctx.clone(), "node", "namespace")?;
        let subscriber = node.subscribe::<r2r::std_msgs::msg::ByteMultiArray>(
            "/chatter/client",
            QosProfile::default(),
        )?;
        let publisher = node.create_publisher::<r2r::std_msgs::msg::ByteMultiArray>(
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

    pub fn create(&mut self, metadata: Metadata) -> Result<Topic>
// where
    //     S: WrappedTypesupport + 'static,
    //     P: WrappedTypesupport + 'static,
    {
        let subscriber = self.node.subscribe::<r2r::std_msgs::msg::ByteMultiArray>(
            &format!("/capsule_{}/client", metadata.hash_string()),
            QosProfile::default(),
        )?;
        let publisher = self
            .node
            .create_publisher::<r2r::std_msgs::msg::ByteMultiArray>(
                &format!("/capsule_{}/server", metadata.hash_string()),
                QosProfile::default(),
            )?;

        let gdp_name = metadata.hash_string();

        // Run the publisher in another task
        let inner_msg = DataCapsuleRequest::Create { gdp_name };
        let inner_pub = self.chatter.publisher.clone();
        self.pool.spawner().spawn_local(async move {
            let msg = r2r::std_msgs::msg::ByteMultiArray {
                data: serde_json::to_vec(&inner_msg).unwrap(),
                ..Default::default()
            };
            inner_pub.publish(&msg).unwrap();
        })?;

        // publisher.publish();

        Ok(Topic {
            name: metadata.hash_string(),
            subscriber: Box::new(subscriber),
            publisher,
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
