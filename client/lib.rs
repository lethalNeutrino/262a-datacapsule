mod capsule;

use anyhow::Result;
use capsulelib::{Metadata, SHA256Hashable};
use futures::{Stream, executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::{Publisher, QosProfile, WrappedTypesupport};
use std::collections::HashMap;

enum DataCapsuleRequest {
    Create {
        gdp_name: r2r::std_msgs::msg::String,
    },
}

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
    pub subscriber: Box<dyn Stream<Item = r2r::std_msgs::msg::String> + Unpin>,
    pub publisher: Publisher<r2r::std_msgs::msg::String>,
}

impl Connection {
    /// Creates a new namespace with the given context and node name
    pub fn new() -> Result<Self> {
        let ctx = r2r::Context::create()?;
        let mut node = r2r::Node::create(ctx.clone(), "node", "namespace")?;
        let subscriber =
            node.subscribe::<r2r::std_msgs::msg::String>("/chatter_client", QosProfile::default())?;
        let publisher = node.create_publisher::<r2r::std_msgs::msg::String>(
            "/chatter_server",
            QosProfile::default(),
        )?;
        let mut pool = LocalPool::new();
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
        let subscriber = self.node.subscribe::<r2r::std_msgs::msg::String>(
            &format!("/{}_client", metadata.hash_string()),
            QosProfile::default(),
        )?;
        let publisher = self.node.create_publisher::<r2r::std_msgs::msg::String>(
            &format!("/{}_server", metadata.hash_string()),
            QosProfile::default(),
        )?;

        let gdp_name = metadata.hash_string();

        // Run the publisher in another task
        let inner_msg = gdp_name.clone();
        let inner_pub = self.chatter.publisher.clone();
        self.pool.spawner().spawn_local(async move {
            let msg = r2r::std_msgs::msg::String {
                data: format!("create({})", inner_msg),
            };
            inner_pub.publish(&msg).unwrap();
        })?;

        let request = DataCapsuleRequest::Create {
            gdp_name: r2r::std_msgs::msg::String { data: gdp_name },
        };

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
