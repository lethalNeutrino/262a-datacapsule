use anyhow::Result;
use capsulelib::Metadata;
use futures::{Stream, executor::LocalPool, future, stream::StreamExt, task::LocalSpawnExt};
use r2r::{Publisher, QosProfile, WrappedTypesupport};
use std::collections::HashMap;

struct Connection<S, P>
where
    S: WrappedTypesupport + 'static,
    P: WrappedTypesupport + 'static,
{
    subscriber: Box<dyn Stream<Item = S> + Unpin>,
    publisher: Publisher<P>,
}

impl<S, P> Connection<S, P>
where
    S: WrappedTypesupport + 'static,
    P: WrappedTypesupport + 'static,
{
    /// Connects to the server
    pub fn new() -> Result<Self> {
        let ctx = r2r::Context::create()?;
        let mut node = r2r::Node::create(ctx, "node", "namespace")?;
        let subscriber = node.subscribe::<S>("/chatter_client", QosProfile::default())?;
        let publisher = node.create_publisher::<P>("/chatter_server", QosProfile::default())?;
        Ok(Connection {
            subscriber: Box::new(subscriber),
            publisher,
        })
    }

    pub fn create(self, metadata: Metadata) -> Result<()> {
        Ok(())
    }
}
